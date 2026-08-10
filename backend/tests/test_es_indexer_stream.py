from __future__ import annotations

import time
import types
from typing import Any, Dict, List, Optional, Tuple

import pytest

from app.workers.indexing import es_stream
from app.workers.indexing.es_bootstrap import ESConfig
from app.workers.indexing.es_stream import ESStreamConfig
from app.workers.ingest.es_stream_producer import publish_index_events


class _FakePipeline:
    def __init__(self, parent: "_FakeRedis") -> None:
        self.parent = parent
        self.ops: List[Tuple[str, tuple, dict]] = []

    def xadd(self, name: str, fields: dict, **kw: Any) -> "_FakePipeline":
        self.ops.append(("xadd", (name, fields), kw))
        return self

    def execute(self) -> List[Any]:
        out = []
        for op, args, kw in self.ops:
            out.append(getattr(self.parent, op)(*args, **kw))
        self.ops = []
        return out


class _FakeRedis:
    def __init__(self) -> None:
        self.streams: Dict[str, List[Tuple[str, dict]]] = {}
        self.groups: Dict[str, Dict[str, dict]] = {}
        self.hashes: Dict[str, Dict[str, int]] = {}
        self._order: Dict[str, int] = {}
        self._seq = 0

    def pipeline(self) -> _FakePipeline:
        return _FakePipeline(self)

    def xadd(self, name: str, fields: dict, maxlen: Optional[int] = None, approximate: bool = True, **kw: Any) -> str:
        self.streams.setdefault(name, [])
        self._seq += 1
        entry_id = f"{self._seq}-0"
        self._order[entry_id] = self._seq
        self.streams[name].append((entry_id, dict(fields)))
        if maxlen is not None and len(self.streams[name]) > maxlen:
            self.streams[name] = self.streams[name][-maxlen:]
        return entry_id

    def xgroup_create(self, name: str, groupname: str, id: str = "$", mkstream: bool = False) -> bool:
        if name not in self.streams:
            if not mkstream:
                raise Exception("NOGROUP No such stream")
            self.streams[name] = []
        self.groups.setdefault(name, {})
        if groupname in self.groups[name]:
            raise Exception("BUSYGROUP Consumer Group name already exists")
        last_index = 0 if id in ("0", "0-0") else len(self.streams[name])
        self.groups[name][groupname] = {"last_index": last_index, "pel": {}}
        return True

    def xreadgroup(
        self,
        groupname: str,
        consumername: str,
        streams: Dict[str, str],
        count: Optional[int] = None,
        block: Optional[int] = None,
        noack: bool = False,
    ) -> List[Any]:
        out: List[Any] = []
        for key, sid in streams.items():
            g = self.groups[key][groupname]
            entries = self.streams.get(key, [])
            delivered: List[Tuple[str, dict]] = []
            if sid == ">":
                start = g["last_index"]
                end = min(len(entries), start + (count or len(entries)))
                for i in range(start, end):
                    eid, fields = entries[i]
                    g["pel"][eid] = {"consumer": consumername, "idle": time.monotonic(), "fields": fields}
                    delivered.append((eid, fields))
                g["last_index"] = end
            else:
                cur = -1 if sid in ("0", "0-0") else self._order.get(sid, -1)
                pend = [
                    (eid, meta)
                    for eid, meta in g["pel"].items()
                    if meta["consumer"] == consumername and self._order.get(eid, -1) > cur
                ]
                pend.sort(key=lambda t: self._order.get(t[0], -1))
                for eid, meta in pend[: (count or len(pend))]:
                    delivered.append((eid, meta["fields"]))
            if delivered:
                out.append([key, delivered])
        return out

    def xack(self, name: str, groupname: str, *ids: str) -> int:
        pel = self.groups[name][groupname]["pel"]
        removed = 0
        for i in ids:
            if i in pel:
                del pel[i]
                removed += 1
        return removed

    def xpending(self, name: str, groupname: str) -> dict:
        pel = self.groups[name][groupname]["pel"]
        return {"pending": len(pel), "min": None, "max": None, "consumers": []}

    def xinfo_groups(self, name: str) -> List[dict]:
        out = []
        entries = self.streams.get(name, [])
        for gname, g in self.groups.get(name, {}).items():
            out.append(
                {
                    "name": gname,
                    "pending": len(g["pel"]),
                    "lag": max(0, len(entries) - g["last_index"]),
                    "last-delivered-id": "0-0",
                }
            )
        return out

    def xautoclaim(
        self,
        name: str,
        groupname: str,
        consumername: str,
        min_idle_time: int,
        start_id: str = "0-0",
        count: int = 100,
    ) -> list:
        g = self.groups[name][groupname]
        now = time.monotonic()
        claimed: List[Tuple[str, dict]] = []
        for eid, meta in list(g["pel"].items()):
            idle_ms = (now - meta["idle"]) * 1000.0
            if idle_ms >= min_idle_time:
                meta["consumer"] = consumername
                meta["idle"] = now
                claimed.append((eid, meta["fields"]))
        return ["0-0", claimed, []]

    def hincrby(self, key: str, field: str, amount: int = 1) -> int:
        h = self.hashes.setdefault(key, {})
        h[field] = h.get(field, 0) + amount
        return h[field]

    def hdel(self, key: str, field: str) -> int:
        h = self.hashes.setdefault(key, {})
        return 1 if h.pop(field, None) is not None else 0


class _FakeES:
    def __init__(self) -> None:
        self.docs: Dict[str, dict] = {}
        self.perm_fail: set[str] = set()
        self.transient_remaining: Dict[str, int] = {}
        self.reachable = True

    def ping(self) -> bool:
        return self.reachable


def _fake_bulk(es: _FakeES, actions: List[Dict[str, Any]], *, request_timeout: int) -> Tuple[int, List[Any]]:
    if not es.reachable:
        raise ConnectionError("es down")
    success = 0
    errors: List[Any] = []
    for action in actions:
        doc_id = str(action["_id"])
        if doc_id in es.perm_fail:
            errors.append({"index": {"_id": doc_id, "status": 400, "error": {"type": "mapper_parsing_exception"}}})
            continue
        remaining = es.transient_remaining.get(doc_id, 0)
        if remaining > 0:
            es.transient_remaining[doc_id] = remaining - 1
            errors.append({"index": {"_id": doc_id, "status": 503, "error": {"type": "unavailable_shards"}}})
            continue
        es.docs[doc_id] = action["_source"]
        success += 1
    return success, errors


def _cfg(**over: Any) -> ESStreamConfig:
    base = dict(
        stream_key="seagull:events:index",
        group="es-indexer",
        consumer="test-consumer",
        batch_size=100,
        block_ms=100,
        max_retries=3,
        start_id="0",
        dlq_key="seagull:events:index:dlq",
        dlq_maxlen=1000,
        attempts_key="seagull:events:index:attempts",
        claim_min_idle_ms=30000,
        housekeeping_seconds=0.0,
        backlog_alert_threshold=1000,
        retry_backoff_seconds=0.0,
        retry_backoff_max_seconds=0.0,
    )
    base.update(over)
    return ESStreamConfig(**base)


@pytest.fixture(autouse=True)
def _patch_bulk_and_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(es_stream, "run_bulk", _fake_bulk)
    monkeypatch.setattr(es_stream, "_sleep", lambda *_a, **_k: None)


def _es_cfg() -> ESConfig:
    from app.workers.indexing.es_bootstrap import load_config

    return load_config()


def _row(pg_id: int, agent: str = "agent-1", et: str = "flow") -> Dict[str, Any]:
    from datetime import datetime, timezone

    return {
        "pg_event_id": pg_id,
        "agent_id": agent,
        "event_type": et,
        "schema_version": 1,
        "timestamp": datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 1234,
        "dst_port": 443,
        "proto": "tcp",
        "bytes": 100,
        "extra": {"app_proto": "tls"},
    }


def _run(r: _FakeRedis, es: _FakeES, cfg: ESStreamConfig, iterations: int) -> None:
    es_stream.run(
        r=r,
        es=es,
        es_cfg=_es_cfg(),
        cfg=cfg,
        bootstrap_enabled=False,
        ping=True,
        max_iterations=iterations,
    )


def test_producer_publishes_with_pg_event_id() -> None:
    r = _FakeRedis()
    worker_cfg = types.SimpleNamespace(es_stream_key="seagull:events:index", es_stream_maxlen=1000)
    published = publish_index_events(r, [_row(11), _row(22)], worker_cfg)  # type: ignore[arg-type]
    assert published == 2
    import json

    entries = r.streams["seagull:events:index"]
    ids = sorted(json.loads(f["event"])["id"] for _eid, f in entries)
    assert ids == [11, 22]


def test_consume_and_index_happy_path() -> None:
    r = _FakeRedis()
    es = _FakeES()
    worker_cfg = types.SimpleNamespace(es_stream_key="seagull:events:index", es_stream_maxlen=1000)
    publish_index_events(r, [_row(1), _row(2), _row(3)], worker_cfg)  # type: ignore[arg-type]

    _run(r, es, _cfg(), iterations=3)

    assert set(es.docs.keys()) == {"1", "2", "3"}
    assert es.docs["1"]["id"] == 1
    assert es.docs["1"]["app_proto"] == "tls"
    assert r.xpending("seagull:events:index", "es-indexer")["pending"] == 0


def test_idempotent_id_overwrite() -> None:
    r = _FakeRedis()
    es = _FakeES()
    worker_cfg = types.SimpleNamespace(es_stream_key="seagull:events:index", es_stream_maxlen=1000)
    publish_index_events(r, [_row(7, agent="a"), _row(7, agent="b")], worker_cfg)  # type: ignore[arg-type]

    _run(r, es, _cfg(), iterations=3)

    assert list(es.docs.keys()) == ["7"]


def test_permanent_error_goes_to_dlq() -> None:
    r = _FakeRedis()
    es = _FakeES()
    es.perm_fail.add("2")
    worker_cfg = types.SimpleNamespace(es_stream_key="seagull:events:index", es_stream_maxlen=1000)
    publish_index_events(r, [_row(1), _row(2), _row(3)], worker_cfg)  # type: ignore[arg-type]

    _run(r, es, _cfg(), iterations=3)

    assert set(es.docs.keys()) == {"1", "3"}
    dlq = r.streams.get("seagull:events:index:dlq", [])
    assert len(dlq) == 1
    assert dlq[0][1]["doc_id"] == "2"
    assert dlq[0][1]["reason"].startswith("permanent_400")
    assert r.xpending("seagull:events:index", "es-indexer")["pending"] == 0


def test_transient_error_retried_then_indexed() -> None:
    r = _FakeRedis()
    es = _FakeES()
    es.transient_remaining["2"] = 1
    worker_cfg = types.SimpleNamespace(es_stream_key="seagull:events:index", es_stream_maxlen=1000)
    publish_index_events(r, [_row(1), _row(2), _row(3)], worker_cfg)  # type: ignore[arg-type]

    _run(r, es, _cfg(), iterations=5)

    assert set(es.docs.keys()) == {"1", "2", "3"}
    assert r.streams.get("seagull:events:index:dlq", []) == []
    assert r.xpending("seagull:events:index", "es-indexer")["pending"] == 0


def test_transient_exceeds_max_retries_goes_to_dlq() -> None:
    r = _FakeRedis()
    es = _FakeES()
    es.transient_remaining["2"] = 999
    worker_cfg = types.SimpleNamespace(es_stream_key="seagull:events:index", es_stream_maxlen=1000)
    publish_index_events(r, [_row(1), _row(2), _row(3)], worker_cfg)  # type: ignore[arg-type]

    _run(r, es, _cfg(max_retries=3), iterations=8)

    assert set(es.docs.keys()) == {"1", "3"}
    dlq = r.streams.get("seagull:events:index:dlq", [])
    assert len(dlq) == 1
    assert dlq[0][1]["doc_id"] == "2"
    assert dlq[0][1]["reason"] == "max_retries"
    assert r.xpending("seagull:events:index", "es-indexer")["pending"] == 0


def test_boot_replays_pending_entries() -> None:
    r = _FakeRedis()
    es = _FakeES()
    worker_cfg = types.SimpleNamespace(es_stream_key="seagull:events:index", es_stream_maxlen=1000)
    publish_index_events(r, [_row(5)], worker_cfg)  # type: ignore[arg-type]

    cfg = _cfg()
    es_stream._ensure_group(r, cfg)
    delivered = r.xreadgroup(
        groupname=cfg.group, consumername=cfg.consumer, streams={cfg.stream_key: ">"}, count=10
    )
    assert delivered and delivered[0][1]
    assert r.xpending(cfg.stream_key, cfg.group)["pending"] == 1

    _run(r, es, cfg, iterations=1)

    assert es.docs["5"]["id"] == 5
    assert r.xpending(cfg.stream_key, cfg.group)["pending"] == 0


def test_es_unreachable_leaves_pending_no_dlq() -> None:
    r = _FakeRedis()
    es = _FakeES()
    es.reachable = False
    worker_cfg = types.SimpleNamespace(es_stream_key="seagull:events:index", es_stream_maxlen=1000)
    publish_index_events(r, [_row(1)], worker_cfg)  # type: ignore[arg-type]

    cfg = _cfg()
    es_stream._ensure_group(r, cfg)
    r.xreadgroup(groupname=cfg.group, consumername=cfg.consumer, streams={cfg.stream_key: ">"}, count=10)

    es_stream._process_batch(
        r=r,
        es=es,
        es_cfg=_es_cfg(),
        cfg=cfg,
        entries=es_stream._extract_stream_entries(
            [[cfg.stream_key, [(eid, f) for eid, f in r.streams[cfg.stream_key]]]]
        ),
    )

    assert es.docs == {}
    assert r.streams.get("seagull:events:index:dlq", []) == []
    assert r.hashes.get(cfg.attempts_key, {}) == {}
    assert r.xpending(cfg.stream_key, cfg.group)["pending"] == 1
