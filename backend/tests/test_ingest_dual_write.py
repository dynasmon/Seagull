from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional

import pytest

from app.core.config import settings
from app.core.messaging.topics import EVENTS_INDEX_TOPIC, EVENTS_RAW_TOPIC
from app.features.ingest import event_log
from app.workers.ingest import es_stream_producer
from app.workers.ingest.config import WorkerConfig


class _FakeEventLogProducer:
    def __init__(self, delivered: bool = True, accept: bool = True) -> None:
        self.delivered = delivered
        self.accept = accept
        self.published: List[Dict[str, Any]] = []
        self.flushes = 0

    def publish(
        self,
        topic: str,
        *,
        key: str,
        event: Mapping[str, Any],
        on_result: Optional[Callable[[bool], None]] = None,
        produced_at: Optional[str] = None,
    ) -> bool:
        if not self.accept:
            if on_result is not None:
                on_result(False)
            return False
        self.published.append({"topic": topic, "key": key, "event": dict(event)})
        if on_result is not None:
            on_result(self.delivered)
        return True

    def flush(self, _timeout: float = 10.0) -> int:
        self.flushes += 1
        return 0


class _CounterSpy:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, name: str, value: float = 1.0, **labels: Any) -> None:
        self.calls.append({"name": name, "value": value, **labels})

    def total(self, name: str, **labels: Any) -> float:
        out = 0.0
        for call in self.calls:
            if call["name"] != name:
                continue
            if all(call.get(k) == v for k, v in labels.items()):
                out += call["value"]
        return out


def _wire_row(agent_id: str = "agent-1") -> List[Any]:
    return [agent_id, "ssh_auth", 1, "2026-07-13T00:00:00+00:00", "10.0.0.1", "10.0.0.2", 22, 2222, "tcp", 128, {"severity": "low"}]


@pytest.fixture()
def dual_write_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "SEAGULL_REDPANDA_ENABLED", True)
    monkeypatch.setattr(settings, "SEAGULL_REDPANDA_DUAL_WRITE_ENABLED", True)


def test_publish_raw_events_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_REDPANDA_ENABLED", False)
    monkeypatch.setattr(settings, "SEAGULL_REDPANDA_DUAL_WRITE_ENABLED", False)
    called: List[Any] = []
    monkeypatch.setattr(event_log, "get_producer", lambda: called.append(1))

    assert event_log.publish_raw_events(rows=[_wire_row()], redis_ok=True) == 0
    assert called == []


def test_publish_raw_events_publishes_all_rows(monkeypatch: pytest.MonkeyPatch, dual_write_on: None) -> None:
    fake = _FakeEventLogProducer()
    monkeypatch.setattr(event_log, "get_producer", lambda: fake)

    published = event_log.publish_raw_events(rows=[_wire_row("agent-a"), _wire_row("agent-a")], redis_ok=True)

    assert published == 2
    assert all(p["topic"] == EVENTS_RAW_TOPIC for p in fake.published)
    assert all(p["key"] == "agent-a" for p in fake.published)
    event = fake.published[0]["event"]
    assert event["agent_id"] == "agent-a"
    assert event["event_type"] == "ssh_auth"
    assert event["extra"] == {"severity": "low"}


def test_publish_raw_events_counts_discrepancy_when_redpanda_fails(
    monkeypatch: pytest.MonkeyPatch, dual_write_on: None
) -> None:
    spy = _CounterSpy()
    monkeypatch.setattr(event_log, "incr_counter", spy)
    fake = _FakeEventLogProducer(delivered=False)
    monkeypatch.setattr(event_log, "get_producer", lambda: fake)

    event_log.publish_raw_events(rows=[_wire_row()], redis_ok=True)

    assert spy.total("ingest_dual_write_discrepancy_total", stream="events_raw", reason="redpanda_write_failed") == 1.0


def test_publish_raw_events_counts_discrepancy_when_redis_failed(
    monkeypatch: pytest.MonkeyPatch, dual_write_on: None
) -> None:
    spy = _CounterSpy()
    monkeypatch.setattr(event_log, "incr_counter", spy)
    fake = _FakeEventLogProducer(delivered=True)
    monkeypatch.setattr(event_log, "get_producer", lambda: fake)

    event_log.publish_raw_events(rows=[_wire_row()], redis_ok=False)

    assert spy.total("ingest_dual_write_discrepancy_total", stream="events_raw", reason="redis_write_failed") == 1.0


def test_publish_raw_events_producer_unavailable(monkeypatch: pytest.MonkeyPatch, dual_write_on: None) -> None:
    spy = _CounterSpy()
    monkeypatch.setattr(event_log, "incr_counter", spy)
    monkeypatch.setattr(event_log, "get_producer", lambda: None)

    assert event_log.publish_raw_events(rows=[_wire_row(), _wire_row()], redis_ok=True) == 0
    assert spy.total("ingest_dual_write_discrepancy_total", stream="events_raw", reason="producer_unavailable") == 2.0


class _FakePipeline:
    def __init__(self, parent: "_FakeRedis") -> None:
        self.parent = parent
        self.ops: List[Any] = []

    def xadd(self, name: str, fields: dict, **kw: Any) -> "_FakePipeline":
        self.ops.append((name, fields, kw))
        return self

    def execute(self) -> List[Any]:
        if self.parent.fail:
            raise RuntimeError("redis down")
        for name, fields, _kw in self.ops:
            self.parent.streams.setdefault(name, []).append(fields)
        out = [True] * len(self.ops)
        self.ops = []
        return out


class _FakeRedis:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.streams: Dict[str, List[dict]] = {}

    def pipeline(self) -> _FakePipeline:
        return _FakePipeline(self)


def _worker_cfg() -> WorkerConfig:
    from app.workers.ingest.config import load_config

    return load_config()


def _hot_row(pg_event_id: int = 11, agent_id: str = "agent-b") -> Dict[str, Any]:
    return {
        "pg_event_id": pg_event_id,
        "agent_id": agent_id,
        "event_type": "net_flow",
        "schema_version": 1,
        "timestamp": "2026-07-13T00:00:00+00:00",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.9",
        "src_port": 1000,
        "dst_port": 443,
        "proto": "tcp",
        "bytes": 64,
        "extra": {},
    }


def test_publish_index_events_writes_redis_and_redpanda(monkeypatch: pytest.MonkeyPatch, dual_write_on: None) -> None:
    fake_producer = _FakeEventLogProducer()
    monkeypatch.setattr(es_stream_producer, "get_producer", lambda: fake_producer)
    r = _FakeRedis()
    cfg = _worker_cfg()

    published = es_stream_producer.publish_index_events(r, [_hot_row(11), _hot_row(12)], cfg)

    assert published == 2
    assert len(r.streams[cfg.es_stream_key]) == 2
    assert len(fake_producer.published) == 2
    assert all(p["topic"] == EVENTS_INDEX_TOPIC for p in fake_producer.published)
    assert fake_producer.published[0]["event"]["id"] == 11
    assert fake_producer.published[0]["key"] == "agent-b"


def test_publish_index_events_redis_failure_still_publishes_redpanda(
    monkeypatch: pytest.MonkeyPatch, dual_write_on: None
) -> None:
    spy = _CounterSpy()
    monkeypatch.setattr(event_log, "incr_counter", spy)
    fake_producer = _FakeEventLogProducer(delivered=True)
    monkeypatch.setattr(es_stream_producer, "get_producer", lambda: fake_producer)
    r = _FakeRedis(fail=True)
    cfg = _worker_cfg()

    published = es_stream_producer.publish_index_events(r, [_hot_row(21)], cfg)

    assert published == 0
    assert len(fake_producer.published) == 1
    assert spy.total("ingest_dual_write_discrepancy_total", stream="events_index", reason="redis_write_failed") == 1.0


def test_publish_index_events_skips_rows_without_pg_id(monkeypatch: pytest.MonkeyPatch, dual_write_on: None) -> None:
    fake_producer = _FakeEventLogProducer()
    monkeypatch.setattr(es_stream_producer, "get_producer", lambda: fake_producer)
    r = _FakeRedis()
    cfg = _worker_cfg()

    row = _hot_row(31)
    row_no_id = dict(row)
    row_no_id["pg_event_id"] = None

    assert es_stream_producer.publish_index_events(r, [row, row_no_id], cfg) == 1
    assert len(fake_producer.published) == 1


def test_dual_write_disabled_keeps_redis_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_REDPANDA_ENABLED", False)
    monkeypatch.setattr(settings, "SEAGULL_REDPANDA_DUAL_WRITE_ENABLED", False)
    called: List[Any] = []
    monkeypatch.setattr(es_stream_producer, "get_producer", lambda: called.append(1))
    r = _FakeRedis()
    cfg = _worker_cfg()

    assert es_stream_producer.publish_index_events(r, [_hot_row(41)], cfg) == 1
    assert called == []
    assert len(r.streams[cfg.es_stream_key]) == 1
