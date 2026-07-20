from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://u:p@localhost:5432/seagull")

from app.core.observability import snapshot_metrics
from app.core.realtime import portal as realtime_portal
from app.features.realtime import dashboards, service
from app.shared.analytics import snapshot_store
from app.shared.analytics.snapshot_store import SnapshotRow
from app.shared.analytics.snapshots import SnapshotPage


class _GateRedis:
    def __init__(self) -> None:
        self.keys: dict[str, str] = {}

    def set(self, key: str, value: str, ex: int | None = None, nx: bool = False):
        _ = ex
        if nx and key in self.keys:
            return None
        self.keys[key] = value
        return True


class _StreamRedis:
    def __init__(self) -> None:
        self.cursor = 0
        self.streams: dict[str, list[tuple[str, dict[str, str]]]] = {}

    def incr(self, _key: str) -> int:
        self.cursor += 1
        return self.cursor

    def xadd(self, key: str, fields: dict[str, str], maxlen: int | None = None, approximate: bool = True) -> str:
        _ = (maxlen, approximate)
        stream_id = f"{self.cursor}-0"
        self.streams.setdefault(key, []).append((stream_id, dict(fields)))
        return stream_id


def _counter(name: str, **labels: str) -> float:
    for row in snapshot_metrics()["counters"]:
        if row["name"] != name:
            continue
        if all(row["labels"].get(key) == value for key, value in labels.items()):
            return float(row["value"])
    return 0.0


def _published_envelopes(stream: _StreamRedis) -> list[dict]:
    out: list[dict] = []
    for entries in stream.streams.values():
        for _stream_id, fields in entries:
            out.append(json.loads(fields["envelope"]))
    return out


def _wire_publish(monkeypatch) -> tuple[_StreamRedis, _GateRedis]:
    stream = _StreamRedis()
    gate = _GateRedis()
    monkeypatch.setattr(realtime_portal, "get_redis", lambda **kwargs: stream)
    monkeypatch.setattr(dashboards, "get_redis", lambda **kwargs: gate)
    return stream, gate


def test_every_channel_matches_the_realtime_event_policy() -> None:
    for channel in dashboards.DASHBOARD_CHANNELS.values():
        policy = service.realtime_event_policy(channel.event_type)
        assert policy["topic"] == channel.topic
        assert policy["mode"] == "invalidate"
        assert channel.topic in realtime_portal.PORTAL_REALTIME_TOPICS
        assert channel.topic in service.TOPIC_REQUIRED_SCOPE


def test_channels_cover_every_broadcastable_snapshot_page() -> None:
    import app.features.exposure.service  # noqa: F401
    import app.features.network_topology.service  # noqa: F401
    import app.features.overview.service  # noqa: F401
    import app.features.threat_map.service  # noqa: F401
    import app.features.vuln.overview  # noqa: F401
    from app.shared.analytics.snapshots import iter_snapshot_pages

    registered = {page.page for page in iter_snapshot_pages()}
    assert set(dashboards.DASHBOARD_CHANNELS) <= registered


def test_publish_emits_scoped_envelope_and_counts_it(monkeypatch) -> None:
    stream, _gate = _wire_publish(monkeypatch)
    before = _counter("dashboard_invalidate_emitted_total", page="overview", scope="w60:global")

    outcome = dashboards.publish_dashboard_invalidate(
        page="overview",
        version='W/"1-abc"',
        scope_key="seagull:overview:w60",
        scope={"window_minutes": 60, "agent_id": None, "lite": False},
        scope_label="w60:global",
    )

    assert outcome == "emitted"
    assert _counter("dashboard_invalidate_emitted_total", page="overview", scope="w60:global") == before + 1.0

    envelopes = _published_envelopes(stream)
    assert len(envelopes) == 1
    envelope = envelopes[0]
    assert envelope["type"] == "ui.overview.invalidate"
    assert envelope["topic"] == "overview"
    assert envelope["mode"] == "invalidate"
    assert envelope["payload"]["page"] == "overview"
    assert envelope["payload"]["version"] == 'W/"1-abc"'
    assert envelope["payload"]["scope_params"] == {"window_minutes": 60, "agent_id": None, "lite": False}


def test_publish_is_throttled_within_the_minimum_interval(monkeypatch) -> None:
    stream, _gate = _wire_publish(monkeypatch)
    before = _counter("dashboard_invalidate_throttled_total", page="threat_map", reason="min_interval")

    first = dashboards.publish_dashboard_invalidate(page="threat_map", version="v1", scope_key="tm:1440")
    second = dashboards.publish_dashboard_invalidate(page="threat_map", version="v2", scope_key="tm:1440")
    other_scope = dashboards.publish_dashboard_invalidate(page="threat_map", version="v3", scope_key="tm:360")

    assert (first, second, other_scope) == ("emitted", "throttled", "emitted")
    assert _counter("dashboard_invalidate_throttled_total", page="threat_map", reason="min_interval") == before + 1.0
    assert len(_published_envelopes(stream)) == 2


def test_publish_reports_dropped_when_the_stream_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(realtime_portal, "get_redis", lambda **kwargs: None)
    monkeypatch.setattr(dashboards, "get_redis", lambda **kwargs: _GateRedis())

    outcome = dashboards.publish_dashboard_invalidate(page="vuln_summary", version="v1", scope_key="vuln:1")

    assert outcome == "dropped"


def test_publish_is_a_no_op_for_unmapped_pages(monkeypatch) -> None:
    stream, _gate = _wire_publish(monkeypatch)

    assert dashboards.publish_dashboard_invalidate(page="unit_page", version="v1", scope_key="k") == "unmapped"
    assert _published_envelopes(stream) == []


def test_publish_is_disabled_by_flag(monkeypatch) -> None:
    from app.core.config import settings

    stream, _gate = _wire_publish(monkeypatch)
    monkeypatch.setattr(settings, "SEAGULL_REALTIME_DASHBOARD_INVALIDATE_ENABLED", False, raising=False)

    assert dashboards.publish_dashboard_invalidate(page="overview", version="v1", scope_key="k") == "disabled"
    assert _published_envelopes(stream) == []


def test_scope_normalization_bounds_payload_size() -> None:
    normalized = dashboards._normalize_scope({f"k{i}": "x" * 200 for i in range(40)})

    assert len(normalized) == 12
    assert all(len(value) == 96 for value in normalized.values())


def _envelope(page: str | None, scope_params: dict | None, cursor: str) -> service.RealtimeEnvelope:
    payload: dict = {"reason": "content_changed"}
    if page is not None:
        payload["page"] = page
    if scope_params is not None:
        payload["scope_params"] = scope_params
    return service.build_realtime_envelope(
        event_type="ui.overview.invalidate",
        payload=payload,
        cursor=cursor,
    )


def test_coalescing_keeps_distinct_dashboard_scopes() -> None:
    envelopes = [
        _envelope("overview", {"window_minutes": 60}, "1"),
        _envelope("overview", {"window_minutes": 1440}, "2"),
        _envelope("overview", {"window_minutes": 60}, "3"),
    ]

    out = service.coalesce_realtime_envelopes(envelopes)

    assert [item.cursor for item in out] == ["2", "3"]


def test_coalescing_still_collapses_untagged_invalidates() -> None:
    envelopes = [_envelope(None, None, "1"), _envelope(None, None, "2")]

    out = service.coalesce_realtime_envelopes(envelopes)

    assert [item.cursor for item in out] == ["2"]


def test_delivery_counter_tracks_dashboard_invalidates_only() -> None:
    before = _counter("dashboard_invalidate_delivered_total", page="overview")

    dashboards.record_dashboard_invalidate_delivery(_envelope("overview", {"window_minutes": 60}, "1"))
    dashboards.record_dashboard_invalidate_delivery(_envelope(None, None, "2"))
    dashboards.record_dashboard_invalidate_delivery(
        service.build_realtime_envelope(event_type="ui.overview.kpi.patch", payload={"events_5m_delta": 1}, cursor="3")
    )

    assert _counter("dashboard_invalidate_delivered_total", page="overview") == before + 1.0


def test_content_version_ignores_page_declared_volatile_keys() -> None:
    from app.shared.analytics.snapshots import snapshot_content_version

    page = SnapshotPage(
        page="network_topology_summary",
        flag_env="SEAGULL_SNAPSHOT_TOPOLOGY_SUMMARY_ENABLED",
        schema_version=1,
        raw_compute=None,  # type: ignore[arg-type]
        scope_key_builder=lambda _params: "k",
        static_scopes=lambda: [{}],
        volatile_keys=frozenset({"freshness_seconds"}),
    )

    drifted = snapshot_content_version(page, {"total_nodes": 4, "freshness_seconds": 422})
    baseline = snapshot_content_version(page, {"total_nodes": 4, "freshness_seconds": 360})
    changed = snapshot_content_version(page, {"total_nodes": 5, "freshness_seconds": 360})

    assert drifted == baseline
    assert changed != baseline


def test_content_version_matches_the_response_etag_when_nothing_is_excluded() -> None:
    from app.shared.analytics import payload_etag
    from app.shared.analytics.snapshots import snapshot_content_version

    page = SnapshotPage(
        page="exposure_summary",
        flag_env="SEAGULL_SNAPSHOT_EXPOSURE_SUMMARY_ENABLED",
        schema_version=3,
        raw_compute=None,  # type: ignore[arg-type]
        scope_key_builder=lambda _params: "k",
        static_scopes=lambda: [{}],
    )
    payload = {"assets": 12, "meta": {"generated_at": "now"}}

    assert snapshot_content_version(page, payload) == payload_etag(payload, schema_version=3)


def _worker_page(monkeypatch, payloads: list[dict]) -> SnapshotPage:
    from app.core.config import settings
    from app.shared.analytics import snapshots

    monkeypatch.setattr(settings, "SEAGULL_SNAPSHOT_OVERVIEW_ENABLED", True, raising=False)
    monkeypatch.setattr(snapshots, "get_redis", lambda: None)

    async def raw_compute(_params: dict) -> dict:
        return payloads.pop(0)

    return SnapshotPage(
        page="overview",
        flag_env="SEAGULL_SNAPSHOT_OVERVIEW_ENABLED",
        schema_version=1,
        raw_compute=raw_compute,
        scope_key_builder=lambda params: f"overview:w{params['window_minutes']}",
        static_scopes=lambda: [{"window_minutes": 60}],
        track_params=lambda params: {"window_minutes": params["window_minutes"], "agent_id": None},
        scope_label=lambda params: f"w{params['window_minutes']}:global",
    )


def _run_worker_cycles(monkeypatch, payloads: list[dict], outcomes: list[str]) -> list[dict]:
    from app.workers.analytics.snapshots import main as worker_main

    page = _worker_page(monkeypatch, payloads)
    stored: dict[tuple[str, str], SnapshotRow] = {}
    published: dict[tuple[str, str], str] = {}
    calls: list[dict] = []

    def _fake_upsert(*, page: str, scope_key: str, schema_version: int, payload: dict, computed_ms: float, computed_at=None) -> None:
        stored[(page, scope_key)] = SnapshotRow(
            page=page,
            scope_key=scope_key,
            schema_version=schema_version,
            payload=payload,
            computed_at=computed_at or datetime.now(timezone.utc),
            computed_ms=computed_ms,
        )

    monkeypatch.setattr(snapshot_store, "upsert_snapshot", _fake_upsert)
    monkeypatch.setattr(snapshot_store, "read_snapshot", lambda p, k: stored.get((p, k)))
    monkeypatch.setattr(snapshot_store, "read_published_hash", lambda p, k: published.get((p, k)))
    monkeypatch.setattr(
        snapshot_store,
        "mark_published",
        lambda *, page, scope_key, published_hash: published.__setitem__((page, scope_key), published_hash),
    )
    monkeypatch.setattr(worker_main, "get_redis", lambda: None)

    async def _acquire(_key: str, *, ttl_s: float):
        return "token"

    async def _release(_key: str, _token: str) -> None:
        return None

    monkeypatch.setattr(worker_main, "acquire_lock", _acquire)
    monkeypatch.setattr(worker_main, "release_lock", _release)

    def _fake_publish(**kwargs):
        calls.append(kwargs)
        return outcomes.pop(0)

    monkeypatch.setattr(worker_main, "publish_dashboard_invalidate", _fake_publish)

    for _ in range(len(payloads)):
        asyncio.run(worker_main.run_page(page))
    return calls


def test_worker_announces_only_when_content_changes(monkeypatch) -> None:
    calls = _run_worker_cycles(
        monkeypatch,
        payloads=[
            {"value": 1, "meta": {"tick": 1}},
            {"value": 1, "meta": {"tick": 2}},
            {"value": 2, "meta": {"tick": 3}},
        ],
        outcomes=["emitted", "emitted"],
    )

    assert len(calls) == 2
    assert calls[0]["page"] == "overview"
    assert calls[0]["scope"] == {"window_minutes": 60, "agent_id": None}
    assert calls[0]["scope_label"] == "w60:global"
    assert calls[0]["version"] != calls[1]["version"]


def test_worker_retries_a_throttled_announcement_on_the_next_cycle(monkeypatch) -> None:
    calls = _run_worker_cycles(
        monkeypatch,
        payloads=[
            {"value": 1, "meta": {"tick": 1}},
            {"value": 1, "meta": {"tick": 2}},
        ],
        outcomes=["throttled", "emitted"],
    )

    assert len(calls) == 2
    assert calls[0]["version"] == calls[1]["version"]


def test_worker_survives_an_announcement_failure(monkeypatch) -> None:
    from app.workers.analytics.snapshots import main as worker_main

    page = _worker_page(monkeypatch, [{"value": 1}])
    stored: dict[tuple[str, str], SnapshotRow] = {}

    def _fake_upsert(*, page: str, scope_key: str, schema_version: int, payload: dict, computed_ms: float, computed_at=None) -> None:
        stored[(page, scope_key)] = SnapshotRow(
            page=page,
            scope_key=scope_key,
            schema_version=schema_version,
            payload=payload,
            computed_at=computed_at or datetime.now(timezone.utc),
            computed_ms=computed_ms,
        )

    def _boom(*_args, **_kwargs):
        raise RuntimeError("store unavailable")

    monkeypatch.setattr(snapshot_store, "upsert_snapshot", _fake_upsert)
    monkeypatch.setattr(snapshot_store, "read_snapshot", lambda p, k: stored.get((p, k)))
    monkeypatch.setattr(snapshot_store, "read_published_hash", _boom)
    monkeypatch.setattr(worker_main, "get_redis", lambda: None)

    async def _acquire(_key: str, *, ttl_s: float):
        return "token"

    async def _release(_key: str, _token: str) -> None:
        return None

    monkeypatch.setattr(worker_main, "acquire_lock", _acquire)
    monkeypatch.setattr(worker_main, "release_lock", _release)

    stats = asyncio.run(worker_main.run_page(page))

    assert stats == {"ok": 1, "error": 0, "locked": 0, "fresh": 0}
    assert ("overview", "overview:w60") in stored
