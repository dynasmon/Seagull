import os
from types import SimpleNamespace

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://u:p@localhost:5432/seagull")

import app.features.network_topology.worker_runtime as wr
from app.features.network_topology.worker_runtime import map_event_to_invalidate_kwargs


def _env(event_type, payload):
    return SimpleNamespace(type=event_type, payload=payload)


def test_map_exposure_summary_updated():
    kw = map_event_to_invalidate_kwargs(
        _env("exposure.summary.updated", {"updated_at": "2026-06-18T00:00:00+00:00", "asset_key": "asset-1"})
    )
    assert kw is not None
    assert kw["reason"] == "exposure_graph_updated"
    assert kw["source"] == "exposure"
    assert kw["projected_at"] is not None


def test_map_exposure_summary_updated_missing_timestamp():
    kw = map_event_to_invalidate_kwargs(_env("exposure.summary.updated", {"asset_key": "asset-1"}))
    assert kw is not None
    assert kw["projected_at"] is None


def test_map_inventory_invalidate():
    kw = map_event_to_invalidate_kwargs(_env("ui.inventory.invalidate", {"agent_id": "agent-1"}))
    assert kw == {"reason": "inventory_snapshot_ingested", "source": "inventory", "agent_id": "agent-1"}


def test_map_alert_created_and_updated():
    created = map_event_to_invalidate_kwargs(_env("ui.alerts.delta.patch", {"action": "upsert", "alert": {"id": 7}}))
    assert created is not None
    assert created["reason"] == "alert_created"
    assert created["source"] == "alerts"
    assert created["alert_id"] == 7
    assert created["high_priority"] is True

    updated = map_event_to_invalidate_kwargs(_env("ui.alerts.delta.patch", {"action": "patch", "alert": {"id": 9}}))
    assert updated is not None
    assert updated["reason"] == "alert_updated"
    assert updated["alert_id"] == 9


def test_map_ingest_event_batch():
    kw = map_event_to_invalidate_kwargs(
        _env(
            "ingest.event_batch.ingested",
            {
                "reason": "event_batch_ingested",
                "source": "ingest",
                "agent_id": "agent-2",
                "batch_size": 5,
                "event_types": ["ssh_auth"],
                "degraded": True,
                "sampled": True,
                "high_priority": True,
            },
        )
    )
    assert kw == {
        "reason": "event_batch_ingested",
        "source": "ingest",
        "agent_id": "agent-2",
        "batch_size": 5,
        "event_types": ["ssh_auth"],
        "degraded": True,
        "sampled": True,
        "high_priority": True,
    }


def test_map_ignores_topology_invalidate_and_unknown_events():
    assert map_event_to_invalidate_kwargs(_env("ui.network_topology.invalidate", {})) is None
    assert map_event_to_invalidate_kwargs(_env("ui.network_topology.summary.patch", {})) is None
    assert map_event_to_invalidate_kwargs(_env("some.other.event", {"x": 1})) is None


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value


def _unexpected(*args, **kwargs):
    raise AssertionError("unexpected stream access")


def test_drain_resumes_from_persisted_cursor_after_restart(monkeypatch):
    fake = _FakeRedis()
    fake.store[wr._signal_cursor_key("control")] = "5-0"
    fake.store[wr._signal_cursor_key("critical")] = "4-0"
    monkeypatch.setattr(wr, "get_redis", lambda **kwargs: fake)
    monkeypatch.setattr(wr, "load_portal_realtime_replay", _unexpected)

    seen = {}

    def fake_read(redis_client, *, streams, block_ms, count):
        seen["streams"] = streams
        control_key = wr.portal_realtime_partition_stream_key("control")
        return [SimpleNamespace(stream_id="6-0", message="msg")], {control_key: "6-0"}

    monkeypatch.setattr(wr, "read_portal_realtime_stream", fake_read)
    monkeypatch.setattr(
        wr,
        "parse_realtime_envelope",
        lambda message: SimpleNamespace(type="ui.inventory.invalidate", payload={"agent_id": "a1"}),
    )
    published = []
    monkeypatch.setattr(wr, "publish_topology_invalidate", lambda **kwargs: published.append(kwargs))

    state = SimpleNamespace(last_signal_stream_ids={})
    reacted = wr.drain_topology_signals(state)

    assert seen["streams"] == {
        wr.portal_realtime_partition_stream_key("control"): "5-0",
        wr.portal_realtime_partition_stream_key("critical"): "4-0",
    }
    assert reacted == 1
    assert published[0]["source"] == "inventory"
    assert state.last_signal_stream_ids == {"control": "6-0", "critical": "4-0"}
    assert fake.store[wr._signal_cursor_key("control")] == "6-0"
    assert fake.store[wr._signal_cursor_key("critical")] == "4-0"


def test_drain_first_run_tails_to_latest_and_persists_baseline(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(wr, "get_redis", lambda **kwargs: fake)
    monkeypatch.setattr(
        wr,
        "load_portal_realtime_replay",
        lambda redis_client, *, partitions, max_events: [SimpleNamespace(stream_id=f"{next(iter(partitions))}-42-0")],
    )
    monkeypatch.setattr(wr, "read_portal_realtime_stream", _unexpected)

    state = SimpleNamespace(last_signal_stream_ids={})
    reacted = wr.drain_topology_signals(state)

    assert reacted == 0
    assert state.last_signal_stream_ids == {"control": "control-42-0", "critical": "critical-42-0"}
    assert fake.store[wr._signal_cursor_key("control")] == "control-42-0"
    assert fake.store[wr._signal_cursor_key("critical")] == "critical-42-0"


def test_drain_first_run_empty_stream_persists_zero_baseline(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(wr, "get_redis", lambda **kwargs: fake)
    monkeypatch.setattr(wr, "load_portal_realtime_replay", lambda redis_client, *, partitions, max_events: [])
    monkeypatch.setattr(wr, "read_portal_realtime_stream", _unexpected)

    state = SimpleNamespace(last_signal_stream_ids={})
    reacted = wr.drain_topology_signals(state)

    assert reacted == 0
    assert state.last_signal_stream_ids == {"control": "0", "critical": "0"}
    assert fake.store[wr._signal_cursor_key("control")] == "0"
    assert fake.store[wr._signal_cursor_key("critical")] == "0"
