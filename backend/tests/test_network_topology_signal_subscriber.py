from types import SimpleNamespace

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
