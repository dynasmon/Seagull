from __future__ import annotations

import os
from datetime import datetime, timezone
from types import SimpleNamespace

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")


def test_network_topology_worker_config_defaults(monkeypatch) -> None:
    for name in (
        "SEAGULL_NETWORK_TOPOLOGY_ENABLED",
        "SEAGULL_NETWORK_TOPOLOGY_REFRESH_SECONDS",
        "SEAGULL_NETWORK_TOPOLOGY_WINDOW_MINUTES",
        "SEAGULL_NETWORK_TOPOLOGY_STALE_AFTER_MINUTES",
        "SEAGULL_NETWORK_TOPOLOGY_MAX_EVENTS_PER_RUN",
    ):
        monkeypatch.delenv(name, raising=False)

    from app.workers.intelligence.network_topology.runner import load_worker_config

    cfg = load_worker_config()
    assert cfg.enabled is True
    assert cfg.refresh_seconds == 300.0
    assert cfg.window_minutes == 1440
    assert cfg.stale_after_minutes == 15
    assert cfg.max_events_per_run == 5000


def test_network_topology_worker_config_env(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_NETWORK_TOPOLOGY_ENABLED", "false")
    monkeypatch.setenv("SEAGULL_NETWORK_TOPOLOGY_REFRESH_SECONDS", "120")
    monkeypatch.setenv("SEAGULL_NETWORK_TOPOLOGY_WINDOW_MINUTES", "60")
    monkeypatch.setenv("SEAGULL_NETWORK_TOPOLOGY_STALE_AFTER_MINUTES", "3")
    monkeypatch.setenv("SEAGULL_NETWORK_TOPOLOGY_MAX_EVENTS_PER_RUN", "1000")

    from app.workers.intelligence.network_topology.runner import load_worker_config

    cfg = load_worker_config()
    assert cfg.enabled is False
    assert cfg.refresh_seconds == 120.0
    assert cfg.window_minutes == 60
    assert cfg.stale_after_minutes == 3
    assert cfg.max_events_per_run == 1000


def test_network_topology_manager_child_spec_present() -> None:
    from app.workers.manager import GROUPS

    children = {spec.name: spec for spec in GROUPS["intelligence"]}
    assert "network-topology" in children
    spec = children["network-topology"]
    assert spec.module == "app.workers.intelligence.network_topology.main"
    assert spec.enabled_env == "SEAGULL_NETWORK_TOPOLOGY_ENABLED"
    assert spec.enabled_default is True


def test_network_topology_realtime_invalidation(monkeypatch) -> None:
    from app.features.network_topology import realtime as topo_rt

    emitted: list[tuple[str, dict]] = []
    scheduled: list[dict] = []

    monkeypatch.setattr(topo_rt, "_gate_once", lambda **kwargs: True)
    monkeypatch.setattr(topo_rt, "request_recalculation", lambda **kwargs: scheduled.append(kwargs) or True)
    monkeypatch.setattr(topo_rt, "publish_realtime", lambda event_type, payload: emitted.append((event_type, payload)))

    topo_rt.publish_topology_invalidate(
        reason="inventory_snapshot_ingested",
        source="inventory",
        agent_id="agent-1",
    )

    assert scheduled
    assert emitted == [
        (
            "ui.network_topology.invalidate",
            {
                "reason": "inventory_snapshot_ingested",
                "scope": "network_topology",
                "source": "inventory",
                "agent_id": "agent-1",
                "event_types": [],
                "degraded": False,
                "sampled": False,
                "high_priority": False,
                "requested_at": emitted[0][1]["requested_at"],
            },
        )
    ]


def test_network_topology_realtime_does_not_publish_huge_graph_patch(monkeypatch) -> None:
    from app.features.network_topology import realtime as topo_rt

    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(topo_rt, "_gate_once", lambda **kwargs: True)
    monkeypatch.setattr(
        topo_rt,
        "publish_realtime",
        lambda event_type, payload: emitted.append((event_type, payload)) or True,
    )

    ok = topo_rt.publish_graph_patch(
        generated_at=datetime.now(timezone.utc),
        projected_at=datetime.now(timezone.utc),
        nodes=[{"node_key": f"n{i}"} for i in range(topo_rt.NETWORK_TOPOLOGY_GRAPH_PATCH_MAX_NODES + 1)],
        edges=[],
        graph_health={},
    )

    assert ok is False
    assert "ui.network_topology.graph.patch" not in [event_type for event_type, _ in emitted]


def test_network_topology_recalculation_idempotent(monkeypatch) -> None:
    from app.features.network_topology import service as topo_service
    from app.features.network_topology.schemas import TopologyCoverageOut

    snapshots: dict[str, SimpleNamespace] = {}

    def fake_upsert_snapshot(_db, **kwargs):
        row = SimpleNamespace(
            id=1,
            snapshot_key=kwargs["snapshot_key"],
            node_count=kwargs["node_count"],
            edge_count=kwargs["edge_count"],
            agent_count=kwargs["agent_count"],
            subnet_count=kwargs["subnet_count"],
            external_ip_count=kwargs["external_ip_count"],
            created_at=datetime.now(timezone.utc),
            coverage=kwargs["coverage"],
            metrics=kwargs["metrics"],
        )
        snapshots[kwargs["snapshot_key"]] = row
        return row

    monkeypatch.setattr(topo_service, "project_topology", lambda _db, **kwargs: TopologyCoverageOut(agents_projected=2))
    monkeypatch.setattr(
        topo_service.repository,
        "topology_summary_metrics",
        lambda _db: {
            "total_nodes": 4,
            "total_edges": 3,
            "stale_node_count": 0,
            "by_type": {"agent": 2, "subnet": 1, "external_ip": 1},
            "alert_edge_count": 0,
            "exposure_edge_count": 0,
        },
    )
    monkeypatch.setattr(topo_service.repository, "upsert_snapshot", fake_upsert_snapshot)
    monkeypatch.setattr(topo_service.repository, "get_latest_snapshot", lambda _db: snapshots.get("latest"))
    monkeypatch.setattr(topo_service, "_ingest_pressure_snapshot", lambda: {"sampled": False, "phase": "ok"})
    monkeypatch.setattr(topo_service.topo_realtime, "publish_topology_updated", lambda **kwargs: None)
    monkeypatch.setattr(topo_service.topo_realtime, "publish_summary_patch", lambda **kwargs: None)
    monkeypatch.setattr(topo_service.topo_realtime, "publish_topology_invalidate", lambda **kwargs: None)

    db = SimpleNamespace(flush=lambda: None, commit=lambda: None)
    first = topo_service.run_recalculation(
        db,
        projected_by="test",
        window_minutes=60,
        max_events_per_run=1000,
    )
    second = topo_service.run_recalculation(
        db,
        projected_by="test",
        window_minutes=60,
        max_events_per_run=1000,
    )

    assert len(snapshots) == 1
    assert first.projected_nodes == second.projected_nodes == 4
    assert first.projected_edges == second.projected_edges == 3
    assert snapshots["latest"].snapshot_key == "latest"
