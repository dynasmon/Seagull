from __future__ import annotations

import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.features.auth.session import PortalPrincipal, get_current_user, require_admin
from app.features.network_topology import api as topo_api
from app.features.network_topology import service as topo_service
from app.features.network_topology.schemas import (
    TopologyCoverageOut,
    TopologyEdgeDetailOut,
    TopologyEdgeOut,
    TopologyGraphHealthOut,
    TopologyGraphOut,
    TopologyNodeDetailOut,
    TopologyNodeOut,
    TopologyRecalculateOut,
    TopologySubnetOut,
    TopologySummaryOut,
)
from app.main import app
from app.shared.schemas import CursorPage

_UTC = timezone.utc


def _now() -> datetime:
    return datetime.now(_UTC)


def _node_out(*, node_key: str = "topo:agent:agent-1", node_type: str = "agent") -> TopologyNodeOut:
    return TopologyNodeOut(
        node_key=node_key,
        node_type=node_type,
        agent_id="agent-1",
        label="agent-1",
        ip="10.0.0.1",
        cidr=None,
        port=None,
        protocol=None,
        severity="unknown",
        risk_score=0,
        confidence=80,
        is_stale=False,
        event_count=0,
        alert_count=0,
        observation_count=0,
        first_seen_at=_now(),
        last_seen_at=_now(),
        updated_at=_now(),
        metadata={},
    )


def _edge_out(*, edge_key: str = "same_agent::src::dst") -> TopologyEdgeOut:
    return TopologyEdgeOut(
        edge_key=edge_key,
        source_node_key="topo:agent:agent-1",
        target_node_key="topo:host:agent-1:host-1",
        edge_type="same_agent",
        agent_id="agent-1",
        weight=1.0,
        confidence=90,
        severity="unknown",
        port=None,
        protocol=None,
        event_count=0,
        alert_count=0,
        first_seen_at=_now(),
        last_seen_at=_now(),
        updated_at=_now(),
        metadata={},
    )


def _graph_out() -> TopologyGraphOut:
    return TopologyGraphOut(
        nodes=[_node_out()],
        edges=[_edge_out()],
        graph_health=TopologyGraphHealthOut(
            max_nodes_applied=200,
            max_edges_applied=300,
            node_count=1,
            edge_count=1,
            nodes_truncated=False,
            edges_truncated=False,
            last_projected_at=_now(),
        ),
    )


def _summary_out() -> TopologySummaryOut:
    return TopologySummaryOut(
        total_nodes=5,
        total_edges=4,
        agent_count=2,
        host_count=2,
        subnet_count=1,
        external_ip_count=0,
        service_count=0,
        docker_network_count=0,
        unknown_count=0,
        stale_node_count=0,
        alert_edge_count=1,
        exposure_edge_count=1,
        node_type_breakdown=[],
        last_projected_at=_now(),
    )


@pytest.fixture(autouse=True)
def _clear_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()



def test_summary_requires_auth() -> None:
    with TestClient(app) as client:
        response = client.get("/network-topology/summary")
    assert response.status_code == 401


def test_graph_requires_auth() -> None:
    with TestClient(app) as client:
        response = client.get("/network-topology/graph")
    assert response.status_code == 401


def test_subnets_requires_auth() -> None:
    with TestClient(app) as client:
        response = client.get("/network-topology/subnets")
    assert response.status_code == 401


def test_observations_requires_auth() -> None:
    with TestClient(app) as client:
        response = client.get("/network-topology/observations")
    assert response.status_code == 401


def test_recalculate_requires_admin() -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    app.dependency_overrides[require_admin] = lambda: (_ for _ in ()).throw(
        HTTPException(status_code=403, detail="Forbidden")
    )
    with TestClient(app) as client:
        response = client.post("/network-topology/recalculate")
    assert response.status_code == 403



def test_summary_returns_expected_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(topo_api.service, "get_summary", lambda _db: _summary_out())
    with TestClient(app) as client:
        response = client.get("/network-topology/summary")
    assert response.status_code == 200
    body = response.json()
    assert body["total_nodes"] == 5
    assert body["total_edges"] == 4
    assert body["agent_count"] == 2
    assert "node_type_breakdown" in body



def test_graph_returns_nodes_and_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(topo_api.service, "get_graph", lambda _db, params: _graph_out())
    with TestClient(app) as client:
        response = client.get("/network-topology/graph")
    assert response.status_code == 200
    body = response.json()
    assert len(body["nodes"]) == 1
    assert len(body["edges"]) == 1
    assert "graph_health" in body
    assert body["graph_health"]["node_count"] == 1


def test_graph_forwards_params(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def _get_graph(_db, params):
        captured["params"] = params
        return _graph_out()

    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(topo_api.service, "get_graph", _get_graph)
    with TestClient(app) as client:
        client.get(
            "/network-topology/graph",
            params={
                "max_nodes": 100,
                "max_edges": 150,
                "min_confidence": 30,
                "agent_id": "agent-1",
                "include_stale": "false",
            },
        )
    p = captured["params"]
    assert p.max_nodes == 100
    assert p.max_edges == 150
    assert p.min_confidence == 30
    assert p.agent_id == "agent-1"
    assert p.include_stale is False


def test_graph_max_nodes_bounded() -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    with TestClient(app) as client:
        response = client.get("/network-topology/graph", params={"max_nodes": 99999})
    assert response.status_code == 422


def test_graph_max_edges_bounded() -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    with TestClient(app) as client:
        response = client.get("/network-topology/graph", params={"max_edges": 99999})
    assert response.status_code == 422



def test_node_detail_returns_correct_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    node = _node_out()
    monkeypatch.setattr(
        topo_api.service,
        "get_node_detail",
        lambda _db, node_key: TopologyNodeDetailOut(
            node=node,
            observations=[],
            connected_nodes=[],
            edges=[_edge_out()],
        ),
    )
    with TestClient(app) as client:
        response = client.get("/network-topology/nodes/topo:agent:agent-1")
    assert response.status_code == 200
    body = response.json()
    assert body["node"]["node_key"] == "topo:agent:agent-1"
    assert "edges" in body
    assert "observations" in body


def test_node_detail_404(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(
        topo_api.service,
        "get_node_detail",
        lambda _db, node_key: (_ for _ in ()).throw(
            HTTPException(status_code=404, detail={"code": "node_not_found", "message": "Node not found", "context": {}})
        ),
    )
    with TestClient(app) as client:
        response = client.get("/network-topology/nodes/topo:missing:key")
    assert response.status_code == 404



def test_edge_detail_returns_correct_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    edge = _edge_out()
    monkeypatch.setattr(
        topo_api.service,
        "get_edge_detail",
        lambda _db, edge_key: TopologyEdgeDetailOut(
            edge=edge,
            observations=[],
            source_node=_node_out(node_key="topo:agent:agent-1"),
            target_node=_node_out(node_key="topo:host:agent-1:host-1", node_type="host"),
        ),
    )
    with TestClient(app) as client:
        response = client.get("/network-topology/edges/same_agent::src::dst")
    assert response.status_code == 200
    body = response.json()
    assert body["edge"]["edge_type"] == "same_agent"
    assert body["source_node"] is not None
    assert body["target_node"] is not None



def test_subnets_returns_cursor_page(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    subnet = TopologySubnetOut(
        node_key="topo:subnet:10.0.0.0/24",
        cidr="10.0.0.0/24",
        label="10.0.0.0/24",
        severity="unknown",
        confidence=70,
        first_seen_at=_now(),
        last_seen_at=_now(),
    )
    monkeypatch.setattr(
        topo_api.service,
        "list_subnets",
        lambda _db, params: CursorPage(items=[subnet], next_cursor=None, has_more=False),
    )
    with TestClient(app) as client:
        response = client.get("/network-topology/subnets")
    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["cidr"] == "10.0.0.0/24"



def test_recalculate_returns_202(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=9, username="root", role="admin")
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=9, username="root", role="admin")
    monkeypatch.setattr(
        topo_api.service,
        "request_recalculate",
        lambda _db, *, admin: TopologyRecalculateOut(
            accepted=True,
            projected_nodes=10,
            projected_edges=8,
            duration_ms=42.0,
            requested_at=_now(),
            coverage=TopologyCoverageOut(agents_projected=2),
        ),
    )
    with TestClient(app) as client:
        response = client.post("/network-topology/recalculate")
    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] is True
    assert body["projected_nodes"] == 10



def test_service_get_graph_respects_hard_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features.network_topology import realtime as topo_rt

    monkeypatch.setattr(topo_rt, "graph_nodes_hard_limit", lambda: 3)
    monkeypatch.setattr(topo_rt, "graph_edges_hard_limit", lambda: 2)

    from app.features.network_topology import repository as topo_repo
    from app.features.network_topology.schemas import TopologyGraphQuery

    nodes_fetched: list[int] = []
    edges_fetched: list[int] = []

    def fake_list_nodes(_db, *, limit, **kwargs):
        nodes_fetched.append(limit)
        return []

    def fake_list_edges(_db, *, limit, **kwargs):
        edges_fetched.append(limit)
        return []

    monkeypatch.setattr(topo_repo, "list_nodes", fake_list_nodes)
    monkeypatch.setattr(topo_repo, "list_edges", fake_list_edges)
    monkeypatch.setattr(topo_repo, "get_latest_snapshot", lambda _db: None)

    params = TopologyGraphQuery(max_nodes=2000, max_edges=3000)
    topo_service.get_graph(SimpleNamespace(), params)

    assert nodes_fetched[0] == 3
    assert edges_fetched[0] == 2



def test_parse_dt_z_suffix_returns_utc_aware() -> None:
    from app.features.network_topology.api import _parse_dt
    from datetime import timezone

    result = _parse_dt("2026-05-12T10:00:00.000Z")
    assert result is not None
    assert result.tzinfo is not None
    assert result.utcoffset().total_seconds() == 0
    assert result.year == 2026
    assert result.hour == 10


def test_parse_dt_naive_string_gets_utc() -> None:
    from app.features.network_topology.api import _parse_dt

    result = _parse_dt("2026-05-12T10:00:00")
    assert result is not None
    assert result.tzinfo is not None
    assert result.utcoffset().total_seconds() == 0


def test_parse_dt_none_returns_none() -> None:
    from app.features.network_topology.api import _parse_dt

    assert _parse_dt(None) is None
    assert _parse_dt("") is None
    assert _parse_dt("not-a-date") is None


def test_service_list_subnets_paginates(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features.network_topology import repository as topo_repo
    from app.features.network_topology.schemas import TopologySubnetQuery

    def _fake_node(idx: int):
        from app.features.network_topology.models import TopologyNodeModel
        n = TopologyNodeModel()
        n.id = idx
        n.node_key = f"topo:subnet:10.0.{idx}.0/24"
        n.node_type = "subnet"
        n.label = f"10.0.{idx}.0/24"
        n.cidr = f"10.0.{idx}.0/24"
        n.agent_id = None
        n.severity = "unknown"
        n.confidence = 70
        n.is_stale = 0
        n.first_seen_at = _now()
        n.last_seen_at = _now()
        n.updated_at = _now()
        n.extra_data = {}
        return n

    rows = [_fake_node(i) for i in range(3)]
    monkeypatch.setattr(topo_repo, "list_subnet_nodes_page", lambda _db, **kwargs: rows)

    page = topo_service.list_subnets(SimpleNamespace(), TopologySubnetQuery(page_size=2))
    assert len(page.items) == 2
    assert page.has_more is True
    assert page.next_cursor is not None


def test_graph_backward_compat_no_new_params(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(topo_api.service, "get_graph", lambda _db, params: _graph_out())
    with TestClient(app) as client:
        response = client.get("/network-topology/graph")
    assert response.status_code == 200
    body = response.json()
    assert "nodes" in body
    assert "edges" in body
    assert "graph_health" in body


def test_graph_view_mode_location_param(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def _capture(_db, params):
        captured["params"] = params
        return _graph_out()

    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(topo_api.service, "get_graph", _capture)
    with TestClient(app) as client:
        client.get("/network-topology/graph", params={"view_mode": "location", "group_by": "agent"})
    assert captured["params"].view_mode == "location"
    assert captured["params"].group_by == "agent"


def test_graph_focused_group_key_param(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def _capture(_db, params):
        captured["params"] = params
        return _graph_out()

    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(topo_api.service, "get_graph", _capture)
    with TestClient(app) as client:
        client.get(
            "/network-topology/graph",
            params={"focused_group_key": "agent:a1", "exclusive_focus": "true"},
        )
    assert captured["params"].focused_group_key == "agent:a1"
    assert captured["params"].exclusive_focus is True


def test_graph_includes_facets_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features.network_topology.schemas import TopologyFacetsOut

    graph_with_facets = _graph_out()
    graph_with_facets.facets = TopologyFacetsOut(total_nodes=1, total_edges=1, node_types={"agent": 1})

    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(topo_api.service, "get_graph", lambda _db, params: graph_with_facets)
    with TestClient(app) as client:
        response = client.get("/network-topology/graph")
    assert response.status_code == 200
    body = response.json()
    assert body["facets"] is not None
    assert body["facets"]["total_nodes"] == 1


def test_graph_includes_groups_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features.network_topology.schemas import TopologyGroupEdgeOut, TopologyGroupOut

    graph_with_groups = _graph_out()
    graph_with_groups.groups = [
        TopologyGroupOut(
            group_key="agent:a1",
            group_type="agent",
            label="Agent A1",
            node_count=1,
        )
    ]
    graph_with_groups.group_edges = []
    graph_with_groups.group_strategy = "auto"

    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(topo_api.service, "get_graph", lambda _db, params: graph_with_groups)
    with TestClient(app) as client:
        response = client.get("/network-topology/graph", params={"view_mode": "location"})
    assert response.status_code == 200
    body = response.json()
    assert body["groups"] is not None
    assert len(body["groups"]) == 1
    assert body["groups"][0]["group_key"] == "agent:a1"
    assert body["group_strategy"] == "auto"


def test_group_detail_returns_404_for_missing_group(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(
        topo_api.service,
        "get_group_detail",
        lambda _db, group_key, params: (_ for _ in ()).throw(
            HTTPException(status_code=404, detail={"code": "group_not_found", "message": "Group not found", "context": {}})
        ),
    )
    with TestClient(app) as client:
        response = client.get("/network-topology/groups/agent:missing")
    assert response.status_code == 404


def test_group_detail_returns_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features.network_topology.schemas import TopologyGroupDetailOut

    detail = TopologyGroupDetailOut(
        group_key="agent:a1",
        group_type="agent",
        label="Agent A1",
        node_count=2,
        edge_count=1,
        alert_count=0,
        highest_severity="unknown",
        top_member_nodes=[_node_out()],
        top_services=[],
        related_edges=[_edge_out()],
    )
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(topo_api.service, "get_group_detail", lambda _db, group_key, params: detail)
    with TestClient(app) as client:
        response = client.get("/network-topology/groups/agent:a1")
    assert response.status_code == 200
    body = response.json()
    assert body["group_key"] == "agent:a1"
    assert body["group_type"] == "agent"
    assert len(body["top_member_nodes"]) == 1
    assert len(body["related_edges"]) == 1


def test_group_detail_requires_auth() -> None:
    with TestClient(app) as client:
        response = client.get("/network-topology/groups/agent:a1")
    assert response.status_code == 401


def test_service_get_graph_with_location_mode_returns_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features.network_topology import realtime as topo_rt
    from app.features.network_topology import repository as topo_repo
    from app.features.network_topology.models import TopologyNodeModel
    from app.features.network_topology.schemas import TopologyGraphQuery

    monkeypatch.setattr(topo_rt, "graph_nodes_hard_limit", lambda: 200)
    monkeypatch.setattr(topo_rt, "graph_edges_hard_limit", lambda: 300)
    monkeypatch.setattr(topo_repo, "get_latest_snapshot", lambda _db: None)
    monkeypatch.setattr(topo_service, "_load_agent_labels", lambda _db: {"agent-1": "Agent One"})

    n = TopologyNodeModel()
    n.id = 1
    n.node_key = "topo:agent:agent-1"
    n.node_type = "agent"
    n.label = "agent-1"
    n.ip = "10.0.0.1"
    n.cidr = None
    n.agent_id = "agent-1"
    n.severity = "unknown"
    n.risk_score = 0
    n.confidence = 80
    n.is_stale = 0
    n.event_count = 0
    n.alert_count = 0
    n.observation_count = 0
    n.first_seen_at = _now()
    n.last_seen_at = _now()
    n.updated_at = _now()
    n.extra_data = {}

    monkeypatch.setattr(topo_repo, "list_nodes", lambda _db, **kwargs: [n])
    monkeypatch.setattr(topo_repo, "list_edges", lambda _db, **kwargs: [])

    params = TopologyGraphQuery(max_nodes=200, max_edges=300, view_mode="location")
    result = topo_service.get_graph(SimpleNamespace(), params)

    assert result.groups is not None
    assert len(result.groups) == 1
    assert result.groups[0].group_key == "agent:agent-1"
    assert result.groups[0].label == "Agent One"
    assert result.facets is not None
    assert result.group_strategy == "auto"


def test_service_get_graph_default_has_no_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features.network_topology import realtime as topo_rt
    from app.features.network_topology import repository as topo_repo
    from app.features.network_topology.schemas import TopologyGraphQuery

    monkeypatch.setattr(topo_rt, "graph_nodes_hard_limit", lambda: 200)
    monkeypatch.setattr(topo_rt, "graph_edges_hard_limit", lambda: 300)
    monkeypatch.setattr(topo_repo, "get_latest_snapshot", lambda _db: None)
    monkeypatch.setattr(topo_repo, "list_nodes", lambda _db, **kwargs: [])
    monkeypatch.setattr(topo_repo, "list_edges", lambda _db, **kwargs: [])

    params = TopologyGraphQuery(max_nodes=200, max_edges=300)
    result = topo_service.get_graph(SimpleNamespace(), params)

    assert result.groups is None
    assert result.facets is not None


def test_service_get_group_detail_raises_404_for_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features.network_topology import realtime as topo_rt
    from app.features.network_topology import repository as topo_repo
    from app.features.network_topology.schemas import TopologyGraphQuery

    monkeypatch.setattr(topo_rt, "graph_nodes_hard_limit", lambda: 200)
    monkeypatch.setattr(topo_rt, "graph_edges_hard_limit", lambda: 300)
    monkeypatch.setattr(topo_repo, "list_nodes", lambda _db, **kwargs: [])
    monkeypatch.setattr(topo_repo, "list_edges", lambda _db, **kwargs: [])

    params = TopologyGraphQuery(max_nodes=200, max_edges=300)
    with pytest.raises(HTTPException) as exc_info:
        topo_service.get_group_detail(SimpleNamespace(), "agent:nonexistent", params)
    assert exc_info.value.status_code == 404


def test_service_get_group_detail_uses_agent_display_label_and_keeps_related_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.features.network_topology import realtime as topo_rt
    from app.features.network_topology import repository as topo_repo
    from app.features.network_topology.models import TopologyEdgeModel, TopologyNodeModel
    from app.features.network_topology.schemas import TopologyGraphQuery

    monkeypatch.setattr(topo_rt, "graph_nodes_hard_limit", lambda: 200)
    monkeypatch.setattr(topo_rt, "graph_edges_hard_limit", lambda: 300)
    monkeypatch.setattr(topo_service, "_load_agent_labels", lambda _db: {"agent-1": "Agent One"})

    def node(
        *,
        row_id: int,
        node_key: str,
        node_type: str,
        agent_id: str,
        label: str,
    ) -> TopologyNodeModel:
        n = TopologyNodeModel()
        n.id = row_id
        n.node_key = node_key
        n.node_type = node_type
        n.label = label
        n.ip = None
        n.cidr = None
        n.port = None
        n.protocol = None
        n.agent_id = agent_id
        n.severity = "unknown"
        n.risk_score = 0
        n.confidence = 80
        n.is_stale = 0
        n.event_count = 0
        n.alert_count = 0
        n.observation_count = 0
        n.first_seen_at = _now()
        n.last_seen_at = _now()
        n.updated_at = _now()
        n.extra_data = {}
        return n

    def edge(
        *,
        row_id: int,
        edge_key: str,
        source_node_key: str,
        target_node_key: str,
    ) -> TopologyEdgeModel:
        e = TopologyEdgeModel()
        e.id = row_id
        e.edge_key = edge_key
        e.source_node_key = source_node_key
        e.target_node_key = target_node_key
        e.edge_type = "observed_flow"
        e.agent_id = None
        e.weight = 1.0
        e.confidence = 80
        e.severity = "unknown"
        e.port = None
        e.protocol = None
        e.event_count = 0
        e.alert_count = 0
        e.first_seen_at = _now()
        e.last_seen_at = _now()
        e.updated_at = _now()
        e.extra_data = {}
        return e

    nodes = [
        node(row_id=1, node_key="agent-node", node_type="agent", agent_id="agent-1", label="agent-1"),
        node(row_id=2, node_key="service-node", node_type="service", agent_id="agent-1", label="svc"),
        node(row_id=3, node_key="neighbor-node", node_type="host", agent_id="agent-2", label="neighbor"),
    ]
    edges = [
        edge(row_id=1, edge_key="member-edge", source_node_key="agent-node", target_node_key="service-node"),
        edge(row_id=2, edge_key="neighbor-edge", source_node_key="service-node", target_node_key="neighbor-node"),
    ]

    monkeypatch.setattr(topo_repo, "list_nodes", lambda _db, **kwargs: nodes)
    monkeypatch.setattr(topo_repo, "list_edges", lambda _db, **kwargs: edges)

    params = TopologyGraphQuery(max_nodes=200, max_edges=300, group_by="agent")
    result = topo_service.get_group_detail(SimpleNamespace(), "agent:agent-1", params)

    assert result.label == "Agent One"
    assert [n.node_key for n in result.top_services] == ["service-node"]
    assert {e.edge_key for e in result.related_edges} == {"member-edge", "neighbor-edge"}
