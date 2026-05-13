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
    TopologyEvidencePageMetaOut,
    TopologyEvidenceSourceOut,
    TopologyGraphHealthOut,
    TopologyGraphOut,
    TopologyNodeDetailOut,
    TopologyNodeOut,
    TopologyObservationOut,
    TopologyRelatedAlertOut,
    TopologyRelatedFlowOut,
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


# ---- Authentication enforcement --------------------------------------------------

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


# ---- Summary endpoint ------------------------------------------------------------

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


# ---- Graph endpoint --------------------------------------------------------------

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


# ---- Node detail endpoint --------------------------------------------------------

def test_node_detail_returns_correct_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    node = _node_out()
    monkeypatch.setattr(
        topo_api.service,
        "get_node_detail",
        lambda _db, node_key: TopologyNodeDetailOut(
            node=node,
            observations=[
                TopologyObservationOut(
                    id=1,
                    node_key=node.node_key,
                    source_type="flow",
                    source_id="123",
                    observed_at=_now(),
                    summary="Observed traffic",
                    confidence=88,
                    raw_context={"confidence": 88},
                )
            ],
            evidence_meta=TopologyEvidencePageMetaOut(limit=20, total=25, omitted=5),
            evidence_sources=[TopologyEvidenceSourceOut(source_type="flow", count=25, latest_observed_at=_now())],
            connected_nodes=[],
            edges=[_edge_out()],
            related_flows=[
                TopologyRelatedFlowOut(
                    id=123,
                    timestamp=_now(),
                    agent_id="agent-1",
                    event_type="conn",
                    src_ip="10.0.0.1",
                    dst_ip="10.0.0.2",
                )
            ],
            related_alerts=[],
            related_services=[],
            related_exposure_findings=[],
            related_attack_chain_cases=[],
        ),
    )
    with TestClient(app) as client:
        response = client.get("/network-topology/nodes/topo:agent:agent-1")
    assert response.status_code == 200
    body = response.json()
    assert body["node"]["node_key"] == "topo:agent:agent-1"
    assert "edges" in body
    assert "observations" in body
    assert body["evidence_meta"]["omitted"] == 5
    assert body["observations"][0]["confidence"] == 88
    assert body["related_flows"][0]["id"] == 123


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


# ---- Edge detail endpoint --------------------------------------------------------

def test_edge_detail_returns_correct_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    edge = _edge_out()
    monkeypatch.setattr(
        topo_api.service,
        "get_edge_detail",
        lambda _db, edge_key: TopologyEdgeDetailOut(
            edge=edge,
            observations=[
                TopologyObservationOut(
                    id=2,
                    node_key=edge.source_node_key,
                    edge_key=edge.edge_key,
                    source_type="alert",
                    source_id="77",
                    observed_at=_now(),
                    summary="Alert linked endpoints",
                    confidence=75,
                    raw_context={"confidence": 75},
                )
            ],
            evidence_meta=TopologyEvidencePageMetaOut(limit=20, total=21, omitted=1),
            evidence_sources=[TopologyEvidenceSourceOut(source_type="alert", count=21, latest_observed_at=_now())],
            source_node=_node_out(node_key="topo:agent:agent-1"),
            target_node=_node_out(node_key="topo:host:agent-1:host-1", node_type="host"),
            related_flows=[],
            related_alerts=[
                TopologyRelatedAlertOut(
                    id=77,
                    created_at=_now(),
                    rule_id="test.rule",
                    severity="high",
                    status="open",
                    confidence=75,
                    description="Test alert",
                )
            ],
            related_exposure_findings=[],
            related_attack_chain_cases=[],
            application_protocols=["http"],
            total_bytes=1024,
        ),
    )
    with TestClient(app) as client:
        response = client.get("/network-topology/edges/same_agent::src::dst")
    assert response.status_code == 200
    body = response.json()
    assert body["edge"]["edge_type"] == "same_agent"
    assert body["source_node"] is not None
    assert body["target_node"] is not None
    assert body["evidence_meta"]["omitted"] == 1
    assert body["related_alerts"][0]["id"] == 77
    assert body["application_protocols"] == ["http"]


# ---- Subnets endpoint ------------------------------------------------------------

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


# ---- Recalculate endpoint --------------------------------------------------------

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


# ---- Service layer: graph bounds -------------------------------------------------

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


def test_service_node_detail_caps_evidence_and_hides_sensitive_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features.network_topology import repository as topo_repo

    now = _now()
    node = SimpleNamespace(
        node_key="topo:host:agent-1:10.0.0.5",
        node_type="host",
        agent_id="agent-1",
        label="host-1",
        ip="10.0.0.5",
        cidr=None,
        port=None,
        protocol=None,
        severity="medium",
        risk_score=50,
        confidence=82,
        is_stale=0,
        event_count=7,
        alert_count=2,
        observation_count=25,
        first_seen_at=now,
        last_seen_at=now,
        updated_at=now,
        extra_data={"hostname": "host-1", "api_token": "should-not-render"},
    )
    observation = SimpleNamespace(
        id=1,
        node_key=node.node_key,
        edge_key=None,
        agent_id="agent-1",
        source_type="flow",
        source_id="123",
        observed_at=now,
        summary="Observed traffic",
        raw_context={"confidence": 88, "secret": "hidden"},
    )
    flow = SimpleNamespace(
        id=123,
        timestamp=now,
        agent_id="agent-1",
        event_type="conn",
        src_ip="10.0.0.5",
        dst_ip="10.0.0.8",
        src_port=51514,
        dst_port=443,
        proto="tcp",
        bytes=2048,
        app_proto="https",
    )
    alert = SimpleNamespace(
        id=77,
        created_at=now,
        rule_id="test.rule",
        severity="high",
        status="open",
        confidence=80,
        description="Suspicious traffic",
        src_ip="10.0.0.5",
        dst_ip="10.0.0.8",
        dst_port=443,
    )
    finding = SimpleNamespace(
        finding_key="finding-1",
        asset_key="asset-1",
        agent_id="agent-1",
        finding_type="service_exposure",
        severity="high",
        status="open",
        confidence=90,
        title="Open service",
        summary="Service exposed",
        last_seen_at=now,
    )
    case = SimpleNamespace(
        id=9,
        agent_id="agent-1",
        suspect_ip="10.0.0.5",
        status="open",
        score=70,
        max_stage="execution",
        step_count=3,
        first_seen_at=now,
        last_seen_at=now,
    )

    monkeypatch.setattr(topo_repo, "get_node", lambda _db, node_key: node)
    monkeypatch.setattr(topo_repo, "list_observations_for_node", lambda _db, **kwargs: [observation])
    monkeypatch.setattr(topo_repo, "count_observations_for_node", lambda _db, **kwargs: 25)
    monkeypatch.setattr(topo_repo, "evidence_sources_for_node", lambda _db, **kwargs: [("flow", 25, now)])
    monkeypatch.setattr(topo_repo, "list_edges_for_node", lambda _db, **kwargs: [])
    monkeypatch.setattr(topo_repo, "list_connected_node_keys", lambda _db, **kwargs: [])
    monkeypatch.setattr(topo_repo, "list_nodes_by_keys", lambda _db, **kwargs: [])
    monkeypatch.setattr(topo_repo, "list_related_flows_for_node", lambda _db, **kwargs: [flow])
    monkeypatch.setattr(topo_repo, "list_related_alerts_for_node", lambda _db, **kwargs: [alert])
    monkeypatch.setattr(topo_repo, "list_related_exposure_findings_for_node", lambda _db, **kwargs: [finding])
    monkeypatch.setattr(topo_repo, "list_related_attack_chain_cases_for_node", lambda _db, **kwargs: [case])

    detail = topo_service.get_node_detail(SimpleNamespace(), node.node_key)

    assert detail.evidence_meta.limit == 20
    assert detail.evidence_meta.total == 25
    assert detail.evidence_meta.omitted == 5
    assert detail.observations[0].confidence == 88
    assert "api_token" not in detail.node.metadata
    assert "secret" not in detail.observations[0].raw_context
    assert detail.related_flows[0].id == 123
    assert detail.related_alerts[0].id == 77
    assert detail.related_exposure_findings[0].finding_key == "finding-1"
    assert detail.related_attack_chain_cases[0].id == 9


def test_service_edge_detail_returns_aggregate_evidence_and_hides_sensitive_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.features.network_topology import repository as topo_repo

    now = _now()
    src_node = SimpleNamespace(
        node_key="topo:host:agent-1:10.0.0.5",
        node_type="host",
        agent_id="agent-1",
        label="host-1",
        ip="10.0.0.5",
        cidr=None,
        port=None,
        protocol=None,
        severity="medium",
        risk_score=50,
        confidence=82,
        is_stale=0,
        event_count=7,
        alert_count=2,
        observation_count=25,
        first_seen_at=now,
        last_seen_at=now,
        updated_at=now,
        extra_data={"ip_scope": "internal_network"},
    )
    dst_node = SimpleNamespace(
        **{
            **src_node.__dict__,
            "node_key": "topo:host:agent-1:10.0.0.8",
            "label": "service-1",
            "ip": "10.0.0.8",
        }
    )
    edge = SimpleNamespace(
        edge_key="observed_flow::src::dst::443::tcp",
        source_node_key=src_node.node_key,
        target_node_key=dst_node.node_key,
        edge_type="observed_flow",
        agent_id="agent-1",
        weight=1.0,
        confidence=74,
        severity="high",
        port=443,
        protocol="tcp",
        event_count=12,
        alert_count=1,
        first_seen_at=now,
        last_seen_at=now,
        updated_at=now,
        extra_data={"app_protocols": ["ssh"], "api_token": "should-not-render"},
    )
    observation = SimpleNamespace(
        id=2,
        node_key=src_node.node_key,
        edge_key=edge.edge_key,
        agent_id="agent-1",
        source_type="flow",
        source_id="124",
        observed_at=now,
        summary="Observed service traffic",
        raw_context={"confidence": 79, "session_secret": "hidden"},
    )
    flow = SimpleNamespace(
        id=124,
        timestamp=now,
        agent_id="agent-1",
        event_type="conn",
        src_ip="10.0.0.5",
        dst_ip="10.0.0.8",
        src_port=51514,
        dst_port=443,
        proto="tcp",
        bytes=512,
        app_proto="https",
    )

    monkeypatch.setattr(topo_repo, "get_edge", lambda _db, edge_key: edge)
    monkeypatch.setattr(topo_repo, "get_node", lambda _db, node_key: src_node if node_key == src_node.node_key else dst_node)
    monkeypatch.setattr(topo_repo, "list_observations_for_edge", lambda _db, **kwargs: [observation])
    monkeypatch.setattr(topo_repo, "count_observations_for_edge", lambda _db, **kwargs: 21)
    monkeypatch.setattr(topo_repo, "evidence_sources_for_edge", lambda _db, **kwargs: [("flow", 21, now)])
    monkeypatch.setattr(topo_repo, "list_related_flows_for_edge", lambda _db, **kwargs: [flow])
    monkeypatch.setattr(topo_repo, "list_related_alerts_for_edge", lambda _db, **kwargs: [])
    monkeypatch.setattr(topo_repo, "list_related_exposure_findings_for_edge", lambda _db, **kwargs: [])
    monkeypatch.setattr(topo_repo, "list_related_attack_chain_cases_for_edge", lambda _db, **kwargs: [])
    monkeypatch.setattr(topo_repo, "edge_flow_metrics", lambda _db, **kwargs: (4096, ["https", "tls"]))

    detail = topo_service.get_edge_detail(SimpleNamespace(), edge.edge_key)

    assert detail.evidence_meta.limit == 20
    assert detail.evidence_meta.total == 21
    assert detail.evidence_meta.omitted == 1
    assert detail.total_bytes == 4096
    assert detail.application_protocols == ["ssh", "https", "tls"]
    assert "api_token" not in detail.edge.metadata
    assert "session_secret" not in detail.observations[0].raw_context


# ---- Service layer: pagination ---------------------------------------------------

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
