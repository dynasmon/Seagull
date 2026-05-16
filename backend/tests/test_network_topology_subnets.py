from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.features.network_topology import repository as topo_repo
from app.features.network_topology import service as topo_service
from app.features.network_topology.models import TopologyEdgeModel, TopologyNodeModel, TopologyObservationModel

_UTC = timezone.utc
_NOW = datetime(2026, 5, 16, 12, 0, tzinfo=_UTC)


def _node(
    *,
    row_id: int,
    node_key: str,
    node_type: str = "host",
    label: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
    severity: str = "unknown",
    risk_score: int = 0,
    alert_count: int = 0,
    event_count: int = 0,
    confidence: int = 80,
    is_stale: int = 0,
    last_seen_offset_minutes: int = 0,
    extra_data: dict | None = None,
) -> TopologyNodeModel:
    node = TopologyNodeModel()
    node.id = row_id
    node.node_key = node_key
    node.node_type = node_type
    node.agent_id = None
    node.label = label or node_key
    node.ip = ip
    node.cidr = cidr
    node.port = None
    node.protocol = None
    node.severity = severity
    node.risk_score = risk_score
    node.confidence = confidence
    node.is_stale = is_stale
    node.event_count = event_count
    node.alert_count = alert_count
    node.observation_count = 0
    node.first_seen_at = _NOW - timedelta(days=1)
    node.last_seen_at = _NOW - timedelta(minutes=last_seen_offset_minutes)
    node.updated_at = _NOW
    node.extra_data = extra_data or {}
    return node


def _edge(
    *,
    row_id: int,
    edge_key: str,
    source_node_key: str,
    target_node_key: str,
    edge_type: str = "observed_flow",
    severity: str = "unknown",
    alert_count: int = 0,
    event_count: int = 0,
    extra_data: dict | None = None,
) -> TopologyEdgeModel:
    edge = TopologyEdgeModel()
    edge.id = row_id
    edge.edge_key = edge_key
    edge.source_node_key = source_node_key
    edge.target_node_key = target_node_key
    edge.edge_type = edge_type
    edge.agent_id = None
    edge.weight = 1.0
    edge.confidence = 80
    edge.severity = severity
    edge.port = None
    edge.protocol = None
    edge.event_count = event_count
    edge.alert_count = alert_count
    edge.first_seen_at = _NOW - timedelta(days=1)
    edge.last_seen_at = _NOW
    edge.updated_at = _NOW
    edge.extra_data = extra_data or {}
    return edge


def _observation(row_id: int, *, node_key: str) -> TopologyObservationModel:
    obs = TopologyObservationModel()
    obs.id = row_id
    obs.node_key = node_key
    obs.edge_key = None
    obs.agent_id = None
    obs.source_type = "inventory"
    obs.source_id = str(row_id)
    obs.observed_at = _NOW - timedelta(minutes=row_id)
    obs.summary = f"observation-{row_id}"
    obs.raw_context = {"confidence": 80}
    return obs


def _install_repo_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    subnet: TopologyNodeModel | None,
    members: list[TopologyNodeModel] | None = None,
    edges: list[TopologyEdgeModel] | None = None,
    observations: list[TopologyObservationModel] | None = None,
    metrics: dict | None = None,
    member_total: int | None = None,
    edge_total: int | None = None,
    observation_total: int | None = None,
    extra_nodes: list[TopologyNodeModel] | None = None,
) -> None:
    members = members or []
    edges = edges or []
    observations = observations or []
    all_nodes = {node.node_key: node for node in [*(extra_nodes or []), *members, *([subnet] if subnet else [])]}
    monkeypatch.setattr(topo_repo, "get_subnet_node_by_cidr", lambda _db, *, cidr: subnet)
    monkeypatch.setattr(topo_repo, "count_subnet_member_nodes", lambda _db, **kwargs: member_total if member_total is not None else len(members))
    monkeypatch.setattr(
        topo_repo,
        "subnet_member_metrics",
        lambda _db, **kwargs: metrics
        or {
            "node_count": len(members),
            "active_node_count": sum(1 for node in members if not node.is_stale),
            "stale_node_count": sum(1 for node in members if node.is_stale),
            "alert_count": sum(int(node.alert_count or 0) for node in members),
            "risk_score": max((int(node.risk_score or 0) for node in members), default=None),
            "confidence": max((int(node.confidence or 0) for node in members), default=None),
            "first_seen": min((node.first_seen_at for node in members), default=None),
            "last_seen": max((node.last_seen_at for node in members), default=None),
        },
    )
    monkeypatch.setattr(topo_repo, "list_subnet_member_nodes", lambda _db, **kwargs: list(members))
    monkeypatch.setattr(topo_repo, "count_edges_for_subnet", lambda _db, **kwargs: edge_total if edge_total is not None else len(edges))
    monkeypatch.setattr(topo_repo, "list_edges_for_subnet", lambda _db, **kwargs: list(edges))
    monkeypatch.setattr(
        topo_repo,
        "list_nodes_by_keys",
        lambda _db, *, node_keys: [all_nodes[key] for key in node_keys if key in all_nodes],
    )
    monkeypatch.setattr(
        topo_repo,
        "count_observations_for_subnet",
        lambda _db, **kwargs: observation_total if observation_total is not None else len(observations),
    )
    monkeypatch.setattr(topo_repo, "list_observations_for_subnet", lambda _db, **kwargs: list(observations))


def test_subnet_detail_raises_404_when_cidr_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_repo_fakes(monkeypatch, subnet=None)
    with pytest.raises(HTTPException) as exc_info:
        topo_service.get_subnet_detail(SimpleNamespace(), "10.0.99.0/24")
    assert exc_info.value.status_code == 404
    assert exc_info.value.detail["code"] == "subnet_not_found"


def test_subnet_detail_derives_gateway_candidate_from_real_route_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    subnet = _node(row_id=1, node_key="topo:subnet:10.0.0.0/24", node_type="subnet", cidr="10.0.0.0/24")
    member = _node(row_id=2, node_key="topo:interface:agent-1:eth0", node_type="interface", ip="10.0.0.5")
    gateway = _node(row_id=3, node_key="topo:gateway:10.0.0.1", node_type="gateway", ip="10.0.0.1")
    edges = [
        _edge(
            row_id=1,
            edge_key="member",
            source_node_key=member.node_key,
            target_node_key=subnet.node_key,
            edge_type="member_of_subnet",
        ),
        _edge(
            row_id=2,
            edge_key="route",
            source_node_key=member.node_key,
            target_node_key=gateway.node_key,
            edge_type="route_next_hop",
        ),
    ]
    _install_repo_fakes(monkeypatch, subnet=subnet, members=[member], edges=edges, extra_nodes=[gateway])
    detail = topo_service.get_subnet_detail(SimpleNamespace(), "10.0.0.0/24")
    assert [node.node_key for node in detail.gateway_candidates] == [gateway.node_key]


def test_subnet_detail_does_not_guess_gateway_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    subnet = _node(row_id=1, node_key="topo:subnet:10.0.0.0/24", node_type="subnet", cidr="10.0.0.0/24")
    member = _node(row_id=2, node_key="topo:host:10.0.0.1", node_type="host", ip="10.0.0.1")
    edges = [
        _edge(
            row_id=1,
            edge_key="member",
            source_node_key=member.node_key,
            target_node_key=subnet.node_key,
            edge_type="member_of_subnet",
        ),
    ]
    _install_repo_fakes(monkeypatch, subnet=subnet, members=[member], edges=edges)
    detail = topo_service.get_subnet_detail(SimpleNamespace(), "10.0.0.0/24")
    assert detail.gateway_candidates == []


def test_subnet_detail_sorts_members_by_severity_risk_alerts_events_and_recency(monkeypatch: pytest.MonkeyPatch) -> None:
    subnet = _node(row_id=1, node_key="topo:subnet:10.0.0.0/24", node_type="subnet", cidr="10.0.0.0/24")
    members = [
        _node(row_id=2, node_key="low", severity="low", risk_score=99, alert_count=9, event_count=9),
        _node(row_id=3, node_key="critical-old", severity="critical", risk_score=20, alert_count=1, event_count=1, last_seen_offset_minutes=10),
        _node(row_id=4, node_key="critical-high-risk", severity="critical", risk_score=90, alert_count=0, event_count=0),
        _node(row_id=5, node_key="critical-high-alert", severity="critical", risk_score=90, alert_count=3, event_count=1),
    ]
    _install_repo_fakes(monkeypatch, subnet=subnet, members=members)
    detail = topo_service.get_subnet_detail(SimpleNamespace(), "10.0.0.0/24")
    assert [node.node_key for node in detail.member_nodes[:4]] == [
        "critical-high-alert",
        "critical-high-risk",
        "critical-old",
        "low",
    ]


def test_subnet_detail_caps_lists_and_reports_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    subnet = _node(row_id=1, node_key="topo:subnet:10.0.0.0/24", node_type="subnet", cidr="10.0.0.0/24")
    members = [_node(row_id=10 + idx, node_key=f"member-{idx}", ip=f"10.0.0.{idx + 2}") for idx in range(35)]
    external = _node(
        row_id=100,
        node_key="topo:external_ip:1.1.1.1",
        node_type="external_ip",
        ip="1.1.1.1",
        extra_data={"ip_scope": "public_internet"},
    )
    edges = [
        _edge(
            row_id=idx,
            edge_key=f"edge-{idx}",
            source_node_key=members[idx % len(members)].node_key,
            target_node_key=external.node_key,
            event_count=idx,
        )
        for idx in range(60)
    ]
    observations = [_observation(idx, node_key=members[0].node_key) for idx in range(25)]
    _install_repo_fakes(
        monkeypatch,
        subnet=subnet,
        members=members,
        edges=edges,
        observations=observations,
        member_total=35,
        edge_total=60,
        observation_total=25,
        extra_nodes=[external],
    )
    detail = topo_service.get_subnet_detail(SimpleNamespace(), "10.0.0.0/24")
    assert len(detail.member_nodes) == 30
    assert len(detail.related_edges) == 50
    assert len(detail.recent_observations) == 20
    assert detail.truncation.member_nodes.omitted == 5
    assert detail.truncation.related_edges.omitted == 10
    assert detail.truncation.recent_observations.omitted == 5


def test_subnet_detail_related_edges_are_bounded_and_relevant(monkeypatch: pytest.MonkeyPatch) -> None:
    subnet = _node(row_id=1, node_key="topo:subnet:10.0.0.0/24", node_type="subnet", cidr="10.0.0.0/24")
    member = _node(row_id=2, node_key="member-1", ip="10.0.0.5")
    neighbor = _node(row_id=3, node_key="neighbor-1", ip="10.0.1.5")
    edges = [
        _edge(row_id=1, edge_key="member-edge", source_node_key=member.node_key, target_node_key=subnet.node_key, edge_type="member_of_subnet"),
        _edge(row_id=2, edge_key="flow-edge", source_node_key=member.node_key, target_node_key=neighbor.node_key),
    ]
    _install_repo_fakes(monkeypatch, subnet=subnet, members=[member], edges=edges, extra_nodes=[neighbor])
    detail = topo_service.get_subnet_detail(SimpleNamespace(), "10.0.0.0/24")
    assert {edge.edge_key for edge in detail.related_edges} == {"member-edge", "flow-edge"}
    assert all(
        member.node_key in {edge.source_node_key, edge.target_node_key}
        or subnet.node_key in {edge.source_node_key, edge.target_node_key}
        for edge in detail.related_edges
    )


def test_subnet_detail_recent_observations_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    subnet = _node(row_id=1, node_key="topo:subnet:10.0.0.0/24", node_type="subnet", cidr="10.0.0.0/24")
    member = _node(row_id=2, node_key="member-1", ip="10.0.0.5")
    observations = [_observation(idx, node_key=member.node_key) for idx in range(22)]
    _install_repo_fakes(monkeypatch, subnet=subnet, members=[member], observations=observations, observation_total=22)
    detail = topo_service.get_subnet_detail(SimpleNamespace(), "10.0.0.0/24")
    assert len(detail.recent_observations) == 20
    assert detail.truncation.recent_observations.total == 22
