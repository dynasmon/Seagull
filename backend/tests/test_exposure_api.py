from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.features.auth.session import PortalPrincipal, get_current_user, require_admin
from app.features.exposure import api as exposure_api
from app.features.exposure import realtime as exposure_realtime
from app.features.exposure import repository as exposure_repository
from app.features.exposure import service as exposure_service
from app.features.exposure.models import (
    ExposureAssetPostureModel,
    ExposureEdgeModel,
    ExposureFindingModel,
    ExposureNodeModel,
)
from app.features.exposure.schemas import (
    ExposureAssetDetailOut,
    ExposureAssetPostureOut,
    ExposureAssetsQuery,
    ExposureGraphHealthOut,
    ExposureGraphLegendOut,
    ExposureGraphOut,
    ExposureGraphQuery,
    ExposureRecalculateOut,
    RecommendationOut,
    ScoreBreakdownOut,
    ScoreExplanationOut,
)
from app.features.investigations import public as investigations_public
from app.features.investigations import repository as investigations_repository
from app.features.investigations import service as investigations_service
from app.main import app
from app.shared.schemas import CursorPage

_UTC = timezone.utc


def _now() -> datetime:
    return datetime.now(_UTC)


def _posture_row(*, asset_key: str = "agent:agent-1", row_id: int = 1, score: int = 87) -> ExposureAssetPostureModel:
    row = ExposureAssetPostureModel()
    row.id = row_id
    row.asset_key = asset_key
    row.agent_id = "agent-1"
    row.asset_type = "host"
    row.display_name = "db-01"
    row.hostname = "db-01"
    row.environment = "prod"
    row.criticality = "critical"
    row.severity = "critical" if score >= 80 else "high"
    row.risk_score = score
    row.confidence = 82
    row.exposure_score = 20
    row.vulnerability_score = 30
    row.active_threat_score = 12
    row.persistence_score = 8
    row.attack_chain_score = 22
    row.asset_criticality_score = 18
    row.reliability_penalty = 4
    row.status = "active"
    row.first_seen_at = _now() - timedelta(days=5)
    row.last_seen_at = _now() - timedelta(minutes=5)
    row.updated_at = _now()
    row.score_breakdown = {
        "exposure_score": row.exposure_score,
        "vulnerability_score": row.vulnerability_score,
        "active_threat_score": row.active_threat_score,
        "persistence_score": row.persistence_score,
        "attack_chain_score": row.attack_chain_score,
        "asset_criticality_score": row.asset_criticality_score,
        "reliability_penalty": row.reliability_penalty,
    }
    row.reason_codes = ["attack_chain_progression", "critical_cve", "stale_inventory"]
    row.top_recommendations = [
        {
            "action": "collect_triage_bundle",
            "title": "Collect forensic triage bundle",
            "reason": "A high-risk exposure needs triage evidence.",
            "priority": 10,
            "safety_level": "caution",
            "requires_admin": True,
            "related_evidence_refs": [],
            "reason_code": "attack_chain_progression",
            "metadata": {},
        }
    ]
    row.evidence_counts = {"event": 2, "alert": 1}
    row.extra_data = {"secret_token": "hidden", "open_port_count": 3}
    return row


def _posture_out() -> ExposureAssetPostureOut:
    return ExposureAssetPostureOut(
        asset_key="agent:agent-1",
        agent_id="agent-1",
        asset_type="host",
        display_name="db-01",
        hostname="db-01",
        environment="prod",
        criticality="critical",
        severity="critical",
        risk_score=88,
        confidence=81,
        status="active",
        first_seen_at=_now() - timedelta(days=1),
        last_seen_at=_now() - timedelta(minutes=1),
        updated_at=_now(),
        score_breakdown=ScoreBreakdownOut(
            exposure_score=10,
            vulnerability_score=30,
            active_threat_score=20,
            persistence_score=8,
            attack_chain_score=15,
            asset_criticality_score=10,
            reliability_penalty=2,
        ),
        reason_codes=["attack_chain_progression", "critical_cve"],
        top_recommendations=[
            RecommendationOut(
                action="collect_triage_bundle",
                title="Collect forensic triage bundle",
                reason="Gather host evidence before cleanup.",
                priority=10,
                safety_level="caution",
                requires_admin=True,
                related_evidence_refs=[],
                reason_code="attack_chain_progression",
                metadata={},
            )
        ],
        evidence_counts={"event": 3},
        metadata={"open_port_count": 2},
    )


def _asset_detail_out() -> ExposureAssetDetailOut:
    posture = _posture_out()
    return ExposureAssetDetailOut(
        posture=posture,
        score_breakdown=posture.score_breakdown,
        score_explanation=ScoreExplanationOut(
            risk_score=posture.risk_score,
            severity=posture.severity,
            confidence=posture.confidence,
            score_components=[],
            reasons=[],
            confidence_note="High confidence",
        ),
        reason_codes=list(posture.reason_codes),
        top_findings=[],
        top_recommendations=list(posture.top_recommendations),
        linked_attack_chain_cases=[],
        linked_alerts=[],
        linked_vulnerabilities=[],
        linked_investigations=[],
        linked_response_actions=[],
        recent_score_history=[],
        updated_at=posture.updated_at,
    )


@pytest.fixture(autouse=True)
def _clear_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def test_exposure_summary_requires_authentication() -> None:
    with TestClient(app) as client:
        response = client.get("/exposure/summary")
        assert response.status_code == 401


def test_exposure_assets_forwards_filters(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _list_assets(_db, *, params):
        captured["params"] = params
        return CursorPage(items=[_posture_out()], next_cursor="cursor-2", has_more=True)

    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(exposure_api.service, "list_assets", _list_assets)
    with TestClient(app) as client:
        response = client.get(
            "/exposure/assets",
            params={
                "page_size": 25,
                "q": "db",
                "severity": "HIGH",
                "min_score": 70,
                "agent_id": "agent-1",
                "status": "active",
                "reason_code": "critical_cve",
                "has_attack_chain": "true",
                "has_critical_vuln": "true",
                "has_persistence_signal": "false",
                "sort": "risk_desc",
            },
        )
    assert response.status_code == 200
    params = captured["params"]
    assert params.page_size == 25
    assert params.q == "db"
    assert params.severity == "high"
    assert params.reason_code == "critical_cve"
    assert params.has_attack_chain is True
    assert params.has_persistence_signal is False
    assert response.json()["next_cursor"] == "cursor-2"


def test_invalid_asset_key_route_returns_400() -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    with TestClient(app) as client:
        response = client.get("/exposure/assets/not-valid")
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_asset_key"


def test_mutation_routes_require_admin() -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    app.dependency_overrides[require_admin] = lambda: (_ for _ in ()).throw(HTTPException(status_code=403, detail="Forbidden"))
    with TestClient(app) as client:
        response = client.post("/exposure/recalculate")
    assert response.status_code == 403


def test_recalculate_route_returns_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=9, username="root", role="admin")
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=9, username="root", role="admin")
    monkeypatch.setattr(
        exposure_api.service,
        "request_recalculate",
        lambda _db, *, request, admin: ExposureRecalculateOut(
            accepted=True,
            mode="worker_refresh_requested",
            requested_at=_now(),
            replay_from_event_id=0,
        ),
    )
    with TestClient(app) as client:
        response = client.post("/exposure/recalculate")
    assert response.status_code == 202
    assert response.json()["mode"] == "worker_refresh_requested"


def test_asset_detail_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")
    monkeypatch.setattr(exposure_api.service, "get_asset_detail", lambda _db, *, asset_key: _asset_detail_out())
    with TestClient(app) as client:
        response = client.get("/exposure/assets/agent:agent-1")
    assert response.status_code == 200
    body = response.json()
    assert body["posture"]["asset_key"] == "agent:agent-1"
    assert "score_breakdown" in body
    assert "top_recommendations" in body


def test_asset_graph_route_is_not_shadowed_by_asset_detail_route(monkeypatch: pytest.MonkeyPatch) -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="analyst", role="user")

    called: dict[str, str] = {"detail": "", "graph": ""}

    def fake_detail(_db, *, asset_key: str):
        called["detail"] = asset_key
        return _asset_detail_out()

    def fake_graph(_db, *, asset_key: str, params):
        called["graph"] = asset_key
        return ExposureGraphOut(
            root_node_key="asset:root",
            recommended_focus_node_keys=[],
            nodes=[],
            edges=[],
            legend=ExposureGraphLegendOut(node_types=[], edge_types=[]),
            graph_health=ExposureGraphHealthOut(
                depth_applied=params.depth,
                max_nodes_applied=params.max_nodes,
                max_edges_applied=params.max_edges,
                node_count=0,
                edge_count=0,
                nodes_truncated=False,
                edges_truncated=False,
                posture_updated_at=None,
                stale_agent=False,
                stale_inventory=False,
            ),
        )

    monkeypatch.setattr(exposure_api.service, "get_asset_detail", fake_detail)
    monkeypatch.setattr(exposure_api.service, "get_asset_graph", fake_graph)

    with TestClient(app) as client:
        response = client.get("/exposure/assets/agent:agent-1/graph")

    assert response.status_code == 200
    assert called["graph"] == "agent:agent-1"
    assert called["detail"] == ""


def test_service_list_assets_paginates(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [_posture_row(row_id=1, score=90), _posture_row(row_id=2, score=80), _posture_row(row_id=3, score=70)]
    monkeypatch.setattr(exposure_repository, "list_assets_page", lambda _db, **kwargs: rows)
    page = exposure_service.list_assets(SimpleNamespace(), params=ExposureAssetsQuery(page_size=2, sort="risk_desc"))
    assert len(page.items) == 2
    assert page.has_more is True
    assert page.next_cursor


def test_service_graph_enforces_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    posture = _posture_row()
    nodes: list[ExposureNodeModel] = []
    edges: list[ExposureEdgeModel] = []
    root_key = exposure_service._asset_root_node_key(posture.asset_key)
    for index in range(8):
        node = ExposureNodeModel()
        node.id = index + 1
        node.node_key = root_key if index == 0 else f"node-{index}"
        node.node_type = "asset" if index == 0 else "alert"
        node.asset_key = posture.asset_key
        node.agent_id = posture.agent_id
        node.label = f"Node {index}"
        node.severity = "high"
        node.risk_score = 90 - index
        node.confidence = 70
        node.first_seen_at = _now()
        node.last_seen_at = _now()
        node.updated_at = _now()
        node.properties = {}
        node.source_refs = []
        nodes.append(node)
    for index in range(7):
        edge = ExposureEdgeModel()
        edge.id = index + 1
        edge.edge_key = f"edge-{index}"
        edge.source_node_key = root_key
        edge.target_node_key = nodes[index + 1].node_key
        edge.edge_type = "triggered_alert"
        edge.asset_key = posture.asset_key
        edge.agent_id = posture.agent_id
        edge.weight = 1.0
        edge.confidence = 80
        edge.first_seen_at = _now()
        edge.last_seen_at = _now()
        edge.updated_at = _now()
        edge.properties = {}
        edge.evidence_refs = []
        edges.append(edge)

    monkeypatch.setattr(exposure_repository, "get_asset_posture", lambda _db, asset_key: posture)
    monkeypatch.setattr(exposure_repository, "list_graph_nodes", lambda _db, **kwargs: nodes)
    monkeypatch.setattr(exposure_repository, "list_graph_edges", lambda _db, **kwargs: edges)
    monkeypatch.setattr(exposure_realtime, "graph_nodes_hard_limit", lambda: 4)
    monkeypatch.setattr(exposure_realtime, "graph_edges_hard_limit", lambda: 3)
    graph = exposure_service.get_asset_graph(
        SimpleNamespace(),
        asset_key=posture.asset_key,
        params=ExposureGraphQuery(max_nodes=50, max_edges=50, depth=3, min_confidence=1, include_resolved=False),
    )
    assert len(graph.nodes) <= 4
    assert len(graph.edges) <= 3
    assert graph.root_node_key == root_key


def test_service_detail_redacts_response_action_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    posture = _posture_row()
    finding = ExposureFindingModel()
    finding.finding_key = "finding-1"
    finding.asset_key = posture.asset_key
    finding.agent_id = posture.agent_id
    finding.finding_type = "alert"
    finding.severity = "high"
    finding.score_delta = 20
    finding.confidence = 80
    finding.title = "Critical alert"
    finding.summary = "Investigate now"
    finding.status = "open"
    finding.first_seen_at = _now()
    finding.last_seen_at = _now()
    finding.updated_at = _now()
    finding.related_node_keys = []
    finding.evidence_refs = []
    finding.reason_codes = ["active_alert"]
    finding.recommendations = []
    finding.extra_data = {}

    action = SimpleNamespace(
        id=11,
        action_type="collect_triage_bundle",
        status="pending",
        requested_by="root",
        requested_at=_now(),
        expires_at=_now() + timedelta(hours=1),
        delivered_at=None,
        started_at=None,
        finished_at=None,
        cancelled_at=None,
        cancelled_by=None,
        last_error=None,
        payload={"secret_token": "abc", "limits": {"max_processes": 10}},
    )
    result = SimpleNamespace(status="queued")

    monkeypatch.setattr(exposure_repository, "get_asset_posture", lambda _db, asset_key: posture)
    monkeypatch.setattr(exposure_repository, "list_findings_for_asset", lambda _db, **kwargs: [finding])
    monkeypatch.setattr(exposure_repository, "get_inventory_context", lambda _db, **kwargs: {"hostname": "db-01", "ip_addresses": ["10.0.0.1"]})
    monkeypatch.setattr(exposure_repository, "list_alerts_for_asset", lambda _db, **kwargs: [])
    monkeypatch.setattr(exposure_repository, "list_vulnerabilities_for_asset", lambda _db, **kwargs: [])
    monkeypatch.setattr(exposure_repository, "list_attack_chain_cases_for_agent", lambda _db, **kwargs: [])
    monkeypatch.setattr(exposure_repository, "list_attack_chain_steps_for_cases", lambda _db, **kwargs: [])
    monkeypatch.setattr(exposure_repository, "list_investigations_for_asset", lambda _db, **kwargs: [])
    monkeypatch.setattr(exposure_repository, "list_response_actions_for_agent", lambda _db, **kwargs: [action])
    monkeypatch.setattr(exposure_repository, "latest_response_results_for_actions", lambda _db, **kwargs: {11: result})
    monkeypatch.setattr(exposure_repository, "list_score_history", lambda _db, **kwargs: [])
    detail = exposure_service.get_asset_detail(SimpleNamespace(), asset_key=posture.asset_key)
    assert detail.linked_response_actions[0].payload["secret_token"] == "<redacted>"
    assert detail.top_findings[0].title == "Critical alert"


def test_service_request_recalculate_marks_worker_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class _DB:
        def commit(self):
            calls["committed"] = True

    monkeypatch.setattr(exposure_service, "set_offset", lambda name, value: calls.update(offset=(name, value)))
    monkeypatch.setattr(
        exposure_service.exposure_realtime,
        "request_recalculation",
        lambda **kwargs: calls.update(realtime=kwargs),
    )
    monkeypatch.setattr(
        exposure_service,
        "write_audit_event",
        lambda db, **kwargs: calls.update(audit=kwargs),
    )
    out = exposure_service.request_recalculate(
        _DB(),
        request=SimpleNamespace(state=SimpleNamespace(request_id="req-1"), headers={}, method="POST", url=SimpleNamespace(path="/exposure/recalculate")),
        admin=PortalPrincipal(id=1, username="root", role="admin"),
    )
    assert out.accepted is True
    assert calls["offset"] == ("exposure_graph_events_v1", 0)
    assert calls["realtime"]["requested_by"] == "root"
    assert calls["committed"] is True


def test_service_open_asset_investigation_links_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    detail = _asset_detail_out()
    workspace_row = SimpleNamespace(
        id=7,
        workspace_key="ws-7",
        title="Existing workspace",
        severity="critical",
        priority="p1",
        status="open",
        summary={"exposure_context_key": exposure_service._exposure_context_key(detail.posture.asset_key, detail.reason_codes, None)},
        updated_by="analyst",
    )

    monkeypatch.setattr(exposure_service, "get_asset_detail", lambda _db, *, asset_key: detail)
    monkeypatch.setattr(
        exposure_repository,
        "list_open_workspaces_for_context",
        lambda _db, **kwargs: [workspace_row],
    )
    monkeypatch.setattr(investigations_repository, "get_workspace", lambda _db, workspace_id, for_update=False: workspace_row)
    monkeypatch.setattr(investigations_repository, "save_workspace", lambda _db, row: row)
    monkeypatch.setattr(exposure_service, "_sync_exposure_bookmarks", lambda *args, **kwargs: 2)
    monkeypatch.setattr(investigations_public, "refresh_workspace_summary", lambda *args, **kwargs: True)
    audit_events: list[dict[str, object]] = []
    result = exposure_service.open_asset_investigation(
        SimpleNamespace(commit=lambda: None),
        asset_key=detail.posture.asset_key,
        request=SimpleNamespace(state=SimpleNamespace(request_id="req-1"), headers={}, method="POST", url=SimpleNamespace(path="/x")),
        admin=PortalPrincipal(id=9, username="root", role="admin"),
        audit_writer=lambda _db, **kwargs: audit_events.append(kwargs),
    )
    assert result.created is False
    assert result.workspace_id == 7
    assert result.bookmark_count_added == 2
    assert audit_events[-1]["action"] == "exposure.asset.investigation.open"


def test_service_open_asset_investigation_creates_new(monkeypatch: pytest.MonkeyPatch) -> None:
    detail = _asset_detail_out()
    workspace_row = SimpleNamespace(
        id=8,
        workspace_key="ws-8",
        title="New workspace",
        severity="critical",
        priority="p1",
        status="open",
        summary={},
        updated_by="root",
    )

    class _DB:
        def commit(self):
            return None

    monkeypatch.setattr(exposure_service, "get_asset_detail", lambda _db, *, asset_key: detail)
    monkeypatch.setattr(exposure_repository, "list_open_workspaces_for_context", lambda _db, **kwargs: [])
    monkeypatch.setattr(
        investigations_service,
        "create_workspace",
        lambda _db, *, payload, request, user, audit_writer: SimpleNamespace(id=8, workspace_key="ws-8", title=payload.title, severity=payload.severity, priority=payload.priority),
    )
    monkeypatch.setattr(investigations_repository, "get_workspace", lambda _db, workspace_id, for_update=False: workspace_row)
    monkeypatch.setattr(investigations_repository, "save_workspace", lambda _db, row: row)
    monkeypatch.setattr(exposure_service, "_sync_exposure_bookmarks", lambda *args, **kwargs: 3)
    monkeypatch.setattr(investigations_public, "refresh_workspace_summary", lambda *args, **kwargs: True)
    result = exposure_service.open_asset_investigation(
        _DB(),
        asset_key=detail.posture.asset_key,
        request=SimpleNamespace(state=SimpleNamespace(request_id="req-1"), headers={}, method="POST", url=SimpleNamespace(path="/x")),
        admin=PortalPrincipal(id=9, username="root", role="admin"),
        audit_writer=lambda _db, **kwargs: None,
    )
    assert result.created is True
    assert result.workspace_key == "ws-8"
    assert result.bookmark_count_added == 3
