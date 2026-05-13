from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.api.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.config.env_secrets import env_value
from app.features.auth.session import PortalPrincipal
from app.features.network_topology import realtime as topo_realtime
from app.features.network_topology import repository
from app.features.network_topology.models import (
    TopologyEdgeModel,
    TopologyNodeModel,
    TopologyObservationModel,
)
from app.features.network_topology.projector import project_topology
from app.features.network_topology.schemas import (
    TopologyCoverageOut,
    TopologyEdgeDetailOut,
    TopologyEdgeOut,
    TopologyEvidencePageMetaOut,
    TopologyEvidenceSourceOut,
    TopologyGraphHealthOut,
    TopologyGraphOut,
    TopologyGraphQuery,
    TopologyRelatedAlertOut,
    TopologyRelatedAttackChainCaseOut,
    TopologyRelatedExposureFindingOut,
    TopologyRelatedFlowOut,
    TopologyNodeDetailOut,
    TopologyNodeOut,
    TopologyNodeTypeStat,
    TopologyObservationOut,
    TopologyObservationQuery,
    TopologyRecalculateOut,
    TopologySubnetOut,
    TopologySubnetQuery,
    TopologySummaryOut,
)
from app.shared.schemas import CursorPage

_UTC = timezone.utc
_DETAIL_OBSERVATION_LIMIT = 20
_DETAIL_EDGE_LIMIT = 50
_DETAIL_RELATED_LIMIT = 10
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "private_key",
    "session",
)


def _env_int(name: str, default: int) -> int:
    raw = env_value(name, None)
    if raw is None:
        return default
    try:
        return int(str(raw).strip(), 10)
    except Exception:
        return default


def _config_window_minutes() -> int:
    return max(5, _env_int("SEAGULL_NETWORK_TOPOLOGY_WINDOW_MINUTES", 1440))


def _config_stale_after_minutes() -> int:
    return max(1, _env_int("SEAGULL_NETWORK_TOPOLOGY_STALE_AFTER_MINUTES", 15))


def _config_max_events_per_run() -> int:
    return max(100, _env_int("SEAGULL_NETWORK_TOPOLOGY_MAX_EVENTS_PER_RUN", 5000))


def get_summary(db: Session) -> TopologySummaryOut:
    metrics = repository.topology_summary_metrics(db)
    by_type: dict[str, int] = metrics.get("by_type", {})
    snapshot = repository.get_latest_snapshot(db)
    last_projected_at = snapshot.created_at if snapshot else None
    freshness = _freshness_metadata(snapshot)

    return TopologySummaryOut(
        total_nodes=metrics["total_nodes"],
        total_edges=metrics["total_edges"],
        agent_count=by_type.get("agent", 0),
        host_count=by_type.get("host", 0),
        subnet_count=by_type.get("subnet", 0),
        external_ip_count=by_type.get("external_ip", 0),
        service_count=by_type.get("service", 0),
        docker_network_count=by_type.get("docker_network", 0),
        unknown_count=by_type.get("unknown", 0),
        stale_node_count=metrics["stale_node_count"],
        alert_edge_count=metrics["alert_edge_count"],
        exposure_edge_count=metrics["exposure_edge_count"],
        node_type_breakdown=[
            TopologyNodeTypeStat(node_type=k, count=v)
            for k, v in sorted(by_type.items(), key=lambda x: -x[1])
        ],
        last_projected_at=last_projected_at,
        **freshness,
    )


def get_graph(db: Session, params: TopologyGraphQuery) -> TopologyGraphOut:
    node_limit = min(int(params.max_nodes), topo_realtime.graph_nodes_hard_limit())
    edge_limit = min(int(params.max_edges), topo_realtime.graph_edges_hard_limit())

    nodes = repository.list_nodes(
        db,
        agent_id=params.agent_id,
        node_types=params.node_types or None,
        ip_scope=params.ip_scope,
        min_confidence=params.min_confidence,
        include_stale=params.include_stale,
        since=params.since,
        until=params.until,
        limit=node_limit,
    )
    edges = repository.list_edges(
        db,
        agent_id=params.agent_id,
        edge_types=params.edge_types or None,
        min_confidence=params.min_confidence,
        since=params.since,
        until=params.until,
        limit=edge_limit,
    )

    nodes_truncated = len(nodes) >= node_limit
    edges_truncated = len(edges) >= edge_limit
    snapshot = repository.get_latest_snapshot(db)
    freshness = _freshness_metadata(snapshot)
    graph_truncation = dict(freshness.get("truncation") or {})
    graph_truncation.update(
        {
            "nodes_truncated": bool(nodes_truncated),
            "edges_truncated": bool(edges_truncated),
            "max_nodes_applied": int(node_limit),
            "max_edges_applied": int(edge_limit),
        }
    )
    graph_freshness = dict(freshness)
    graph_freshness["truncation"] = graph_truncation

    return TopologyGraphOut(
        nodes=[_node_to_out(n) for n in nodes],
        edges=[_edge_to_out(e) for e in edges],
        graph_health=TopologyGraphHealthOut(
            max_nodes_applied=node_limit,
            max_edges_applied=edge_limit,
            node_count=len(nodes),
            edge_count=len(edges),
            nodes_truncated=nodes_truncated,
            edges_truncated=edges_truncated,
            last_projected_at=snapshot.created_at if snapshot else None,
            **graph_freshness,
        ),
        **graph_freshness,
    )


def get_node_detail(db: Session, node_key: str) -> TopologyNodeDetailOut:
    node = repository.get_node(db, node_key)
    if node is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "node_not_found",
                "message": "Node not found",
                "context": {"node_key": node_key},
            },
        )

    observations = repository.list_observations_for_node(db, node_key=node_key, limit=_DETAIL_OBSERVATION_LIMIT)
    evidence_total = repository.count_observations_for_node(db, node_key=node_key)
    evidence_sources = repository.evidence_sources_for_node(db, node_key=node_key)
    edges = repository.list_edges_for_node(db, node_key=node_key, limit=_DETAIL_EDGE_LIMIT)
    connected_keys = repository.list_connected_node_keys(db, node_key=node_key, limit=_DETAIL_EDGE_LIMIT)
    connected_nodes = repository.list_nodes_by_keys(db, node_keys=connected_keys)
    related_flows = repository.list_related_flows_for_node(db, node=node, limit=_DETAIL_RELATED_LIMIT)
    related_alerts = repository.list_related_alerts_for_node(db, node=node, limit=_DETAIL_RELATED_LIMIT)
    related_findings = repository.list_related_exposure_findings_for_node(db, node=node, limit=_DETAIL_RELATED_LIMIT)
    related_cases = repository.list_related_attack_chain_cases_for_node(db, node=node, limit=_DETAIL_RELATED_LIMIT)
    related_services = [n for n in connected_nodes if str(n.node_type or "").lower() == "service"]
    if str(node.node_type or "").lower() == "service":
        related_services.insert(0, node)

    return TopologyNodeDetailOut(
        node=_node_to_out(node),
        observations=[_obs_to_out(o) for o in observations],
        evidence_meta=_evidence_meta(_DETAIL_OBSERVATION_LIMIT, evidence_total),
        evidence_sources=[_evidence_source_to_out(row) for row in evidence_sources],
        connected_nodes=[_node_to_out(n) for n in connected_nodes],
        edges=[_edge_to_out(e) for e in edges],
        related_alerts=[_alert_to_out(a) for a in related_alerts],
        related_flows=[_flow_to_out(f) for f in related_flows],
        related_services=[_node_to_out(n) for n in related_services[:_DETAIL_RELATED_LIMIT]],
        related_exposure_findings=[_exposure_finding_to_out(f) for f in related_findings],
        related_attack_chain_cases=[_attack_chain_case_to_out(c) for c in related_cases],
    )


def get_edge_detail(db: Session, edge_key: str) -> TopologyEdgeDetailOut:
    edge = repository.get_edge(db, edge_key)
    if edge is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "edge_not_found",
                "message": "Edge not found",
                "context": {"edge_key": edge_key},
            },
        )

    src_node = repository.get_node(db, edge.source_node_key)
    dst_node = repository.get_node(db, edge.target_node_key)
    observations = repository.list_observations_for_edge(db, edge_key=edge.edge_key, limit=_DETAIL_OBSERVATION_LIMIT)
    evidence_total = repository.count_observations_for_edge(db, edge_key=edge.edge_key)
    evidence_sources = repository.evidence_sources_for_edge(db, edge_key=edge.edge_key)
    related_flows = repository.list_related_flows_for_edge(
        db,
        edge=edge,
        source_node=src_node,
        target_node=dst_node,
        limit=_DETAIL_RELATED_LIMIT,
    )
    related_alerts = repository.list_related_alerts_for_edge(
        db,
        edge=edge,
        source_node=src_node,
        target_node=dst_node,
        limit=_DETAIL_RELATED_LIMIT,
    )
    related_findings = repository.list_related_exposure_findings_for_edge(
        db,
        source_node=src_node,
        target_node=dst_node,
        limit=_DETAIL_RELATED_LIMIT,
    )
    related_cases = repository.list_related_attack_chain_cases_for_edge(
        db,
        source_node=src_node,
        target_node=dst_node,
        limit=_DETAIL_RELATED_LIMIT,
    )
    total_bytes, aggregate_app_protocols = repository.edge_flow_metrics(
        db,
        edge=edge,
        source_node=src_node,
        target_node=dst_node,
    )
    app_protocols = _app_protocols_for_edge(edge, related_flows, aggregate_app_protocols)

    return TopologyEdgeDetailOut(
        edge=_edge_to_out(edge),
        observations=[_obs_to_out(o) for o in observations],
        evidence_meta=_evidence_meta(_DETAIL_OBSERVATION_LIMIT, evidence_total),
        evidence_sources=[_evidence_source_to_out(row) for row in evidence_sources],
        source_node=_node_to_out(src_node) if src_node else None,
        target_node=_node_to_out(dst_node) if dst_node else None,
        related_alerts=[_alert_to_out(a) for a in related_alerts],
        related_flows=[_flow_to_out(f) for f in related_flows],
        related_exposure_findings=[_exposure_finding_to_out(f) for f in related_findings],
        related_attack_chain_cases=[_attack_chain_case_to_out(c) for c in related_cases],
        application_protocols=app_protocols,
        total_bytes=total_bytes,
    )


def list_subnets(db: Session, params: TopologySubnetQuery) -> CursorPage[TopologySubnetOut]:
    cursor_parsed = None
    if params.cursor:
        cursor_parsed = parse_cursor_ts_id(params.cursor, ts_key="ts", id_key="id")

    rows = repository.list_subnet_nodes_page(
        db,
        page_size=params.page_size,
        agent_id=params.agent_id,
        since=params.since,
        until=params.until,
        cursor_parsed=cursor_parsed,
    )

    has_more = len(rows) > params.page_size
    page_rows = rows[:params.page_size]
    next_cursor: str | None = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = make_cursor_ts_id(_to_utc(last.last_seen_at), int(last.id))

    return CursorPage(
        items=[_subnet_node_to_out(r) for r in page_rows],
        next_cursor=next_cursor,
        has_more=has_more,
    )


def list_observations(db: Session, params: TopologyObservationQuery) -> CursorPage[TopologyObservationOut]:
    cursor_parsed = None
    if params.cursor:
        cursor_parsed = parse_cursor_ts_id(params.cursor, ts_key="ts", id_key="id")

    rows = repository.list_observations_page(
        db,
        page_size=params.page_size,
        node_key=params.node_key,
        agent_id=params.agent_id,
        source_type=params.source_type,
        since=params.since,
        until=params.until,
        cursor_parsed=cursor_parsed,
    )

    has_more = len(rows) > params.page_size
    page_rows = rows[:params.page_size]
    next_cursor: str | None = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = make_cursor_ts_id(_to_utc(last.observed_at), int(last.id))

    return CursorPage(
        items=[_obs_to_out(o) for o in page_rows],
        next_cursor=next_cursor,
        has_more=has_more,
    )


def request_recalculate(db: Session, *, admin: PortalPrincipal) -> TopologyRecalculateOut:
    requested_at = datetime.now(_UTC)
    snapshot = repository.get_latest_snapshot(db)
    topo_realtime.request_recalculation(
        requested_at=requested_at,
        requested_by=admin.username,
        request_id=None,
        reason="manual_recalculate",
        mode="full",
        debounce_seconds=0,
    )
    topo_realtime.publish_topology_invalidate(
        reason="manual_recalculate_requested",
        source="api",
        high_priority=True,
        schedule_recalculation=False,
    )

    coverage = TopologyCoverageOut(**(snapshot.coverage if snapshot and isinstance(snapshot.coverage, dict) else {}))
    return TopologyRecalculateOut(
        accepted=True,
        projected_nodes=int(snapshot.node_count if snapshot else 0),
        projected_edges=int(snapshot.edge_count if snapshot else 0),
        duration_ms=0.0,
        requested_at=requested_at,
        coverage=coverage,
    )


def run_recalculation(
    db: Session,
    *,
    projected_by: str,
    reason: str = "worker",
    window_minutes: int | None = None,
    max_events_per_run: int | None = None,
) -> TopologyRecalculateOut:
    requested_at = datetime.now(_UTC)
    t0 = time.perf_counter()
    window = max(5, int(window_minutes or _config_window_minutes()))
    max_events = max(100, int(max_events_per_run or _config_max_events_per_run()))

    coverage = project_topology(db, window_minutes=window, max_events_per_run=max_events)
    db.flush()

    metrics = repository.topology_summary_metrics(db)
    node_count = metrics["total_nodes"]
    edge_count = metrics["total_edges"]
    snapshot_metrics = _build_snapshot_metrics(
        coverage=coverage,
        projected_by=projected_by,
        reason=reason,
        requested_at=requested_at,
        window_minutes=window,
        max_events_per_run=max_events,
    )

    repository.upsert_snapshot(
        db,
        snapshot_key="latest",
        node_count=node_count,
        edge_count=edge_count,
        agent_count=metrics.get("by_type", {}).get("agent", 0),
        subnet_count=metrics.get("by_type", {}).get("subnet", 0),
        external_ip_count=metrics.get("by_type", {}).get("external_ip", 0),
        coverage=_model_dict(coverage),
        metrics=snapshot_metrics,
    )
    db.commit()

    duration_ms = (time.perf_counter() - t0) * 1000.0
    snapshot = repository.get_latest_snapshot(db)
    freshness = _freshness_metadata(snapshot)

    topo_realtime.publish_topology_updated(
        projected_nodes=node_count,
        projected_edges=edge_count,
    )
    topo_realtime.publish_summary_patch(
        generated_at=freshness["generated_at"],
        projected_at=freshness["projected_at"],
        total_nodes=node_count,
        total_edges=edge_count,
        agent_count=metrics.get("by_type", {}).get("agent", 0),
        subnet_count=metrics.get("by_type", {}).get("subnet", 0),
        external_ip_count=metrics.get("by_type", {}).get("external_ip", 0),
        freshness_seconds=freshness["freshness_seconds"],
        stale=bool(freshness["stale"]),
        source_coverage=freshness["source_coverage"],
        truncation=freshness["truncation"],
    )
    topo_realtime.publish_topology_invalidate(
        reason="projection_updated",
        source="network_topology",
        projected_at=freshness["projected_at"],
        schedule_recalculation=False,
    )

    return TopologyRecalculateOut(
        accepted=True,
        projected_nodes=node_count,
        projected_edges=edge_count,
        duration_ms=round(duration_ms, 2),
        requested_at=requested_at,
        coverage=coverage,
    )


def _freshness_metadata(snapshot) -> dict[str, Any]:
    generated_at = datetime.now(_UTC)
    projected_at = _to_utc(snapshot.created_at) if snapshot else None
    freshness_seconds: int | None = None
    if projected_at is not None:
        freshness_seconds = max(0, int((generated_at - projected_at).total_seconds()))
    stale_after_seconds = _config_stale_after_minutes() * 60
    stale = projected_at is None or freshness_seconds is None or freshness_seconds > stale_after_seconds

    metrics = snapshot.metrics if snapshot and isinstance(snapshot.metrics, dict) else {}
    data_window = metrics.get("data_window") if isinstance(metrics.get("data_window"), dict) else None
    if data_window is None:
        data_window = _default_data_window(generated_at)

    source_coverage = metrics.get("source_coverage") if isinstance(metrics.get("source_coverage"), dict) else None
    if source_coverage is None:
        source_coverage = snapshot.coverage if snapshot and isinstance(snapshot.coverage, dict) else {}

    truncation = metrics.get("truncation") if isinstance(metrics.get("truncation"), dict) else {}

    return {
        "generated_at": generated_at,
        "projected_at": projected_at,
        "data_window": data_window,
        "freshness_seconds": freshness_seconds,
        "stale": bool(stale),
        "source_coverage": source_coverage,
        "truncation": truncation,
    }


def _default_data_window(now: datetime) -> dict[str, Any]:
    window = _config_window_minutes()
    start = now - timedelta(minutes=window)
    return {
        "window_minutes": int(window),
        "start_at": start.isoformat(),
        "end_at": now.isoformat(),
    }


def _build_snapshot_metrics(
    *,
    coverage: TopologyCoverageOut,
    projected_by: str,
    reason: str,
    requested_at: datetime,
    window_minutes: int,
    max_events_per_run: int,
) -> dict[str, Any]:
    now = datetime.now(_UTC)
    coverage_dict = _model_dict(coverage)
    warnings = [str(x) for x in coverage.warnings]
    ingest_pressure = _ingest_pressure_snapshot()
    source_coverage = {
        "projection": coverage_dict,
        "agents": {"projected": int(coverage.agents_projected)},
        "inventory": {"agents_with_inventory": int(coverage.agents_with_inventory)},
        "flows": {"edges_added": int(coverage.flow_edges_added), "window_minutes": int(window_minutes)},
        "alerts": {"edges_added": int(coverage.alert_edges_added), "window_minutes": int(window_minutes)},
        "exposure": {"edges_added": int(coverage.exposure_edges_added)},
        "ingest_pressure": ingest_pressure,
    }
    truncation = {
        "max_events_per_run": int(max_events_per_run),
        "warnings": warnings,
        "agents_truncated": "agent_limit_reached" in warnings,
        "inventory_truncated": "inventory_limit_reached" in warnings,
        "flows_truncated": "flow_edge_limit_reached" in warnings,
        "alerts_truncated": "alert_limit_reached" in warnings,
        "exposure_truncated": "exposure_limit_reached" in warnings,
        "sampled": bool((ingest_pressure or {}).get("sampled")),
    }
    return {
        "projected_by": str(projected_by or "worker"),
        "reason": str(reason or "worker"),
        "requested_at": requested_at.isoformat(),
        "data_window": {
            "window_minutes": int(window_minutes),
            "start_at": (now - timedelta(minutes=int(window_minutes))).isoformat(),
            "end_at": now.isoformat(),
        },
        "source_coverage": source_coverage,
        "truncation": truncation,
    }


def _model_dict(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _ingest_pressure_snapshot() -> dict[str, Any]:
    try:
        from app.features.ingest.control.service import get_storm_status

        raw = get_storm_status()
    except Exception:
        raw = None
    if not isinstance(raw, dict):
        return {"sampled": False, "phase": "unknown"}
    phase = str(raw.get("phase") or "ok")
    sample_hot = raw.get("sample_hot_percent")
    sample_warm = raw.get("sample_warm_percent")
    try:
        hot_i = int(sample_hot)
    except Exception:
        hot_i = 100
    sampled = bool(raw.get("active")) or phase not in {"ok", "normal"} or hot_i < 100
    return {
        "sampled": bool(sampled),
        "phase": phase,
        "reason": str(raw.get("reason") or "ok"),
        "backlog_events": int(raw.get("backlog_events") or 0),
        "backlog_messages": int(raw.get("backlog_messages") or 0),
        "sample_hot_percent": hot_i,
        "sample_warm_percent": int(sample_warm or 0),
    }


def _node_to_out(node: TopologyNodeModel) -> TopologyNodeOut:
    return TopologyNodeOut(
        node_key=node.node_key,
        node_type=node.node_type,
        agent_id=node.agent_id,
        label=node.label,
        ip=node.ip,
        cidr=node.cidr,
        port=node.port,
        protocol=node.protocol,
        severity=node.severity,
        risk_score=int(node.risk_score or 0),
        confidence=int(node.confidence or 0),
        is_stale=bool(node.is_stale),
        event_count=int(node.event_count or 0),
        alert_count=int(node.alert_count or 0),
        observation_count=int(node.observation_count or 0),
        first_seen_at=_to_utc(node.first_seen_at),
        last_seen_at=_to_utc(node.last_seen_at),
        updated_at=_to_utc(node.updated_at),
        metadata=_sanitize_public_json(node.extra_data or {}),
    )


def _edge_to_out(edge: TopologyEdgeModel) -> TopologyEdgeOut:
    return TopologyEdgeOut(
        edge_key=edge.edge_key,
        source_node_key=edge.source_node_key,
        target_node_key=edge.target_node_key,
        edge_type=edge.edge_type,
        agent_id=edge.agent_id,
        weight=float(edge.weight or 1.0),
        confidence=int(edge.confidence or 0),
        severity=edge.severity,
        port=edge.port,
        protocol=edge.protocol,
        event_count=int(edge.event_count or 0),
        alert_count=int(edge.alert_count or 0),
        first_seen_at=_to_utc(edge.first_seen_at),
        last_seen_at=_to_utc(edge.last_seen_at),
        updated_at=_to_utc(edge.updated_at),
        metadata=_sanitize_public_json(edge.extra_data or {}),
    )


def _obs_to_out(obs: TopologyObservationModel) -> TopologyObservationOut:
    raw_context = _sanitize_public_json(obs.raw_context or {})
    return TopologyObservationOut(
        id=int(obs.id),
        node_key=obs.node_key,
        edge_key=obs.edge_key,
        agent_id=obs.agent_id,
        source_type=obs.source_type,
        source_id=obs.source_id,
        observed_at=_to_utc(obs.observed_at),
        summary=obs.summary,
        confidence=_confidence_from_context(raw_context),
        raw_context=raw_context,
    )


def _subnet_node_to_out(node: TopologyNodeModel) -> TopologySubnetOut:
    return TopologySubnetOut(
        node_key=node.node_key,
        cidr=str(node.cidr or node.label),
        label=node.label,
        agent_id=node.agent_id,
        severity=node.severity,
        confidence=int(node.confidence or 0),
        first_seen_at=_to_utc(node.first_seen_at),
        last_seen_at=_to_utc(node.last_seen_at),
        metadata=_sanitize_public_json(node.extra_data or {}),
    )


def _evidence_meta(limit: int, total: int) -> TopologyEvidencePageMetaOut:
    return TopologyEvidencePageMetaOut(
        limit=int(limit),
        total=max(0, int(total or 0)),
        omitted=max(0, int(total or 0) - int(limit)),
    )


def _evidence_source_to_out(row: tuple[str, int, datetime | None]) -> TopologyEvidenceSourceOut:
    source_type, count, latest = row
    return TopologyEvidenceSourceOut(
        source_type=str(source_type or "unknown"),
        count=int(count or 0),
        latest_observed_at=_to_utc(latest) if latest else None,
    )


def _flow_to_out(flow: Any) -> TopologyRelatedFlowOut:
    return TopologyRelatedFlowOut(
        id=int(getattr(flow, "id", 0) or 0),
        timestamp=_to_utc(getattr(flow, "timestamp", None)),
        agent_id=str(getattr(flow, "agent_id", "") or ""),
        event_type=str(getattr(flow, "event_type", "") or "event"),
        src_ip=getattr(flow, "src_ip", None),
        dst_ip=getattr(flow, "dst_ip", None),
        src_port=getattr(flow, "src_port", None),
        dst_port=getattr(flow, "dst_port", None),
        protocol=getattr(flow, "proto", None),
        bytes=getattr(flow, "bytes", None),
        app_proto=getattr(flow, "app_proto", None),
    )


def _alert_to_out(alert: Any) -> TopologyRelatedAlertOut:
    return TopologyRelatedAlertOut(
        id=int(getattr(alert, "id", 0) or 0),
        created_at=_to_utc(getattr(alert, "created_at", None)),
        rule_id=str(getattr(alert, "rule_id", "") or ""),
        severity=str(getattr(alert, "severity", "unknown") or "unknown"),
        status=str(getattr(alert, "status", "open") or "open"),
        confidence=int(getattr(alert, "confidence", 0) or 0),
        description=str(getattr(alert, "description", "") or ""),
        src_ip=getattr(alert, "src_ip", None),
        dst_ip=getattr(alert, "dst_ip", None),
        dst_port=getattr(alert, "dst_port", None),
    )


def _exposure_finding_to_out(finding: Any) -> TopologyRelatedExposureFindingOut:
    return TopologyRelatedExposureFindingOut(
        finding_key=str(getattr(finding, "finding_key", "") or ""),
        asset_key=str(getattr(finding, "asset_key", "") or ""),
        agent_id=getattr(finding, "agent_id", None),
        finding_type=str(getattr(finding, "finding_type", "") or "finding"),
        severity=str(getattr(finding, "severity", "unknown") or "unknown"),
        status=str(getattr(finding, "status", "open") or "open"),
        confidence=int(getattr(finding, "confidence", 0) or 0),
        title=str(getattr(finding, "title", "") or ""),
        summary=str(getattr(finding, "summary", "") or ""),
        last_seen_at=_to_utc(getattr(finding, "last_seen_at", None)),
    )


def _attack_chain_case_to_out(case: Any) -> TopologyRelatedAttackChainCaseOut:
    return TopologyRelatedAttackChainCaseOut(
        id=int(getattr(case, "id", 0) or 0),
        agent_id=str(getattr(case, "agent_id", "") or ""),
        suspect_ip=getattr(case, "suspect_ip", None),
        status=str(getattr(case, "status", "open") or "open"),
        score=int(getattr(case, "score", 0) or 0),
        max_stage=str(getattr(case, "max_stage", "initial_access") or "initial_access"),
        step_count=int(getattr(case, "step_count", 0) or 0),
        first_seen_at=_to_utc(getattr(case, "first_seen_at", None)),
        last_seen_at=_to_utc(getattr(case, "last_seen_at", None)),
    )


def _app_protocols_for_edge(edge: TopologyEdgeModel, flows: list[Any], aggregate_protocols: list[str] | None = None) -> list[str]:
    protocols: list[str] = []
    metadata = edge.extra_data if isinstance(edge.extra_data, dict) else {}
    raw = metadata.get("application_protocols") or metadata.get("app_protocols")
    if isinstance(raw, list):
        protocols.extend(str(item).strip().lower() for item in raw if str(item or "").strip())
    elif isinstance(raw, str) and raw.strip():
        protocols.append(raw.strip().lower())
    for flow in flows:
        app_proto = str(getattr(flow, "app_proto", "") or "").strip().lower()
        if app_proto:
            protocols.append(app_proto)
    for app_proto in aggregate_protocols or []:
        proto = str(app_proto or "").strip().lower()
        if proto:
            protocols.append(proto)
    out: list[str] = []
    seen: set[str] = set()
    for proto in protocols:
        if proto in seen:
            continue
        seen.add(proto)
        out.append(proto)
    return out[:12]


def _confidence_from_context(context: dict[str, Any]) -> int:
    raw = context.get("confidence")
    try:
        value = int(raw)
    except Exception:
        return 50
    return max(0, min(100, value))


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _sanitize_public_json(value: Any, *, depth: int = 0) -> Any:
    if depth >= 6:
        return "[truncated]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            if _is_sensitive_key(text_key):
                continue
            out[text_key] = _sanitize_public_json(item, depth=depth + 1)
        return out
    if isinstance(value, list):
        return [_sanitize_public_json(item, depth=depth + 1) for item in value[:50]]
    if isinstance(value, tuple):
        return [_sanitize_public_json(item, depth=depth + 1) for item in value[:50]]
    if isinstance(value, str) and len(value) > 2048:
        return value[:2048] + "...[truncated]"
    return value


def _to_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(_UTC)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=_UTC)
    return dt
