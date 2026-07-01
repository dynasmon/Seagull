from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.api.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.config import settings
from app.core.observability import observe_hist
from app.features.agents import public as agents_public
from app.features.auth.session import PortalPrincipal
from app.features.network_topology import realtime as topo_realtime
from app.features.network_topology import repository
from app.features.network_topology.domain.config import (
    _config_max_events_per_run,
    _config_stale_after_minutes,
    _config_window_minutes,
    _env_int,
)
from app.features.network_topology.domain.freshness import (
    _build_snapshot_metrics,
    _default_data_window,
    _freshness_metadata,
    _ingest_pressure_snapshot,
    _model_dict,
)
from app.features.network_topology.domain.insights import _compute_insights, _compute_visibility
from app.features.network_topology.domain.serializers import (
    _alert_to_out,
    _app_protocols_for_edge,
    _attack_chain_case_to_out,
    _confidence_from_context,
    _edge_to_out,
    _evidence_meta,
    _evidence_source_to_out,
    _exposure_finding_to_out,
    _flow_to_out,
    _is_sensitive_key,
    _node_to_out,
    _obs_to_out,
    _sanitize_public_json,
    _subnet_node_to_out,
    _to_utc,
)
from app.features.network_topology.domain.subnet_details import (
    _dedupe_sorted_nodes,
    _earliest_dt,
    _edge_has_gateway_metadata,
    _highest_node_severity,
    _latest_dt,
    _node_ip_scope,
    _severity_weight,
    _subnet_exposed_or_public_nodes,
    _subnet_external_destinations,
    _subnet_gateway_candidates,
    _subnet_listening_services,
    _topology_edge_sort_key,
    _topology_node_sort_key,
)
from app.features.network_topology.grouping import (
    apply_exclusive_focus,
    build_groups,
    compute_facets,
)
from app.features.network_topology.projector import project_topology
from app.features.network_topology.schemas import (
    TopologyCoverageOut,
    TopologyEdgeDetailOut,
    TopologyFacetsOut,
    TopologyGraphHealthOut,
    TopologyGraphOut,
    TopologyGraphQuery,
    TopologyGroupDetailOut,
    TopologyGroupEdgeOut,
    TopologyGroupOut,
    TopologyNodeDetailOut,
    TopologyNodeTypeStat,
    TopologyObservationOut,
    TopologyObservationQuery,
    TopologyRecalculateOut,
    TopologySubnetDetailOut,
    TopologySubnetDetailTruncationOut,
    TopologySubnetOut,
    TopologySubnetQuery,
    TopologySummaryOut,
)
from app.features.ueba import repository as ueba_repository
from app.shared.analytics import AnalyticalReadModel, register_read_model, serve_read_model
from app.shared.schemas import CursorPage

_UTC = timezone.utc
_DETAIL_OBSERVATION_LIMIT = 20
_DETAIL_EDGE_LIMIT = 50
_DETAIL_RELATED_LIMIT = 10
_GROUP_DETAIL_MEMBER_LIMIT = 30
_GROUP_DETAIL_SERVICES_LIMIT = 20
_GROUP_DETAIL_EDGE_LIMIT = 50
_SUBNET_DETAIL_MEMBER_LIMIT = 30
_SUBNET_DETAIL_GATEWAY_LIMIT = 10
_SUBNET_DETAIL_EXPOSED_LIMIT = 20
_SUBNET_DETAIL_SERVICE_LIMIT = 20
_SUBNET_DETAIL_DESTINATION_LIMIT = 20
_SUBNET_DETAIL_EDGE_LIMIT = 50
_SUBNET_DETAIL_EDGE_SCAN_LIMIT = 200
_SUBNET_DETAIL_OBSERVATION_LIMIT = 20

__all__ = [
    "_alert_to_out",
    "_app_protocols_for_edge",
    "_attack_chain_case_to_out",
    "_build_snapshot_metrics",
    "_compute_insights",
    "_compute_visibility",
    "_confidence_from_context",
    "_config_max_events_per_run",
    "_config_stale_after_minutes",
    "_config_window_minutes",
    "_dedupe_sorted_nodes",
    "_default_data_window",
    "_earliest_dt",
    "_edge_has_gateway_metadata",
    "_edge_to_out",
    "_env_int",
    "_evidence_meta",
    "_evidence_source_to_out",
    "_exposure_finding_to_out",
    "_flow_to_out",
    "_freshness_metadata",
    "_highest_node_severity",
    "_ingest_pressure_snapshot",
    "_is_sensitive_key",
    "_latest_dt",
    "_load_agent_labels",
    "_model_dict",
    "_node_ip_scope",
    "_node_to_out",
    "_obs_to_out",
    "_sanitize_public_json",
    "_severity_weight",
    "_subnet_exposed_or_public_nodes",
    "_subnet_external_destinations",
    "_subnet_gateway_candidates",
    "_subnet_listening_services",
    "_subnet_node_to_out",
    "_to_utc",
    "_topology_edge_sort_key",
    "_topology_node_sort_key",
    "get_edge_detail",
    "get_graph",
    "get_graph_async",
    "get_group_detail",
    "get_node_detail",
    "get_subnet_detail",
    "get_summary",
    "get_summary_async",
    "list_observations",
    "list_subnets",
    "request_recalculate",
    "run_recalculation",
]


def _load_agent_labels(db: Session) -> dict[str, str]:
    return {a.agent_id: (a.display_name or a.agent_id) for a in agents_public.list_all_agents(db)}


def _peer_deviation_by_agent(db: Session) -> dict[str, Any]:
    if not hasattr(db, "get_bind"):
        return {}
    try:
        bind = db.get_bind()
        if bind is None or not inspect(bind).has_table("ueba_findings"):
            return {}
        findings = ueba_repository.list_high_peer_deviation_findings(db, min_risk_score=70)
    except SQLAlchemyError:
        return {}
    out: dict[str, Any] = {}
    for finding in findings:
        agent_id = str(getattr(finding, "agent_id", "") or "")
        if not agent_id:
            continue
        current = out.get(agent_id)
        if current is None or int(getattr(finding, "risk_score", 0) or 0) > int(getattr(current, "risk_score", 0) or 0):
            out[agent_id] = finding
    return out


def _node_to_out_with_peer_deviation(node: Any, peer_deviation_by_agent: dict[str, Any]) -> Any:
    out = _node_to_out(node)
    if str(out.node_type or "").lower() != "agent" or not out.agent_id:
        return out
    finding = peer_deviation_by_agent.get(str(out.agent_id))
    if finding is None:
        return out
    explanation = getattr(finding, "explanation", None) if isinstance(getattr(finding, "explanation", None), dict) else {}
    metadata = dict(out.metadata or {})
    metadata["peer_group_deviation"] = {
        "finding_id": int(getattr(finding, "id", 0) or 0),
        "risk_score": int(getattr(finding, "risk_score", 0) or 0),
        "severity": str(getattr(finding, "severity", "high") or "high"),
        "mahalanobis_distance": explanation.get("mahalanobis_distance"),
        "threshold_distance": explanation.get("threshold_distance"),
        "group_id": explanation.get("group_id"),
        "last_seen_at": _to_utc(getattr(finding, "last_seen_at", None)).isoformat(),
    }
    peer_risk = int(getattr(finding, "risk_score", 0) or 0)
    peer_severity = str(getattr(finding, "severity", "high") or "high")
    severity = peer_severity if _severity_weight(peer_severity) > _severity_weight(out.severity) else out.severity
    return out.model_copy(
        update={
            "metadata": metadata,
            "risk_score": max(int(out.risk_score or 0), peer_risk),
            "severity": severity,
        }
    )


def get_summary(db: Session) -> TopologySummaryOut:
    metrics = repository.topology_summary_metrics(db)
    by_type: dict[str, int] = metrics.get("by_type", {})
    snapshot = repository.get_latest_snapshot(db)
    last_projected_at = snapshot.created_at if snapshot else None
    freshness = _freshness_metadata(snapshot)

    window_minutes = _config_window_minutes()
    since = datetime.now(_UTC) - timedelta(minutes=window_minutes)
    insight_metrics = repository.topology_insight_metrics(db, since=since)

    snapshot_coverage: dict[str, Any] = {}
    if snapshot and isinstance(snapshot.coverage, dict):
        snapshot_coverage = snapshot.coverage
    if snapshot and isinstance(snapshot.metrics, dict):
        pass

    insights = _compute_insights(insight_metrics, window_minutes=window_minutes)
    visibility = _compute_visibility(
        insight_metrics=insight_metrics,
        coverage=snapshot_coverage,
        alert_edge_count=metrics["alert_edge_count"],
        exposure_edge_count=metrics["exposure_edge_count"],
    )

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
        insights=insights,
        visibility=visibility,
        last_projected_at=last_projected_at,
        **freshness,
    )


def _topology_summary_cache_key(params: dict) -> str:
    return "seagull:network_topology:summary:v1"


def _resolve_topology_summary_blocking() -> TopologySummaryOut:
    from app.core.db import SessionLocal

    db = SessionLocal()
    try:
        return get_summary(db)
    finally:
        db.close()


async def _compute_topology_summary(params: dict) -> dict:
    payload = await asyncio.to_thread(_resolve_topology_summary_blocking)
    return payload.model_dump(mode="json")


TOPOLOGY_SUMMARY_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="network_topology_summary",
        schema_version=1,
        fresh_s=int(getattr(settings, "SEAGULL_NETWORK_TOPOLOGY_SUMMARY_FRESH_SECONDS", 60) or 60),
        stale_s=int(getattr(settings, "SEAGULL_NETWORK_TOPOLOGY_SUMMARY_STALE_SECONDS", 600) or 600),
        key_builder=_topology_summary_cache_key,
        compute=_compute_topology_summary,
    )
)


async def get_summary_async() -> tuple[dict, str, str]:
    started = time.perf_counter()
    payload, etag, outcome = await serve_read_model(TOPOLOGY_SUMMARY_READ_MODEL, {})
    payload = dict(payload)
    meta = dict(payload.get("meta") or {})
    meta["cache_hit"] = outcome != "miss"
    meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    payload["meta"] = meta
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/network-topology/summary",
        source=str(meta.get("source") or "compute"),
    )
    return payload, etag, outcome

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

    should_group = bool(params.view_mode == "location" or params.group_by)
    group_strategy = str(params.group_by or "auto")
    agent_labels = _load_agent_labels(db) if nodes and (should_group or params.focused_group_key) else {}

    raw_groups: list[dict[str, Any]] = []
    raw_group_edges: list[dict[str, Any]] = []
    if should_group or params.focused_group_key:
        raw_groups, raw_group_edges = build_groups(nodes, edges, strategy=group_strategy, agent_labels=agent_labels)

    focus_applied = False
    if params.focused_group_key and params.exclusive_focus:
        nodes, edges, focus_applied = apply_exclusive_focus(
            nodes,
            edges,
            focused_group_key=params.focused_group_key,
            groups=raw_groups,
        )
        if focus_applied:
            raw_groups, raw_group_edges = build_groups(nodes, edges, strategy=group_strategy, agent_labels=agent_labels)

    facets_data = compute_facets(nodes, edges, raw_groups)

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
    if params.focused_group_key:
        graph_truncation["focused_group_key"] = params.focused_group_key
        graph_truncation["exclusive_focus_applied"] = focus_applied

    graph_freshness = dict(freshness)
    graph_freshness["truncation"] = graph_truncation

    groups_out: list[TopologyGroupOut] | None = None
    group_edges_out: list[TopologyGroupEdgeOut] | None = None
    if should_group:
        groups_out = [TopologyGroupOut(**g) for g in raw_groups]
        group_edges_out = [TopologyGroupEdgeOut(**ge) for ge in raw_group_edges]

    peer_deviation_by_agent = _peer_deviation_by_agent(db)

    return TopologyGraphOut(
        nodes=[_node_to_out_with_peer_deviation(n, peer_deviation_by_agent) for n in nodes],
        edges=[_edge_to_out(e) for e in edges],
        groups=groups_out,
        group_edges=group_edges_out,
        facets=TopologyFacetsOut(**facets_data),
        group_strategy=group_strategy if should_group else None,
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


def _topology_text_cache_part(value: Any) -> str:
    return str(value or "").strip() or "*"


def _topology_dt_cache_part(value: datetime | None) -> str:
    return value.isoformat() if value is not None else "*"


def _topology_graph_cache_key(params: dict) -> str:
    return (
        "seagull:network_topology:graph:v1:"
        f"a={_topology_text_cache_part(params.get('agent_id'))}:"
        f"vm={_topology_text_cache_part(params.get('view_mode'))}:"
        f"gb={_topology_text_cache_part(params.get('group_by'))}:"
        f"mc={int(params['min_confidence'])}:"
        f"fg={_topology_text_cache_part(params.get('focused_group_key'))}:"
        f"xf={1 if params.get('exclusive_focus') else 0}:"
        f"mn={int(params['max_nodes'])}:me={int(params['max_edges'])}:"
        f"ip={_topology_text_cache_part(params.get('ip_scope'))}:"
        f"s={_topology_dt_cache_part(params.get('since'))}:u={_topology_dt_cache_part(params.get('until'))}"
    )


def _topology_graph_params(params: TopologyGraphQuery) -> dict[str, Any]:
    return {
        "max_nodes": int(params.max_nodes),
        "max_edges": int(params.max_edges),
        "min_confidence": int(params.min_confidence),
        "agent_id": params.agent_id or None,
        "node_types": list(params.node_types or []),
        "edge_types": list(params.edge_types or []),
        "ip_scope": params.ip_scope or None,
        "since": params.since,
        "until": params.until,
        "include_stale": bool(params.include_stale),
        "view_mode": params.view_mode or None,
        "group_by": params.group_by or None,
        "focused_group_key": params.focused_group_key or None,
        "exclusive_focus": bool(params.exclusive_focus),
    }


def _topology_graph_bypass_cache(params: TopologyGraphQuery) -> bool:
    return bool(params.include_stale or params.node_types or params.edge_types)


def _resolve_topology_graph_blocking(*, params: TopologyGraphQuery) -> TopologyGraphOut:
    from app.core.db import SessionLocal

    db = SessionLocal()
    try:
        return get_graph(db, params)
    finally:
        db.close()


async def _compute_topology_graph(params: dict) -> dict:
    query = TopologyGraphQuery(**params)
    payload = await asyncio.to_thread(_resolve_topology_graph_blocking, params=query)
    return payload.model_dump(mode="json")


TOPOLOGY_GRAPH_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="network_topology_graph",
        schema_version=1,
        fresh_s=int(getattr(settings, "SEAGULL_NETWORK_TOPOLOGY_GRAPH_FRESH_SECONDS", 30) or 30),
        stale_s=int(getattr(settings, "SEAGULL_NETWORK_TOPOLOGY_GRAPH_STALE_SECONDS", 300) or 300),
        key_builder=_topology_graph_cache_key,
        compute=_compute_topology_graph,
    )
)


async def get_graph_async(params: TopologyGraphQuery) -> tuple[dict, str, str]:
    started = time.perf_counter()
    if _topology_graph_bypass_cache(params):
        payload_model = await asyncio.to_thread(_resolve_topology_graph_blocking, params=params)
        payload = payload_model.model_dump(mode="json")
        meta = dict(payload.get("meta") or {})
        meta["cache_hit"] = False
        meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
        payload["meta"] = meta
        observe_hist(
            "api_route_latency_seconds",
            time.perf_counter() - started,
            route="/network-topology/graph",
            source="bypass",
        )
        return payload, "", "bypass"

    payload, etag, outcome = await serve_read_model(TOPOLOGY_GRAPH_READ_MODEL, _topology_graph_params(params))
    payload = dict(payload)
    meta = dict(payload.get("meta") or {})
    meta["cache_hit"] = outcome != "miss"
    meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    payload["meta"] = meta
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/network-topology/graph",
        source=str(meta.get("source") or "compute"),
    )
    return payload, etag, outcome


def get_group_detail(db: Session, group_key: str, params: TopologyGraphQuery) -> TopologyGroupDetailOut:
    node_limit = min(int(params.max_nodes), topo_realtime.graph_nodes_hard_limit())
    edge_limit = min(int(params.max_edges), topo_realtime.graph_edges_hard_limit())

    nodes = repository.list_nodes(
        db,
        agent_id=params.agent_id,
        min_confidence=params.min_confidence,
        include_stale=params.include_stale,
        since=params.since,
        until=params.until,
        limit=node_limit,
    )
    edges = repository.list_edges(
        db,
        agent_id=params.agent_id,
        min_confidence=params.min_confidence,
        since=params.since,
        until=params.until,
        limit=edge_limit,
    )

    strategy = str(params.group_by or "auto")
    agent_labels = _load_agent_labels(db) if nodes else {}
    raw_groups, _ = build_groups(nodes, edges, strategy=strategy, agent_labels=agent_labels)

    group = next((g for g in raw_groups if g["group_key"] == group_key), None)
    if not group:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "group_not_found",
                "message": "Group not found",
                "context": {"group_key": group_key},
            },
        )

    member_keys: set[str] = set(group["child_node_keys"])
    member_nodes = [n for n in nodes if n.node_key in member_keys]

    def _sort_key(n: Any) -> tuple[int, int, int, int]:
        sev_w = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}.get(
            str(n.severity or "").lower(), 0
        )
        return (-sev_w, -int(n.risk_score or 0), -int(n.alert_count or 0), -int(n.event_count or 0))

    member_nodes.sort(key=_sort_key)
    top_members = member_nodes[:_GROUP_DETAIL_MEMBER_LIMIT]
    top_services = [n for n in member_nodes if str(n.node_type or "") == "service"][:_GROUP_DETAIL_SERVICES_LIMIT]

    neighbor_keys: set[str] = set()
    candidate_edges: list[Any] = []
    for edge in edges:
        src_in = edge.source_node_key in member_keys
        tgt_in = edge.target_node_key in member_keys
        if src_in:
            neighbor_keys.add(edge.target_node_key)
        if tgt_in:
            neighbor_keys.add(edge.source_node_key)
        if src_in or tgt_in:
            candidate_edges.append(edge)
    neighbor_keys -= member_keys
    visible_keys = member_keys | neighbor_keys

    related_edges = [
        e for e in candidate_edges
        if e.source_node_key in visible_keys and e.target_node_key in visible_keys
    ][:_GROUP_DETAIL_EDGE_LIMIT]

    return TopologyGroupDetailOut(
        group_key=group["group_key"],
        group_type=group["group_type"],
        label=group["label"],
        node_count=group["node_count"],
        edge_count=group["edge_count"],
        alert_count=group["alert_count"],
        highest_severity=group["highest_severity"],
        risk_score=group["risk_score"],
        confidence=group["confidence"],
        is_stale=group["is_stale"],
        first_seen=group["first_seen"],
        last_seen=group["last_seen"],
        top_member_nodes=[_node_to_out(n) for n in top_members],
        top_services=[_node_to_out(n) for n in top_services],
        related_edges=[_edge_to_out(e) for e in related_edges],
        child_node_keys_truncated=group["child_node_keys_truncated"],
        metadata=group["metadata"],
    )

def get_subnet_detail(db: Session, cidr: str) -> TopologySubnetDetailOut:
    subnet = repository.get_subnet_node_by_cidr(db, cidr=cidr)
    if subnet is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "subnet_not_found",
                "message": "Subnet not found",
                "context": {"cidr": cidr},
            },
        )

    member_total = repository.count_subnet_member_nodes(db, subnet_node_key=subnet.node_key, cidr=cidr)
    member_metrics = repository.subnet_member_metrics(db, subnet_node_key=subnet.node_key, cidr=cidr)
    member_nodes = repository.list_subnet_member_nodes(
        db,
        subnet_node_key=subnet.node_key,
        cidr=cidr,
        limit=_SUBNET_DETAIL_MEMBER_LIMIT,
    )
    member_nodes = sorted(member_nodes, key=_topology_node_sort_key)[:_SUBNET_DETAIL_MEMBER_LIMIT]

    related_edge_total = repository.count_edges_for_subnet(db, subnet_node_key=subnet.node_key, cidr=cidr)
    edge_scan = repository.list_edges_for_subnet(
        db,
        subnet_node_key=subnet.node_key,
        cidr=cidr,
        limit=_SUBNET_DETAIL_EDGE_SCAN_LIMIT,
    )

    member_keys = {node.node_key for node in member_nodes}
    member_keys.update(
        edge.source_node_key
        for edge in edge_scan
        if str(edge.edge_type or "") == "member_of_subnet" and edge.target_node_key == subnet.node_key
    )
    relevant_edges = sorted(edge_scan, key=_topology_edge_sort_key)

    related_node_keys = {subnet.node_key, *member_keys}
    for edge in relevant_edges:
        related_node_keys.add(edge.source_node_key)
        related_node_keys.add(edge.target_node_key)
    related_nodes = repository.list_nodes_by_keys(db, node_keys=sorted(related_node_keys))
    node_by_key = {node.node_key: node for node in related_nodes}
    for node in member_nodes:
        node_by_key[node.node_key] = node
    node_by_key[subnet.node_key] = subnet

    gateway_candidates = _subnet_gateway_candidates(
        member_nodes=member_nodes,
        related_edges=relevant_edges,
        node_by_key=node_by_key,
        member_keys=member_keys,
    )
    exposed_or_public_nodes = _subnet_exposed_or_public_nodes(member_nodes)
    listening_services = _subnet_listening_services(
        member_nodes=member_nodes,
        related_edges=relevant_edges,
        node_by_key=node_by_key,
        member_keys=member_keys,
    )
    external_destinations = _subnet_external_destinations(
        related_edges=relevant_edges,
        node_by_key=node_by_key,
        member_keys=member_keys,
    )

    observation_total = repository.count_observations_for_subnet(
        db,
        subnet_node_key=subnet.node_key,
        cidr=cidr,
    )
    recent_observations = repository.list_observations_for_subnet(
        db,
        subnet_node_key=subnet.node_key,
        cidr=cidr,
        limit=_SUBNET_DETAIL_OBSERVATION_LIMIT,
    )[:_SUBNET_DETAIL_OBSERVATION_LIMIT]

    metadata = subnet.extra_data if isinstance(subnet.extra_data, dict) else {}
    highest_severity = _highest_node_severity(member_nodes) if member_nodes else str(subnet.severity or "unknown")
    first_seen = _earliest_dt(member_metrics.get("first_seen"), subnet.first_seen_at)
    last_seen = _latest_dt(member_metrics.get("last_seen"), subnet.last_seen_at)

    return TopologySubnetDetailOut(
        cidr=str(subnet.cidr or cidr),
        label=str(subnet.label or subnet.cidr or cidr),
        ip_scope=str(metadata.get("ip_scope") or "").strip() or None,
        node_count=int(member_metrics.get("node_count", member_total) or 0),
        active_node_count=int(member_metrics.get("active_node_count", 0) or 0),
        stale_node_count=int(member_metrics.get("stale_node_count", 0) or 0),
        alert_count=int(member_metrics.get("alert_count", 0) or 0),
        highest_severity=highest_severity,
        risk_score=member_metrics.get("risk_score"),
        confidence=member_metrics.get("confidence") if member_metrics.get("confidence") is not None else int(subnet.confidence or 0),
        first_seen=_to_utc(first_seen) if first_seen else None,
        last_seen=_to_utc(last_seen) if last_seen else None,
        gateway_candidates=[_node_to_out(node) for node in gateway_candidates[:_SUBNET_DETAIL_GATEWAY_LIMIT]],
        member_nodes=[_node_to_out(node) for node in member_nodes],
        exposed_or_public_nodes=[_node_to_out(node) for node in exposed_or_public_nodes[:_SUBNET_DETAIL_EXPOSED_LIMIT]],
        listening_services=[_node_to_out(node) for node in listening_services[:_SUBNET_DETAIL_SERVICE_LIMIT]],
        external_destinations=[_node_to_out(node) for node in external_destinations[:_SUBNET_DETAIL_DESTINATION_LIMIT]],
        related_edges=[_edge_to_out(edge) for edge in relevant_edges[:_SUBNET_DETAIL_EDGE_LIMIT]],
        recent_observations=[_obs_to_out(obs) for obs in recent_observations],
        metadata=_sanitize_public_json(metadata),
        truncation=TopologySubnetDetailTruncationOut(
            member_nodes=_evidence_meta(_SUBNET_DETAIL_MEMBER_LIMIT, member_total),
            gateway_candidates=_evidence_meta(_SUBNET_DETAIL_GATEWAY_LIMIT, len(gateway_candidates)),
            exposed_or_public_nodes=_evidence_meta(_SUBNET_DETAIL_EXPOSED_LIMIT, len(exposed_or_public_nodes)),
            listening_services=_evidence_meta(_SUBNET_DETAIL_SERVICE_LIMIT, len(listening_services)),
            external_destinations=_evidence_meta(_SUBNET_DETAIL_DESTINATION_LIMIT, len(external_destinations)),
            related_edges=_evidence_meta(_SUBNET_DETAIL_EDGE_LIMIT, related_edge_total),
            recent_observations=_evidence_meta(_SUBNET_DETAIL_OBSERVATION_LIMIT, observation_total),
        ),
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
