from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.api.pagination import decode_cursor, make_cursor_ts_id, parse_cursor_ts_id
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
    TopologyGraphHealthOut,
    TopologyGraphOut,
    TopologyGraphQuery,
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


def get_summary(db: Session) -> TopologySummaryOut:
    metrics = repository.topology_summary_metrics(db)
    by_type: dict[str, int] = metrics.get("by_type", {})
    snapshot = repository.get_latest_snapshot(db)
    last_projected_at = snapshot.created_at if snapshot else None

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
        ),
    )


def get_node_detail(db: Session, node_key: str) -> TopologyNodeDetailOut:
    node = repository.get_node(db, node_key)
    if node is None:
        raise HTTPException(status_code=404, detail={"code": "node_not_found", "message": "Node not found", "context": {"node_key": node_key}})

    observations = repository.list_observations_for_node(db, node_key=node_key, limit=20)
    edges = repository.list_edges_for_node(db, node_key=node_key, limit=50)
    connected_keys = repository.list_connected_node_keys(db, node_key=node_key, limit=50)
    connected_nodes = repository.list_nodes_by_keys(db, node_keys=connected_keys)

    return TopologyNodeDetailOut(
        node=_node_to_out(node),
        observations=[_obs_to_out(o) for o in observations],
        connected_nodes=[_node_to_out(n) for n in connected_nodes],
        edges=[_edge_to_out(e) for e in edges],
    )


def get_edge_detail(db: Session, edge_key: str) -> TopologyEdgeDetailOut:
    edge = repository.get_edge(db, edge_key)
    if edge is None:
        raise HTTPException(status_code=404, detail={"code": "edge_not_found", "message": "Edge not found", "context": {"edge_key": edge_key}})

    observations = repository.list_observations_for_node(db, node_key=edge.source_node_key, limit=10)
    src_node = repository.get_node(db, edge.source_node_key)
    dst_node = repository.get_node(db, edge.target_node_key)

    return TopologyEdgeDetailOut(
        edge=_edge_to_out(edge),
        observations=[_obs_to_out(o) for o in observations],
        source_node=_node_to_out(src_node) if src_node else None,
        target_node=_node_to_out(dst_node) if dst_node else None,
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
    t0 = time.perf_counter()

    coverage = project_topology(db)
    db.flush()

    metrics = repository.topology_summary_metrics(db)
    node_count = metrics["total_nodes"]
    edge_count = metrics["total_edges"]

    repository.upsert_snapshot(
        db,
        snapshot_key="latest",
        node_count=node_count,
        edge_count=edge_count,
        agent_count=metrics.get("by_type", {}).get("agent", 0),
        subnet_count=metrics.get("by_type", {}).get("subnet", 0),
        external_ip_count=metrics.get("by_type", {}).get("external_ip", 0),
        coverage=coverage.dict(),
        metrics={"projected_by": admin.username},
    )
    db.commit()

    duration_ms = (time.perf_counter() - t0) * 1000.0

    topo_realtime.publish_topology_updated(
        projected_nodes=node_count,
        projected_edges=edge_count,
    )

    return TopologyRecalculateOut(
        accepted=True,
        projected_nodes=node_count,
        projected_edges=edge_count,
        duration_ms=round(duration_ms, 2),
        requested_at=requested_at,
        coverage=coverage,
    )


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
        metadata=dict(node.extra_data or {}),
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
        metadata=dict(edge.extra_data or {}),
    )


def _obs_to_out(obs: TopologyObservationModel) -> TopologyObservationOut:
    return TopologyObservationOut(
        id=int(obs.id),
        node_key=obs.node_key,
        edge_key=obs.edge_key,
        agent_id=obs.agent_id,
        source_type=obs.source_type,
        source_id=obs.source_id,
        observed_at=_to_utc(obs.observed_at),
        summary=obs.summary,
        raw_context=dict(obs.raw_context or {}),
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
        metadata=dict(node.extra_data or {}),
    )


def _to_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(_UTC)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=_UTC)
    return dt
