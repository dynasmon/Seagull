from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.features.network_topology.models import (
    TopologyEdgeModel,
    TopologyNodeModel,
    TopologyObservationModel,
    TopologySnapshotModel,
)

_MAX_PAGE = 200
_MAX_GRAPH_FETCH = 2000


def upsert_node(
    db: Session,
    *,
    node_key: str,
    node_type: str,
    label: str,
    agent_id: str | None,
    ip: str | None,
    cidr: str | None,
    port: int | None,
    protocol: str | None,
    severity: str,
    risk_score: int,
    confidence: int,
    first_seen_at: datetime,
    last_seen_at: datetime,
    extra_data: dict[str, Any],
) -> TopologyNodeModel:
    now = datetime.now(timezone.utc)
    stmt = (
        pg_insert(TopologyNodeModel)
        .values(
            node_key=node_key,
            node_type=node_type,
            label=label,
            agent_id=agent_id,
            ip=ip,
            cidr=cidr,
            port=port,
            protocol=protocol,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            is_stale=0,
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
            updated_at=now,
            extra_data=extra_data,
        )
        .on_conflict_do_update(
            index_elements=["node_key"],
            set_={
                "label": label,
                "ip": ip,
                "cidr": cidr,
                "severity": severity,
                "risk_score": risk_score,
                "confidence": confidence,
                "is_stale": 0,
                "last_seen_at": last_seen_at,
                "updated_at": now,
                "extra_data": extra_data,
            },
        )
        .returning(TopologyNodeModel)
    )
    return db.execute(stmt).scalars().one()


def upsert_edge(
    db: Session,
    *,
    edge_key: str,
    source_node_key: str,
    target_node_key: str,
    edge_type: str,
    agent_id: str | None,
    weight: float,
    confidence: int,
    severity: str,
    port: int | None,
    protocol: str | None,
    first_seen_at: datetime,
    last_seen_at: datetime,
    extra_data: dict[str, Any],
) -> TopologyEdgeModel:
    now = datetime.now(timezone.utc)
    stmt = (
        pg_insert(TopologyEdgeModel)
        .values(
            edge_key=edge_key,
            source_node_key=source_node_key,
            target_node_key=target_node_key,
            edge_type=edge_type,
            agent_id=agent_id,
            weight=weight,
            confidence=confidence,
            severity=severity,
            port=port,
            protocol=protocol,
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
            updated_at=now,
            extra_data=extra_data,
        )
        .on_conflict_do_update(
            index_elements=["edge_key"],
            set_={
                "weight": weight,
                "confidence": confidence,
                "severity": severity,
                "last_seen_at": last_seen_at,
                "updated_at": now,
                "extra_data": extra_data,
            },
        )
        .returning(TopologyEdgeModel)
    )
    return db.execute(stmt).scalars().one()


def insert_observation(
    db: Session,
    *,
    node_key: str,
    edge_key: str | None,
    agent_id: str | None,
    source_type: str,
    source_id: str | None,
    observed_at: datetime,
    summary: str,
    raw_context: dict[str, Any],
) -> TopologyObservationModel:
    row = TopologyObservationModel(
        node_key=node_key,
        edge_key=edge_key,
        agent_id=agent_id,
        source_type=source_type,
        source_id=source_id,
        observed_at=observed_at,
        summary=summary,
        raw_context=raw_context,
    )
    db.add(row)
    return row


def upsert_snapshot(
    db: Session,
    *,
    snapshot_key: str,
    node_count: int,
    edge_count: int,
    agent_count: int,
    subnet_count: int,
    external_ip_count: int,
    coverage: dict[str, Any],
    metrics: dict[str, Any],
) -> TopologySnapshotModel:
    now = datetime.now(timezone.utc)
    stmt = (
        pg_insert(TopologySnapshotModel)
        .values(
            snapshot_key=snapshot_key,
            node_count=node_count,
            edge_count=edge_count,
            agent_count=agent_count,
            subnet_count=subnet_count,
            external_ip_count=external_ip_count,
            created_at=now,
            coverage=coverage,
            metrics=metrics,
        )
        .on_conflict_do_update(
            index_elements=["snapshot_key"],
            set_={
                "node_count": node_count,
                "edge_count": edge_count,
                "agent_count": agent_count,
                "subnet_count": subnet_count,
                "external_ip_count": external_ip_count,
                "created_at": now,
                "coverage": coverage,
                "metrics": metrics,
            },
        )
        .returning(TopologySnapshotModel)
    )
    return db.execute(stmt).scalars().one()


def get_node(db: Session, node_key: str) -> TopologyNodeModel | None:
    return db.execute(
        select(TopologyNodeModel).where(TopologyNodeModel.node_key == node_key)
    ).scalars().first()


def get_edge(db: Session, edge_key: str) -> TopologyEdgeModel | None:
    return db.execute(
        select(TopologyEdgeModel).where(TopologyEdgeModel.edge_key == edge_key)
    ).scalars().first()


def get_latest_snapshot(db: Session) -> TopologySnapshotModel | None:
    return db.execute(
        select(TopologySnapshotModel)
        .order_by(TopologySnapshotModel.created_at.desc(), TopologySnapshotModel.id.desc())
        .limit(1)
    ).scalars().first()


def list_nodes(
    db: Session,
    *,
    agent_id: str | None = None,
    node_types: Sequence[str] | None = None,
    ip_scope: str | None = None,
    min_confidence: int = 1,
    include_stale: bool = False,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int,
) -> list[TopologyNodeModel]:
    limit = min(int(limit), _MAX_GRAPH_FETCH)
    stmt = select(TopologyNodeModel).where(
        TopologyNodeModel.confidence >= int(min_confidence),
    )
    if not include_stale:
        stmt = stmt.where(TopologyNodeModel.is_stale == 0)
    if agent_id:
        stmt = stmt.where(TopologyNodeModel.agent_id == agent_id)
    if node_types:
        stmt = stmt.where(TopologyNodeModel.node_type.in_(list(node_types)))
    if ip_scope:
        stmt = stmt.where(TopologyNodeModel.extra_data["ip_scope"].astext == ip_scope)
    if since is not None:
        stmt = stmt.where(TopologyNodeModel.last_seen_at >= since)
    if until is not None:
        stmt = stmt.where(TopologyNodeModel.last_seen_at <= until)
    stmt = stmt.order_by(
        TopologyNodeModel.risk_score.desc(),
        TopologyNodeModel.confidence.desc(),
        TopologyNodeModel.id.desc(),
    )
    return db.execute(stmt.limit(limit)).scalars().all()


def list_edges(
    db: Session,
    *,
    agent_id: str | None = None,
    edge_types: Sequence[str] | None = None,
    min_confidence: int = 1,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int,
) -> list[TopologyEdgeModel]:
    limit = min(int(limit), _MAX_GRAPH_FETCH)
    stmt = select(TopologyEdgeModel).where(
        TopologyEdgeModel.confidence >= int(min_confidence),
    )
    if agent_id:
        stmt = stmt.where(TopologyEdgeModel.agent_id == agent_id)
    if edge_types:
        stmt = stmt.where(TopologyEdgeModel.edge_type.in_(list(edge_types)))
    if since is not None:
        stmt = stmt.where(TopologyEdgeModel.last_seen_at >= since)
    if until is not None:
        stmt = stmt.where(TopologyEdgeModel.last_seen_at <= until)
    stmt = stmt.order_by(
        TopologyEdgeModel.confidence.desc(),
        TopologyEdgeModel.weight.desc(),
        TopologyEdgeModel.id.desc(),
    )
    return db.execute(stmt.limit(limit)).scalars().all()


def list_edges_for_node(
    db: Session,
    *,
    node_key: str,
    limit: int = 50,
) -> list[TopologyEdgeModel]:
    limit = min(int(limit), _MAX_PAGE)
    stmt = (
        select(TopologyEdgeModel)
        .where(
            or_(
                TopologyEdgeModel.source_node_key == node_key,
                TopologyEdgeModel.target_node_key == node_key,
            )
        )
        .order_by(TopologyEdgeModel.confidence.desc(), TopologyEdgeModel.id.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def list_connected_node_keys(
    db: Session,
    *,
    node_key: str,
    limit: int = 50,
) -> list[str]:
    edges = list_edges_for_node(db, node_key=node_key, limit=limit)
    keys: list[str] = []
    seen: set[str] = set()
    for edge in edges:
        for k in (edge.source_node_key, edge.target_node_key):
            if k != node_key and k not in seen:
                seen.add(k)
                keys.append(k)
    return keys


def list_nodes_by_keys(
    db: Session,
    *,
    node_keys: Sequence[str],
) -> list[TopologyNodeModel]:
    if not node_keys:
        return []
    stmt = select(TopologyNodeModel).where(TopologyNodeModel.node_key.in_(list(node_keys)))
    return db.execute(stmt).scalars().all()


def list_observations_page(
    db: Session,
    *,
    page_size: int,
    node_key: str | None,
    agent_id: str | None,
    source_type: str | None,
    since: datetime | None,
    until: datetime | None,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[TopologyObservationModel]:
    page_size = min(int(page_size), _MAX_PAGE)
    stmt = select(TopologyObservationModel).order_by(
        TopologyObservationModel.observed_at.desc(),
        TopologyObservationModel.id.desc(),
    )
    if node_key:
        stmt = stmt.where(TopologyObservationModel.node_key == node_key)
    if agent_id:
        stmt = stmt.where(TopologyObservationModel.agent_id == agent_id)
    if source_type:
        stmt = stmt.where(TopologyObservationModel.source_type == source_type)
    if since is not None:
        stmt = stmt.where(TopologyObservationModel.observed_at >= since)
    if until is not None:
        stmt = stmt.where(TopologyObservationModel.observed_at <= until)
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                TopologyObservationModel.observed_at < c_ts,
                and_(
                    TopologyObservationModel.observed_at == c_ts,
                    TopologyObservationModel.id < c_id,
                ),
            )
        )
    return db.execute(stmt.limit(page_size + 1)).scalars().all()


def list_observations_for_node(
    db: Session,
    *,
    node_key: str,
    limit: int = 20,
) -> list[TopologyObservationModel]:
    limit = min(int(limit), _MAX_PAGE)
    stmt = (
        select(TopologyObservationModel)
        .where(TopologyObservationModel.node_key == node_key)
        .order_by(TopologyObservationModel.observed_at.desc(), TopologyObservationModel.id.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def list_subnet_nodes_page(
    db: Session,
    *,
    page_size: int,
    agent_id: str | None,
    since: datetime | None,
    until: datetime | None,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[TopologyNodeModel]:
    page_size = min(int(page_size), _MAX_PAGE)
    stmt = (
        select(TopologyNodeModel)
        .where(TopologyNodeModel.node_type == "subnet")
        .order_by(TopologyNodeModel.last_seen_at.desc(), TopologyNodeModel.id.desc())
    )
    if agent_id:
        stmt = stmt.where(TopologyNodeModel.agent_id == agent_id)
    if since is not None:
        stmt = stmt.where(TopologyNodeModel.last_seen_at >= since)
    if until is not None:
        stmt = stmt.where(TopologyNodeModel.last_seen_at <= until)
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                TopologyNodeModel.last_seen_at < c_ts,
                and_(
                    TopologyNodeModel.last_seen_at == c_ts,
                    TopologyNodeModel.id < c_id,
                ),
            )
        )
    return db.execute(stmt.limit(page_size + 1)).scalars().all()


def topology_summary_metrics(db: Session) -> dict[str, Any]:
    total_nodes = int(db.execute(select(func.count(TopologyNodeModel.id))).scalar() or 0)
    total_edges = int(db.execute(select(func.count(TopologyEdgeModel.id))).scalar() or 0)
    stale_nodes = int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(TopologyNodeModel.is_stale == 1)
        ).scalar()
        or 0
    )

    type_rows = db.execute(
        select(TopologyNodeModel.node_type, func.count(TopologyNodeModel.id))
        .group_by(TopologyNodeModel.node_type)
    ).all()
    by_type: dict[str, int] = {row[0]: int(row[1]) for row in type_rows}

    alert_edges = int(
        db.execute(
            select(func.count(TopologyEdgeModel.id)).where(
                TopologyEdgeModel.edge_type == "alert_related"
            )
        ).scalar()
        or 0
    )
    exposure_edges = int(
        db.execute(
            select(func.count(TopologyEdgeModel.id)).where(
                TopologyEdgeModel.edge_type == "exposure_related"
            )
        ).scalar()
        or 0
    )

    return {
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "stale_node_count": stale_nodes,
        "by_type": by_type,
        "alert_edge_count": alert_edges,
        "exposure_edge_count": exposure_edges,
    }


def mark_all_nodes_stale(db: Session) -> int:
    """Mark all existing nodes as stale before re-projection. Returns row count."""
    from sqlalchemy import update
    result = db.execute(
        update(TopologyNodeModel).values(is_stale=1)
    )
    return int(result.rowcount or 0)
