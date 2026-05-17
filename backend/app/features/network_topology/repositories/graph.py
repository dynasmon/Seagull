from __future__ import annotations

from datetime import datetime
from typing import Sequence

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.features.network_topology.models import (
    TopologyEdgeModel,
    TopologyNodeModel,
    TopologyObservationModel,
    TopologySnapshotModel,
)
from app.features.network_topology.repositories.constants import _MAX_GRAPH_FETCH, _MAX_PAGE


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

def list_observations_for_edge(
    db: Session,
    *,
    edge_key: str,
    limit: int = 20,
) -> list[TopologyObservationModel]:
    limit = min(int(limit), _MAX_PAGE)
    stmt = (
        select(TopologyObservationModel)
        .where(TopologyObservationModel.edge_key == edge_key)
        .order_by(TopologyObservationModel.observed_at.desc(), TopologyObservationModel.id.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()

def count_observations_for_node(db: Session, *, node_key: str) -> int:
    return int(
        db.execute(
            select(func.count(TopologyObservationModel.id)).where(TopologyObservationModel.node_key == node_key)
        ).scalar()
        or 0
    )

def count_observations_for_edge(db: Session, *, edge_key: str) -> int:
    return int(
        db.execute(
            select(func.count(TopologyObservationModel.id)).where(TopologyObservationModel.edge_key == edge_key)
        ).scalar()
        or 0
    )

def evidence_sources_for_node(db: Session, *, node_key: str, limit: int = 12) -> list[tuple[str, int, datetime | None]]:
    stmt = (
        select(
            TopologyObservationModel.source_type,
            func.count(TopologyObservationModel.id),
            func.max(TopologyObservationModel.observed_at),
        )
        .where(TopologyObservationModel.node_key == node_key)
        .group_by(TopologyObservationModel.source_type)
        .order_by(func.count(TopologyObservationModel.id).desc(), func.max(TopologyObservationModel.observed_at).desc())
        .limit(min(int(limit), 50))
    )
    return [(str(row[0]), int(row[1] or 0), row[2]) for row in db.execute(stmt).all()]

def evidence_sources_for_edge(db: Session, *, edge_key: str, limit: int = 12) -> list[tuple[str, int, datetime | None]]:
    stmt = (
        select(
            TopologyObservationModel.source_type,
            func.count(TopologyObservationModel.id),
            func.max(TopologyObservationModel.observed_at),
        )
        .where(TopologyObservationModel.edge_key == edge_key)
        .group_by(TopologyObservationModel.source_type)
        .order_by(func.count(TopologyObservationModel.id).desc(), func.max(TopologyObservationModel.observed_at).desc())
        .limit(min(int(limit), 50))
    )
    return [(str(row[0]), int(row[1] or 0), row[2]) for row in db.execute(stmt).all()]

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
