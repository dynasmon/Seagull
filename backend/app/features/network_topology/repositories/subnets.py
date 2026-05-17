from __future__ import annotations

from typing import Any

from sqlalchemy import case, func, or_, select, union
from sqlalchemy.orm import Session

from app.features.network_topology.models import TopologyEdgeModel, TopologyNodeModel, TopologyObservationModel
from app.features.network_topology.repositories.constants import _MAX_PAGE


def get_subnet_node_by_cidr(db: Session, *, cidr: str) -> TopologyNodeModel | None:
    return db.execute(
        select(TopologyNodeModel).where(
            TopologyNodeModel.node_type == "subnet",
            TopologyNodeModel.cidr == cidr,
        )
    ).scalars().first()

def _subnet_member_keys_subquery(*, subnet_node_key: str, cidr: str):
    edge_members = select(TopologyEdgeModel.source_node_key.label("node_key")).where(
        TopologyEdgeModel.edge_type == "member_of_subnet",
        TopologyEdgeModel.target_node_key == subnet_node_key,
    )
    direct_members = select(TopologyNodeModel.node_key.label("node_key")).where(
        TopologyNodeModel.cidr == cidr,
        TopologyNodeModel.node_key != subnet_node_key,
    )
    return union(edge_members, direct_members).subquery()

def count_subnet_member_nodes(db: Session, *, subnet_node_key: str, cidr: str) -> int:
    member_keys = _subnet_member_keys_subquery(subnet_node_key=subnet_node_key, cidr=cidr)
    return int(db.execute(select(func.count()).select_from(member_keys)).scalar() or 0)

def subnet_member_metrics(db: Session, *, subnet_node_key: str, cidr: str) -> dict[str, Any]:
    member_keys = _subnet_member_keys_subquery(subnet_node_key=subnet_node_key, cidr=cidr)
    row = db.execute(
        select(
            func.count(TopologyNodeModel.id),
            func.coalesce(func.sum(case((TopologyNodeModel.is_stale == 0, 1), else_=0)), 0),
            func.coalesce(func.sum(case((TopologyNodeModel.is_stale != 0, 1), else_=0)), 0),
            func.coalesce(func.sum(TopologyNodeModel.alert_count), 0),
            func.max(TopologyNodeModel.risk_score),
            func.max(TopologyNodeModel.confidence),
            func.min(TopologyNodeModel.first_seen_at),
            func.max(TopologyNodeModel.last_seen_at),
        ).where(TopologyNodeModel.node_key.in_(select(member_keys.c.node_key)))
    ).one()
    return {
        "node_count": int(row[0] or 0),
        "active_node_count": int(row[1] or 0),
        "stale_node_count": int(row[2] or 0),
        "alert_count": int(row[3] or 0),
        "risk_score": int(row[4]) if row[4] is not None else None,
        "confidence": int(row[5]) if row[5] is not None else None,
        "first_seen": row[6],
        "last_seen": row[7],
    }

def list_subnet_member_nodes(
    db: Session,
    *,
    subnet_node_key: str,
    cidr: str,
    limit: int,
) -> list[TopologyNodeModel]:
    limit = min(int(limit), _MAX_PAGE)
    member_keys = _subnet_member_keys_subquery(subnet_node_key=subnet_node_key, cidr=cidr)
    severity_rank = case(
        (TopologyNodeModel.severity == "critical", 5),
        (TopologyNodeModel.severity == "high", 4),
        (TopologyNodeModel.severity == "medium", 3),
        (TopologyNodeModel.severity == "low", 2),
        (TopologyNodeModel.severity == "informational", 1),
        else_=0,
    )
    stmt = (
        select(TopologyNodeModel)
        .where(TopologyNodeModel.node_key.in_(select(member_keys.c.node_key)))
        .order_by(
            severity_rank.desc(),
            TopologyNodeModel.risk_score.desc(),
            TopologyNodeModel.alert_count.desc(),
            TopologyNodeModel.event_count.desc(),
            TopologyNodeModel.last_seen_at.desc(),
            TopologyNodeModel.id.desc(),
        )
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()

def _subnet_related_edge_filter(*, subnet_node_key: str, cidr: str):
    member_keys = _subnet_member_keys_subquery(subnet_node_key=subnet_node_key, cidr=cidr)
    return or_(
        TopologyEdgeModel.source_node_key.in_(select(member_keys.c.node_key)),
        TopologyEdgeModel.target_node_key.in_(select(member_keys.c.node_key)),
        TopologyEdgeModel.source_node_key == subnet_node_key,
        TopologyEdgeModel.target_node_key == subnet_node_key,
    )

def count_edges_for_subnet(db: Session, *, subnet_node_key: str, cidr: str) -> int:
    return int(
        db.execute(
            select(func.count(TopologyEdgeModel.id)).where(
                _subnet_related_edge_filter(subnet_node_key=subnet_node_key, cidr=cidr)
            )
        ).scalar()
        or 0
    )

def list_edges_for_subnet(
    db: Session,
    *,
    subnet_node_key: str,
    cidr: str,
    limit: int,
) -> list[TopologyEdgeModel]:
    limit = min(int(limit), _MAX_PAGE)
    severity_rank = case(
        (TopologyEdgeModel.severity == "critical", 5),
        (TopologyEdgeModel.severity == "high", 4),
        (TopologyEdgeModel.severity == "medium", 3),
        (TopologyEdgeModel.severity == "low", 2),
        (TopologyEdgeModel.severity == "informational", 1),
        else_=0,
    )
    stmt = (
        select(TopologyEdgeModel)
        .where(_subnet_related_edge_filter(subnet_node_key=subnet_node_key, cidr=cidr))
        .order_by(
            severity_rank.desc(),
            TopologyEdgeModel.alert_count.desc(),
            TopologyEdgeModel.event_count.desc(),
            TopologyEdgeModel.last_seen_at.desc(),
            TopologyEdgeModel.id.desc(),
        )
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()

def count_observations_for_subnet(db: Session, *, subnet_node_key: str, cidr: str) -> int:
    member_keys = _subnet_member_keys_subquery(subnet_node_key=subnet_node_key, cidr=cidr)
    edge_keys = select(TopologyEdgeModel.edge_key).where(
        _subnet_related_edge_filter(subnet_node_key=subnet_node_key, cidr=cidr)
    )
    return int(
        db.execute(
            select(func.count(TopologyObservationModel.id)).where(
                or_(
                    TopologyObservationModel.node_key == subnet_node_key,
                    TopologyObservationModel.node_key.in_(select(member_keys.c.node_key)),
                    TopologyObservationModel.edge_key.in_(edge_keys),
                )
            )
        ).scalar()
        or 0
    )

def list_observations_for_subnet(
    db: Session,
    *,
    subnet_node_key: str,
    cidr: str,
    limit: int,
) -> list[TopologyObservationModel]:
    limit = min(int(limit), _MAX_PAGE)
    member_keys = _subnet_member_keys_subquery(subnet_node_key=subnet_node_key, cidr=cidr)
    edge_keys = select(TopologyEdgeModel.edge_key).where(
        _subnet_related_edge_filter(subnet_node_key=subnet_node_key, cidr=cidr)
    )
    stmt = (
        select(TopologyObservationModel)
        .where(
            or_(
                TopologyObservationModel.node_key == subnet_node_key,
                TopologyObservationModel.node_key.in_(select(member_keys.c.node_key)),
                TopologyObservationModel.edge_key.in_(edge_keys),
            )
        )
        .order_by(TopologyObservationModel.observed_at.desc(), TopologyObservationModel.id.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()
