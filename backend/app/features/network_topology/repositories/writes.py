from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.features.network_topology.models import (
    TopologyEdgeModel,
    TopologyNodeModel,
    TopologyObservationModel,
    TopologySnapshotModel,
)


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
    event_count: int | None = None,
    alert_count: int | None = None,
    observation_count: int | None = None,
) -> TopologyNodeModel:
    now = datetime.now(timezone.utc)
    values = {
        "node_key": node_key,
        "node_type": node_type,
        "label": label,
        "agent_id": agent_id,
        "ip": ip,
        "cidr": cidr,
        "port": port,
        "protocol": protocol,
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "is_stale": 0,
        "first_seen_at": first_seen_at,
        "last_seen_at": last_seen_at,
        "updated_at": now,
        "extra_data": extra_data,
    }
    update_values = {
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
    }
    if event_count is not None:
        values["event_count"] = int(event_count)
        update_values["event_count"] = func.greatest(TopologyNodeModel.event_count, int(event_count))
    if alert_count is not None:
        values["alert_count"] = int(alert_count)
        update_values["alert_count"] = func.greatest(TopologyNodeModel.alert_count, int(alert_count))
    if observation_count is not None:
        values["observation_count"] = int(observation_count)
        update_values["observation_count"] = func.greatest(TopologyNodeModel.observation_count, int(observation_count))
    stmt = (
        pg_insert(TopologyNodeModel)
        .values(**values)
        .on_conflict_do_update(
            index_elements=["node_key"],
            set_=update_values,
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
    event_count: int | None = None,
    alert_count: int | None = None,
) -> TopologyEdgeModel:
    now = datetime.now(timezone.utc)
    values = {
        "edge_key": edge_key,
        "source_node_key": source_node_key,
        "target_node_key": target_node_key,
        "edge_type": edge_type,
        "agent_id": agent_id,
        "weight": weight,
        "confidence": confidence,
        "severity": severity,
        "port": port,
        "protocol": protocol,
        "first_seen_at": first_seen_at,
        "last_seen_at": last_seen_at,
        "updated_at": now,
        "extra_data": extra_data,
    }
    update_values = {
        "weight": weight,
        "confidence": confidence,
        "severity": severity,
        "last_seen_at": last_seen_at,
        "updated_at": now,
        "extra_data": extra_data,
    }
    if event_count is not None:
        values["event_count"] = int(event_count)
        update_values["event_count"] = func.greatest(TopologyEdgeModel.event_count, int(event_count))
    if alert_count is not None:
        values["alert_count"] = int(alert_count)
        update_values["alert_count"] = func.greatest(TopologyEdgeModel.alert_count, int(alert_count))
    stmt = (
        pg_insert(TopologyEdgeModel)
        .values(**values)
        .on_conflict_do_update(
            index_elements=["edge_key"],
            set_=update_values,
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

def mark_all_nodes_stale(db: Session) -> int:
    result = db.execute(update(TopologyNodeModel).values(is_stale=1))
    return int(result.rowcount or 0)


def release_external_node_ownership(db: Session) -> int:
    result = db.execute(
        update(TopologyNodeModel)
        .where(
            TopologyNodeModel.agent_id.isnot(None),
            TopologyNodeModel.node_type == "external_ip",
        )
        .values(agent_id=None)
    )
    return int(result.rowcount or 0)
