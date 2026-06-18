from __future__ import annotations

from datetime import datetime
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel


class AlertDTO(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    created_at: datetime
    rule_id: str
    severity: str
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    mitre_tactic: str | None
    mitre_technique_id: str | None
    mitre_technique: str | None
    confidence: int
    description: str
    details: dict[str, Any]
    detector_type: str | None
    rule_version: int | None
    rule_hash: str | None
    ruleset_version: str | None
    status: str
    disposition: str | None
    priority: int | None
    assigned_to: str | None
    investigation_id: int | None
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    closed_at: datetime | None
    closed_by: str | None
    triage_notes: str | None
    risk_score: int | None
    false_positive_reason: str | None


class AlertAssetSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    created_at: datetime
    severity: str
    rule_id: str
    mitre_tactic: str | None
    mitre_technique: str | None
    description: str
    confidence: int


class AlertFlowSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    severity: str
    created_at: datetime


def _to_alert_dto(row: AlertModel) -> AlertDTO:
    return AlertDTO(
        id=row.id,
        created_at=row.created_at,
        rule_id=row.rule_id,
        severity=row.severity,
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        dst_port=row.dst_port,
        mitre_tactic=row.mitre_tactic,
        mitre_technique_id=row.mitre_technique_id,
        mitre_technique=row.mitre_technique,
        confidence=row.confidence,
        description=row.description,
        details=row.details or {},
        detector_type=row.detector_type,
        rule_version=row.rule_version,
        rule_hash=row.rule_hash,
        ruleset_version=row.ruleset_version,
        status=row.status,
        disposition=row.disposition,
        priority=row.priority,
        assigned_to=row.assigned_to,
        investigation_id=row.investigation_id,
        acknowledged_at=row.acknowledged_at,
        acknowledged_by=row.acknowledged_by,
        closed_at=row.closed_at,
        closed_by=row.closed_by,
        triage_notes=row.triage_notes,
        risk_score=row.risk_score,
        false_positive_reason=row.false_positive_reason,
    )


def list_recent_alerts(db: Session, *, min_ts: datetime, limit: int) -> list[AlertDTO]:
    stmt = (
        select(AlertModel)
        .where(AlertModel.created_at >= min_ts)
        .order_by(AlertModel.created_at.desc())
        .limit(limit)
    )
    return [_to_alert_dto(row) for row in db.execute(stmt).scalars().all()]


def list_alerts_for_asset(
    db: Session,
    *,
    agent_id: str | None,
    asset_ips: Sequence[str],
    hostname: str | None,
    limit: int,
    since: datetime | None = None,
) -> list[AlertDTO]:
    conditions = []
    if agent_id:
        conditions.append(func.jsonb_extract_path_text(AlertModel.details, "agent_id") == agent_id)
    ips = [str(value or "").strip() for value in asset_ips if str(value or "").strip()]
    if ips:
        conditions.append(AlertModel.src_ip.in_(ips))
        conditions.append(AlertModel.dst_ip.in_(ips))
    if hostname:
        conditions.append(func.lower(func.jsonb_extract_path_text(AlertModel.details, "hostname")) == hostname.lower())
    if not conditions:
        return []

    stmt = select(AlertModel).where(or_(*conditions))
    if since is not None:
        stmt = stmt.where(AlertModel.created_at >= since)
    stmt = stmt.order_by(AlertModel.created_at.desc(), AlertModel.id.desc()).limit(max(1, int(limit)))
    return [_to_alert_dto(row) for row in db.execute(stmt).scalars().all()]


def list_asset_alert_summaries(
    db: Session,
    *,
    agent_id: str,
    asset_ips: tuple[str, ...],
    hostname: str | None,
    lookback: datetime,
    limit: int,
) -> list[AlertAssetSummary]:
    clauses = [func.jsonb_extract_path_text(AlertModel.details, "agent_id") == agent_id]
    if asset_ips:
        clauses.append(AlertModel.src_ip.in_(asset_ips))
        clauses.append(AlertModel.dst_ip.in_(asset_ips))
        clauses.append(func.jsonb_extract_path_text(AlertModel.details, "asset_ip").in_(asset_ips))
    if hostname:
        host = hostname.lower()
        clauses.append(func.lower(func.jsonb_extract_path_text(AlertModel.details, "hostname")) == host)

    stmt = (
        select(
            AlertModel.id,
            AlertModel.created_at,
            AlertModel.severity,
            AlertModel.rule_id,
            AlertModel.mitre_tactic,
            AlertModel.mitre_technique,
            AlertModel.description,
            AlertModel.confidence,
        )
        .where(or_(*clauses), AlertModel.created_at >= lookback)
        .order_by(AlertModel.created_at.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).mappings().all()
    return [
        AlertAssetSummary(
            id=r["id"],
            created_at=r["created_at"],
            severity=r["severity"],
            rule_id=r["rule_id"],
            mitre_tactic=r["mitre_tactic"],
            mitre_technique=r["mitre_technique"],
            description=r["description"],
            confidence=r["confidence"],
        )
        for r in rows
    ]


def list_alerts_for_node(db: Session, *, ip: str, agent_id: str, limit: int = 10) -> list[AlertDTO]:
    conditions = []
    if ip:
        conditions.append(or_(AlertModel.src_ip == ip, AlertModel.dst_ip == ip))
    elif agent_id:
        conditions.append(AlertModel.details["agent_id"].astext == agent_id)
    if not conditions:
        return []
    stmt = (
        select(AlertModel)
        .where(*conditions)
        .order_by(AlertModel.created_at.desc(), AlertModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return [_to_alert_dto(row) for row in db.execute(stmt).scalars().all()]


def list_alerts_for_edge(
    db: Session,
    *,
    src_ip: str,
    dst_ip: str,
    port: int | None,
    agent_id: str,
    limit: int = 10,
) -> list[AlertDTO]:
    conditions = []
    if src_ip and dst_ip:
        conditions.append(
            or_(
                and_(AlertModel.src_ip == src_ip, AlertModel.dst_ip == dst_ip),
                and_(AlertModel.src_ip == dst_ip, AlertModel.dst_ip == src_ip),
            )
        )
    elif src_ip or dst_ip:
        ip = src_ip or dst_ip
        conditions.append(or_(AlertModel.src_ip == ip, AlertModel.dst_ip == ip))
    if port is not None:
        conditions.append(AlertModel.dst_port == int(port))
    if agent_id:
        conditions.append(AlertModel.details["agent_id"].astext == agent_id)
    if not conditions:
        return []
    stmt = (
        select(AlertModel)
        .where(*conditions)
        .order_by(AlertModel.created_at.desc(), AlertModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return [_to_alert_dto(row) for row in db.execute(stmt).scalars().all()]


def list_alert_flows_since(db: Session, *, since: datetime, limit: int) -> list[AlertFlowSummary]:
    stmt = (
        select(
            AlertModel.src_ip,
            AlertModel.dst_ip,
            AlertModel.dst_port,
            AlertModel.severity,
            AlertModel.created_at,
        )
        .where(
            AlertModel.created_at >= since,
            AlertModel.src_ip.isnot(None),
            AlertModel.dst_ip.isnot(None),
        )
        .order_by(AlertModel.created_at.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).all()
    return [
        AlertFlowSummary(
            src_ip=row[0],
            dst_ip=row[1],
            dst_port=row[2],
            severity=row[3],
            created_at=row[4],
        )
        for row in rows
    ]
