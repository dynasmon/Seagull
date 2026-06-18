from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.features.alerts import public as alerts_public
from app.features.attack_chain import public as attack_chain_public
from app.features.correlations.models import (
    CorrelationEntityStateModel,
    CorrelationIncidentEvidenceModel,
    CorrelationIncidentModel,
    CorrelationRuleModel,
)
from app.features.events.models import NetEventModel
from app.features.exposure.models import ExposureFindingModel
from app.features.vuln.public import VulnFindingDTO, list_recent_findings

_OPEN_STATUSES = frozenset({"open", "triaged"})
_VALID_STATUSES = frozenset({"open", "triaged", "closed", "suppressed"})


def list_rules(db: Session) -> list[CorrelationRuleModel]:
    return db.execute(select(CorrelationRuleModel).order_by(CorrelationRuleModel.id.asc())).scalars().all()


def get_rule_by_id(db: Session, rule_id: int) -> CorrelationRuleModel | None:
    return db.get(CorrelationRuleModel, rule_id)


def list_enabled_rules(db: Session) -> list[CorrelationRuleModel]:
    stmt = (
        select(CorrelationRuleModel)
        .where(CorrelationRuleModel.enabled.is_(True))
        .order_by(CorrelationRuleModel.id.asc())
    )
    return db.execute(stmt).scalars().all()


def list_recent_alerts(db: Session, *, min_ts: datetime, limit: int) -> list[alerts_public.AlertDTO]:
    return alerts_public.list_recent_alerts(db, min_ts=min_ts, limit=limit)


def list_recent_net_events(db: Session, *, min_ts: datetime, limit: int) -> list[NetEventModel]:
    stmt = (
        select(NetEventModel)
        .where(NetEventModel.timestamp >= min_ts)
        .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def list_recent_vuln_findings(db: Session, *, min_ts: datetime, limit: int) -> list[VulnFindingDTO]:
    return list_recent_findings(db, min_ts=min_ts, limit=limit)


def list_recent_exposure_findings(db: Session, *, min_ts: datetime, limit: int) -> list[ExposureFindingModel]:
    stmt = (
        select(ExposureFindingModel)
        .where(ExposureFindingModel.last_seen_at >= min_ts)
        .order_by(ExposureFindingModel.last_seen_at.desc(), ExposureFindingModel.id.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def list_recent_attack_chain_steps(db: Session, *, min_ts: datetime, limit: int) -> list[attack_chain_public.AttackChainStepDTO]:
    return attack_chain_public.list_recent_steps(db, min_ts=min_ts, limit=limit)


def list_recent_attack_chain_cases(db: Session, *, min_ts: datetime, limit: int) -> list[attack_chain_public.AttackChainCaseDTO]:
    return attack_chain_public.list_recent_cases(db, min_ts=min_ts, limit=limit)


# Incident repository

def list_incidents(
    db: Session,
    *,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[CorrelationIncidentModel]:
    stmt = select(CorrelationIncidentModel).order_by(CorrelationIncidentModel.last_seen_at.desc())
    if status:
        stmt = stmt.where(CorrelationIncidentModel.status == status)
    stmt = stmt.limit(limit).offset(offset)
    return db.execute(stmt).scalars().all()


def get_incident_by_id(db: Session, incident_id: int) -> CorrelationIncidentModel | None:
    return db.get(CorrelationIncidentModel, incident_id)


def find_open_incident(
    db: Session,
    *,
    correlation_rule_id: int,
    group_value: str,
) -> CorrelationIncidentModel | None:
    stmt = (
        select(CorrelationIncidentModel)
        .where(CorrelationIncidentModel.correlation_rule_id == correlation_rule_id)
        .where(CorrelationIncidentModel.group_value == group_value)
        .where(CorrelationIncidentModel.status.in_(list(_OPEN_STATUSES)))
        .order_by(CorrelationIncidentModel.started_at.desc())
        .limit(1)
    )
    return db.execute(stmt).scalar_one_or_none()


def get_evidence_alert_ids(db: Session, incident_id: int) -> set[int]:
    rows = db.execute(
        select(CorrelationIncidentEvidenceModel.alert_id)
        .where(CorrelationIncidentEvidenceModel.incident_id == incident_id)
        .where(CorrelationIncidentEvidenceModel.alert_id.isnot(None))
    ).scalars().all()
    return set(rows)


def list_evidence_for_incident(db: Session, incident_id: int) -> list[CorrelationIncidentEvidenceModel]:
    stmt = (
        select(CorrelationIncidentEvidenceModel)
        .where(CorrelationIncidentEvidenceModel.incident_id == incident_id)
        .order_by(CorrelationIncidentEvidenceModel.timestamp.asc())
    )
    return db.execute(stmt).scalars().all()


# Entity state repository

def get_entity_state(
    db: Session,
    *,
    entity_type: str,
    entity_value: str,
) -> CorrelationEntityStateModel | None:
    stmt = (
        select(CorrelationEntityStateModel)
        .where(CorrelationEntityStateModel.entity_type == entity_type)
        .where(CorrelationEntityStateModel.entity_value == entity_value)
    )
    return db.execute(stmt).scalar_one_or_none()


def list_entity_states(db: Session, *, entity_types: list[str] | None = None) -> list[CorrelationEntityStateModel]:
    stmt = select(CorrelationEntityStateModel)
    if entity_types:
        stmt = stmt.where(CorrelationEntityStateModel.entity_type.in_(list(entity_types)))
    stmt = stmt.order_by(CorrelationEntityStateModel.updated_at.desc())
    return db.execute(stmt).scalars().all()


# Generic helpers

def add(db: Session, row) -> None:
    db.add(row)


def delete(db: Session, row) -> None:
    db.delete(row)


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()
