from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.features.alerts.models import AlertEvidenceModel, AlertModel
from app.features.alerts.models import AlertRuleOverrideModel
from app.features.alerts.rule_registry_runtime import fetch_overrides, fetch_suppressions, fetch_tuning
from app.features.alerts.models import AlertRuleSuppressionHistoryModel, AlertRuleSuppressionModel
from app.features.alerts.models import AlertRuleTuningHistoryModel, AlertRuleTuningModel
from app.features.events.models import NetEventModel


# Alert queries

def get_alert_by_id(db: Session, alert_id: int) -> AlertModel | None:
    return db.get(AlertModel, alert_id)


def list_alerts_page(
    db: Session,
    *,
    page_size: int,
    severity: str | None,
    rule_id: str | None,
    tactic: str | None,
    technique_id: str | None,
    min_confidence: int | None,
    status: str | None,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[AlertModel]:
    stmt = select(AlertModel).order_by(AlertModel.created_at.desc(), AlertModel.id.desc())

    if severity:
        stmt = stmt.where(AlertModel.severity == severity)
    if rule_id:
        stmt = stmt.where(AlertModel.rule_id == rule_id)
    if tactic:
        stmt = stmt.where(AlertModel.mitre_tactic == tactic)
    if technique_id:
        stmt = stmt.where(AlertModel.mitre_technique_id == technique_id)
    if min_confidence is not None:
        stmt = stmt.where(AlertModel.confidence >= int(min_confidence))
    if status:
        stmt = stmt.where(AlertModel.status == status)

    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                AlertModel.created_at < c_ts,
                and_(AlertModel.created_at == c_ts, AlertModel.id < c_id),
            )
        )

    return db.execute(stmt.limit(page_size + 1)).scalars().all()


def list_recent_alerts(db: Session, *, limit: int) -> list[AlertModel]:
    stmt = select(AlertModel).order_by(AlertModel.created_at.desc()).limit(limit)
    return db.execute(stmt).scalars().all()


def list_mitre_coverage_rows(db: Session, *, threshold: datetime) -> list[Any]:
    stmt = (
        select(
            AlertModel.mitre_tactic.label("tactic"),
            AlertModel.mitre_technique_id.label("technique_id"),
            AlertModel.mitre_technique.label("technique"),
            func.count().label("cnt"),
            func.max(AlertModel.confidence).label("max_conf"),
            func.avg(AlertModel.confidence).label("avg_conf"),
        )
        .where(AlertModel.created_at >= threshold)
        .where(AlertModel.mitre_tactic.is_not(None))
        .where(AlertModel.mitre_technique_id.is_not(None))
        .group_by(AlertModel.mitre_tactic, AlertModel.mitre_technique_id, AlertModel.mitre_technique)
        .order_by(AlertModel.mitre_tactic.asc(), func.count().desc())
    )
    return db.execute(stmt).all()


# Event-derived detection candidate queries

def list_ssh_bruteforce_candidates(
    db: Session,
    *,
    time_threshold: datetime,
    min_events: int,
) -> list[Any]:
    stmt = (
        select(
            NetEventModel.src_ip.label("src_ip"),
            func.count().label("count"),
        )
        .where(NetEventModel.event_type == "flow")
        .where(NetEventModel.dst_port == 22)
        .where(NetEventModel.timestamp >= time_threshold)
        .where(NetEventModel.src_ip.is_not(None))
        .group_by(NetEventModel.src_ip)
        .having(func.count() >= min_events)
    )
    return db.execute(stmt).all()


def list_port_scan_candidates(
    db: Session,
    *,
    time_threshold: datetime,
    min_distinct_ports: int,
) -> list[Any]:
    stmt = (
        select(
            NetEventModel.src_ip.label("src_ip"),
            func.count(func.distinct(NetEventModel.dst_port)).label("distinct_ports"),
            func.count().label("event_count"),
        )
        .where(NetEventModel.event_type == "flow")
        .where(NetEventModel.proto == "tcp")
        .where(NetEventModel.timestamp >= time_threshold)
        .where(NetEventModel.src_ip.is_not(None))
        .where(NetEventModel.dst_port.is_not(None))
        .group_by(NetEventModel.src_ip)
        .having(func.count(func.distinct(NetEventModel.dst_port)) >= min_distinct_ports)
    )
    return db.execute(stmt).all()


def list_horizontal_scan_candidates(
    db: Session,
    *,
    time_threshold: datetime,
    min_distinct_targets: int,
    dst_port: int,
) -> list[Any]:
    stmt = (
        select(
            NetEventModel.src_ip.label("src_ip"),
            NetEventModel.dst_port.label("dst_port"),
            func.count(func.distinct(NetEventModel.dst_ip)).label("distinct_targets"),
            func.count().label("event_count"),
        )
        .where(NetEventModel.event_type == "flow")
        .where(NetEventModel.timestamp >= time_threshold)
        .where(NetEventModel.src_ip.is_not(None))
        .where(NetEventModel.dst_ip.is_not(None))
        .where(NetEventModel.dst_port == dst_port)
        .group_by(NetEventModel.src_ip, NetEventModel.dst_port)
        .having(func.count(func.distinct(NetEventModel.dst_ip)) >= min_distinct_targets)
    )
    return db.execute(stmt).all()


def list_new_source_hosts_candidates(
    db: Session,
    *,
    time_threshold: datetime,
    min_events: int,
) -> list[Any]:
    stmt = (
        select(
            NetEventModel.src_ip.label("ip"),
            func.min(NetEventModel.timestamp).label("first_seen"),
            func.count().label("event_count"),
        )
        .where(NetEventModel.src_ip.is_not(None))
        .group_by(NetEventModel.src_ip)
        .having(func.min(NetEventModel.timestamp) >= time_threshold)
        .having(func.count() >= min_events)
    )
    return db.execute(stmt).all()


def list_new_destination_hosts_candidates(
    db: Session,
    *,
    time_threshold: datetime,
    min_events: int,
) -> list[Any]:
    stmt = (
        select(
            NetEventModel.dst_ip.label("ip"),
            func.min(NetEventModel.timestamp).label("first_seen"),
            func.count().label("event_count"),
        )
        .where(NetEventModel.dst_ip.is_not(None))
        .group_by(NetEventModel.dst_ip)
        .having(func.min(NetEventModel.timestamp) >= time_threshold)
        .having(func.count() >= min_events)
    )
    return db.execute(stmt).all()


# Override entity

def get_rule_override(db: Session, rule_id: str) -> AlertRuleOverrideModel | None:
    return db.get(AlertRuleOverrideModel, rule_id)


def add_rule_override(db: Session, row: AlertRuleOverrideModel) -> None:
    db.add(row)


def delete_rule_override(db: Session, row: AlertRuleOverrideModel) -> None:
    db.delete(row)


def list_overrides_map(db: Session) -> dict[str, AlertRuleOverrideModel]:
    return fetch_overrides(db)


# Tuning entity

def get_rule_tuning(db: Session, rule_id: str) -> AlertRuleTuningModel | None:
    return db.get(AlertRuleTuningModel, rule_id)


def add_rule_tuning(db: Session, row: AlertRuleTuningModel) -> None:
    db.add(row)


def delete_rule_tuning(db: Session, row: AlertRuleTuningModel) -> None:
    db.delete(row)


def list_tuning_map(db: Session) -> dict[str, AlertRuleTuningModel]:
    return fetch_tuning(db)


def add_tuning_history(db: Session, row: AlertRuleTuningHistoryModel) -> None:
    db.add(row)


def list_tuning_history(db: Session, *, rule_id: str, limit: int) -> list[AlertRuleTuningHistoryModel]:
    return (
        db.query(AlertRuleTuningHistoryModel)
        .filter(AlertRuleTuningHistoryModel.rule_id == rule_id)
        .order_by(AlertRuleTuningHistoryModel.created_at.desc(), AlertRuleTuningHistoryModel.id.desc())
        .limit(limit)
        .all()
    )


# Suppression entity

def list_rule_suppressions(db: Session, *, rule_id: str) -> list[AlertRuleSuppressionModel]:
    return db.query(AlertRuleSuppressionModel).filter(AlertRuleSuppressionModel.rule_id == rule_id).all()


def add_rule_suppression(db: Session, row: AlertRuleSuppressionModel) -> None:
    db.add(row)


def delete_rule_suppression(db: Session, row: AlertRuleSuppressionModel) -> None:
    db.delete(row)


def flush(db: Session) -> None:
    db.flush()


def list_suppressions_map(db: Session) -> dict[str, list[AlertRuleSuppressionModel]]:
    return fetch_suppressions(db)


def add_suppression_history(db: Session, row: AlertRuleSuppressionHistoryModel) -> None:
    db.add(row)


def list_suppression_history(db: Session, *, rule_id: str, limit: int) -> list[AlertRuleSuppressionHistoryModel]:
    return (
        db.query(AlertRuleSuppressionHistoryModel)
        .filter(AlertRuleSuppressionHistoryModel.rule_id == rule_id)
        .order_by(AlertRuleSuppressionHistoryModel.created_at.desc(), AlertRuleSuppressionHistoryModel.id.desc())
        .limit(limit)
        .all()
    )


# Alert evidence

def list_alert_evidence(db: Session, alert_id: int) -> list[AlertEvidenceModel]:
    stmt = (
        select(AlertEvidenceModel)
        .where(AlertEvidenceModel.alert_id == alert_id)
        .order_by(AlertEvidenceModel.id)
    )
    return db.execute(stmt).scalars().all()


def add_alert_evidence(db: Session, row: AlertEvidenceModel) -> None:
    db.add(row)


# Shared persistence operations

def add_alert(db: Session, row: AlertModel) -> None:
    db.add(row)


def commit(db: Session) -> None:
    db.commit()


def refresh(db: Session, row: Any) -> None:
    db.refresh(row)
