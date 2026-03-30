from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel
from app.features.correlations.models import CorrelationRuleModel


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


def list_recent_alerts(db: Session, *, min_ts: datetime, limit: int) -> list[AlertModel]:
    stmt = (
        select(AlertModel)
        .where(AlertModel.created_at >= min_ts)
        .order_by(AlertModel.created_at.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def add(db: Session, row: CorrelationRuleModel) -> None:
    db.add(row)


def delete(db: Session, row: CorrelationRuleModel) -> None:
    db.delete(row)


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row: CorrelationRuleModel) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()
