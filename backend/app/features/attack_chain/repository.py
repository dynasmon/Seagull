from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.features.attack_chain.models import AttackChainAllowlistModel, AttackChainCaseModel, AttackChainStepModel


def list_cases_page(
    db: Session,
    *,
    page_size: int,
    agent_id: str | None,
    suspect_ip: str | None,
    status: str | None,
    min_score: int | None,
    since_dt: datetime | None,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[AttackChainCaseModel]:
    stmt = select(AttackChainCaseModel).order_by(AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc())
    if agent_id:
        stmt = stmt.where(AttackChainCaseModel.agent_id == agent_id)
    if suspect_ip:
        stmt = stmt.where(AttackChainCaseModel.suspect_ip == suspect_ip)
    if status:
        stmt = stmt.where(AttackChainCaseModel.status == status)
    if min_score is not None:
        stmt = stmt.where(AttackChainCaseModel.score >= int(min_score))
    if since_dt is not None:
        stmt = stmt.where(AttackChainCaseModel.last_seen_at >= since_dt)
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                AttackChainCaseModel.last_seen_at < c_ts,
                and_(AttackChainCaseModel.last_seen_at == c_ts, AttackChainCaseModel.id < c_id),
            )
        )
    return db.execute(stmt.limit(int(page_size) + 1)).scalars().all()


def get_case(db: Session, case_id: int) -> AttackChainCaseModel | None:
    return db.get(AttackChainCaseModel, int(case_id))


def list_steps_by_case(db: Session, *, case_id: int) -> list[AttackChainStepModel]:
    stmt = (
        select(AttackChainStepModel)
        .where(AttackChainStepModel.case_id == int(case_id))
        .order_by(AttackChainStepModel.timestamp.asc(), AttackChainStepModel.id.asc())
    )
    return db.execute(stmt).scalars().all()


def save_case(db: Session, row: AttackChainCaseModel) -> AttackChainCaseModel:
    db.add(row)
    return row


def list_allowlist(db: Session, *, rule_type: str) -> list[AttackChainAllowlistModel]:
    stmt = (
        select(AttackChainAllowlistModel)
        .where(AttackChainAllowlistModel.rule_type == rule_type)
        .order_by(AttackChainAllowlistModel.enabled.desc(), AttackChainAllowlistModel.updated_at.desc(), AttackChainAllowlistModel.id.desc())
    )
    return db.execute(stmt).scalars().all()


def create_allowlist(
    db: Session,
    *,
    rule_type: str,
    enabled: bool,
    match_mode: str,
    pattern: str,
    agent_id: Optional[str],
    username: Optional[str],
    target_user: Optional[str],
    notes: Optional[str],
) -> AttackChainAllowlistModel:
    row = AttackChainAllowlistModel(
        rule_type=rule_type,
        enabled=bool(enabled),
        match_mode=match_mode,
        pattern=pattern,
        agent_id=agent_id,
        username=username,
        target_user=target_user,
        notes=notes,
    )
    db.add(row)
    return row


def get_allowlist_rule(db: Session, rule_id: int) -> AttackChainAllowlistModel | None:
    return db.get(AttackChainAllowlistModel, int(rule_id))


def save_allowlist_rule(db: Session, row: AttackChainAllowlistModel) -> AttackChainAllowlistModel:
    db.add(row)
    return row


def delete_allowlist_rule(db: Session, row: AttackChainAllowlistModel) -> None:
    db.delete(row)


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()
