from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Sequence

from pydantic import BaseModel, ConfigDict
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.features.attack_chain.models import AttackChainCaseModel, AttackChainStepModel


class AttackChainCaseDTO(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    agent_id: str
    suspect_ip: str | None
    status: str
    score: int
    max_stage: str
    first_seen_at: datetime
    last_seen_at: datetime
    closed_at: datetime | None
    step_count: int
    context: dict[str, Any]


class AttackChainStepDTO(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    case_id: int
    stage: str
    label: str
    score_delta: int
    fingerprint: str
    event_id: int | None
    event_type: str | None
    timestamp: datetime
    created_at: datetime
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    proto: str | None
    details: dict[str, Any]


class AttackChainCaseSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    score: int
    max_stage: str
    step_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    suspect_ip: str | None


class AttackChainStepGraphSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    case_id: int
    stage: str
    label: str
    score_delta: int
    timestamp: datetime
    event_id: int | None
    event_type: str | None
    src_ip: str | None
    dst_ip: str | None
    proto: str | None
    details: dict[str, Any]


def _to_case_dto(row: AttackChainCaseModel) -> AttackChainCaseDTO:
    return AttackChainCaseDTO(
        id=row.id,
        agent_id=row.agent_id,
        suspect_ip=row.suspect_ip,
        status=row.status,
        score=row.score,
        max_stage=row.max_stage,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        closed_at=row.closed_at,
        step_count=row.step_count,
        context=row.context or {},
    )


def _to_step_dto(row: AttackChainStepModel) -> AttackChainStepDTO:
    return AttackChainStepDTO(
        id=row.id,
        case_id=row.case_id,
        stage=row.stage,
        label=row.label,
        score_delta=row.score_delta,
        fingerprint=row.fingerprint,
        event_id=row.event_id,
        event_type=row.event_type,
        timestamp=row.timestamp,
        created_at=row.created_at,
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        src_port=row.src_port,
        dst_port=row.dst_port,
        proto=row.proto,
        details=row.details or {},
    )


def list_cases_for_agent(db: Session, *, agent_id: str, open_only: bool, limit: int) -> list[AttackChainCaseDTO]:
    stmt = select(AttackChainCaseModel).where(AttackChainCaseModel.agent_id == agent_id)
    if open_only:
        stmt = stmt.where(AttackChainCaseModel.status == "open")
    stmt = stmt.order_by(
        AttackChainCaseModel.score.desc(),
        AttackChainCaseModel.last_seen_at.desc(),
        AttackChainCaseModel.id.desc(),
    )
    rows = db.execute(stmt.limit(max(1, int(limit)))).scalars().all()
    return [_to_case_dto(row) for row in rows]


def list_steps_for_cases(db: Session, *, case_ids: Iterable[int], limit: int) -> list[AttackChainStepDTO]:
    ids = [int(value) for value in case_ids if int(value) > 0]
    if not ids:
        return []
    stmt = (
        select(AttackChainStepModel)
        .where(AttackChainStepModel.case_id.in_(ids))
        .order_by(AttackChainStepModel.timestamp.desc(), AttackChainStepModel.id.desc())
        .limit(max(1, int(limit)))
    )
    return [_to_step_dto(row) for row in db.execute(stmt).scalars().all()]


def list_open_case_summaries_for_agent(
    db: Session,
    *,
    agent_id: str,
    limit: int,
    recency_tiebreak: bool = False,
) -> list[AttackChainCaseSummary]:
    stmt = select(
        AttackChainCaseModel.id,
        AttackChainCaseModel.score,
        AttackChainCaseModel.max_stage,
        AttackChainCaseModel.step_count,
        AttackChainCaseModel.first_seen_at,
        AttackChainCaseModel.last_seen_at,
        AttackChainCaseModel.suspect_ip,
    ).where(
        AttackChainCaseModel.agent_id == agent_id,
        AttackChainCaseModel.status == "open",
    )
    if recency_tiebreak:
        stmt = stmt.order_by(AttackChainCaseModel.score.desc(), AttackChainCaseModel.last_seen_at.desc())
    else:
        stmt = stmt.order_by(AttackChainCaseModel.score.desc())
    rows = db.execute(stmt.limit(limit)).mappings().all()
    return [
        AttackChainCaseSummary(
            id=r["id"],
            score=r["score"],
            max_stage=r["max_stage"],
            step_count=r["step_count"],
            first_seen_at=r["first_seen_at"],
            last_seen_at=r["last_seen_at"],
            suspect_ip=r["suspect_ip"],
        )
        for r in rows
    ]


def list_step_graph_summaries_for_cases(
    db: Session,
    *,
    case_ids: Iterable[int],
    limit: int,
) -> list[AttackChainStepGraphSummary]:
    ids = [int(value) for value in case_ids if int(value) > 0]
    if not ids:
        return []
    stmt = (
        select(
            AttackChainStepModel.id,
            AttackChainStepModel.case_id,
            AttackChainStepModel.stage,
            AttackChainStepModel.label,
            AttackChainStepModel.score_delta,
            AttackChainStepModel.timestamp,
            AttackChainStepModel.event_id,
            AttackChainStepModel.event_type,
            AttackChainStepModel.src_ip,
            AttackChainStepModel.dst_ip,
            AttackChainStepModel.proto,
            AttackChainStepModel.details,
        )
        .where(AttackChainStepModel.case_id.in_(ids))
        .order_by(AttackChainStepModel.timestamp.desc(), AttackChainStepModel.id.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).mappings().all()
    return [
        AttackChainStepGraphSummary(
            id=r["id"],
            case_id=r["case_id"],
            stage=r["stage"],
            label=r["label"],
            score_delta=r["score_delta"],
            timestamp=r["timestamp"],
            event_id=r["event_id"],
            event_type=r["event_type"],
            src_ip=r["src_ip"],
            dst_ip=r["dst_ip"],
            proto=r["proto"],
            details=r["details"] or {},
        )
        for r in rows
    ]


def list_recent_steps(db: Session, *, min_ts: datetime, limit: int) -> list[AttackChainStepDTO]:
    stmt = (
        select(AttackChainStepModel)
        .where(AttackChainStepModel.timestamp >= min_ts)
        .order_by(AttackChainStepModel.timestamp.desc(), AttackChainStepModel.id.desc())
        .limit(limit)
    )
    return [_to_step_dto(row) for row in db.execute(stmt).scalars().all()]


def list_recent_cases(db: Session, *, min_ts: datetime, limit: int) -> list[AttackChainCaseDTO]:
    stmt = (
        select(AttackChainCaseModel)
        .where(AttackChainCaseModel.last_seen_at >= min_ts)
        .order_by(AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc())
        .limit(limit)
    )
    return [_to_case_dto(row) for row in db.execute(stmt).scalars().all()]


def list_related_cases(
    db: Session,
    *,
    suspect_ips: Sequence[str],
    agent_ids: Sequence[str],
    limit: int = 10,
) -> list[AttackChainCaseDTO]:
    conditions = [AttackChainCaseModel.suspect_ip == ip for ip in suspect_ips if ip]
    conditions += [AttackChainCaseModel.agent_id == agent_id for agent_id in agent_ids if agent_id]
    if not conditions:
        return []
    stmt = (
        select(AttackChainCaseModel)
        .where(or_(*conditions))
        .order_by(AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return [_to_case_dto(row) for row in db.execute(stmt).scalars().all()]
