from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event
from app.features.response import service as _service
from app.features.response.models import ResponseActionModel, ResponseActionResultModel
from app.features.response.schemas import ResponseActionCreateIn


class ResponseActionDTO(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    action_type: str
    agent_id: str
    status: str
    batch_id: str | None
    payload: dict[str, Any]
    requested_by: str
    requested_at: datetime
    delivered_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    cancelled_at: datetime | None
    cancelled_by: str | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None


class ResponseActionResultSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    response_action_id: int
    status: str


class ResponseActionContextSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_id: int
    action_type: str
    status: str
    requested_at: datetime | None
    result_status: str | None


def _to_action_dto(row: ResponseActionModel) -> ResponseActionDTO:
    return ResponseActionDTO(
        id=int(row.id),
        action_type=row.action_type,
        agent_id=row.agent_id,
        status=row.status,
        batch_id=row.batch_id,
        payload=dict(row.payload or {}),
        requested_by=row.requested_by,
        requested_at=row.requested_at,
        delivered_at=row.delivered_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
        cancelled_at=row.cancelled_at,
        cancelled_by=row.cancelled_by,
        last_error=row.last_error,
        created_at=row.created_at,
        updated_at=row.updated_at,
        expires_at=row.expires_at,
    )


def _to_result_summary(row: ResponseActionResultModel) -> ResponseActionResultSummary:
    return ResponseActionResultSummary(
        id=int(row.id),
        response_action_id=int(row.response_action_id),
        status=row.status,
    )


def list_actions_for_agent(db: Session, *, agent_id: str, limit: int) -> list[ResponseActionDTO]:
    stmt = (
        select(ResponseActionModel)
        .where(ResponseActionModel.agent_id == agent_id)
        .order_by(ResponseActionModel.requested_at.desc(), ResponseActionModel.id.desc())
        .limit(max(1, int(limit)))
    )
    return [_to_action_dto(row) for row in db.execute(stmt).scalars().all()]


def latest_result_summaries_for_actions(
    db: Session,
    *,
    action_ids: Iterable[int],
) -> dict[int, ResponseActionResultSummary]:
    ids = [int(value) for value in action_ids if int(value) > 0]
    if not ids:
        return {}
    latest_rows = db.execute(
        select(
            ResponseActionResultModel.response_action_id,
            func.max(ResponseActionResultModel.id).label("latest_id"),
        )
        .where(ResponseActionResultModel.response_action_id.in_(ids))
        .group_by(ResponseActionResultModel.response_action_id)
    ).all()
    latest_ids = [int(row[1]) for row in latest_rows if row[1] is not None]
    if not latest_ids:
        return {}
    rows = db.execute(select(ResponseActionResultModel).where(ResponseActionResultModel.id.in_(latest_ids))).scalars().all()
    by_id = {int(row.id): row for row in rows}
    out: dict[int, ResponseActionResultSummary] = {}
    for action_id, latest_id in latest_rows:
        if latest_id is None:
            continue
        row = by_id.get(int(latest_id))
        if row is not None:
            out[int(action_id)] = _to_result_summary(row)
    return out


def list_recent_action_contexts_for_agent(
    db: Session,
    *,
    agent_id: str,
    max_actions: int = 5,
) -> list[ResponseActionContextSummary]:
    actions_stmt = (
        select(
            ResponseActionModel.id,
            ResponseActionModel.action_type,
            ResponseActionModel.status,
            ResponseActionModel.requested_at,
        )
        .where(ResponseActionModel.agent_id == agent_id)
        .order_by(ResponseActionModel.requested_at.desc(), ResponseActionModel.id.desc())
        .limit(max_actions)
    )
    actions = db.execute(actions_stmt).mappings().all()
    if not actions:
        return []

    action_ids = [int(row["id"]) for row in actions]
    result_stmt = (
        select(
            ResponseActionResultModel.response_action_id,
            func.max(ResponseActionResultModel.id).label("latest_result_id"),
        )
        .where(
            ResponseActionResultModel.agent_id == agent_id,
            ResponseActionResultModel.response_action_id.in_(action_ids),
        )
        .group_by(ResponseActionResultModel.response_action_id)
    )
    latest_rows = db.execute(result_stmt).mappings().all()
    latest_map = {int(row["response_action_id"]): int(row["latest_result_id"]) for row in latest_rows}

    result_status_map: dict[int, str] = {}
    if latest_map:
        status_stmt = select(
            ResponseActionResultModel.id,
            ResponseActionResultModel.status,
        ).where(ResponseActionResultModel.id.in_(list(latest_map.values())))
        for row in db.execute(status_stmt).mappings().all():
            result_status_map[int(row["id"])] = str(row.get("status") or "")

    out: list[ResponseActionContextSummary] = []
    for row in actions:
        action_id = int(row["id"])
        latest_id = latest_map.get(action_id)
        out.append(
            ResponseActionContextSummary(
                action_id=action_id,
                action_type=str(row.get("action_type") or ""),
                status=str(row.get("status") or ""),
                requested_at=row.get("requested_at"),
                result_status=result_status_map.get(latest_id) if latest_id else None,
            )
        )
    return out


def create_response_action(
    db: Session,
    *,
    payload: ResponseActionCreateIn,
    request,
    admin,
    audit_writer=write_audit_event,
) -> ResponseActionDTO:
    row = _service.create_response_action(
        db,
        payload=payload,
        request=request,
        admin=admin,
        audit_writer=audit_writer,
    )
    return _to_action_dto(row)
