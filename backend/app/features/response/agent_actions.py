from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.features.agents import profiles
from app.features.agents.auth import AgentPrincipal
from app.features.response import repository
from app.features.response.models import ResponseActionModel, ResponseActionResultModel
from app.features.response.realtime import publish_response_action_lifecycle
from app.features.response.schemas import AgentResponseActionResultIn


def _to_utc_naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def list_pending_actions(
    db: Session,
    *,
    request,
    agent: AgentPrincipal,
    audit_writer=write_audit_event,
) -> List[ResponseActionModel]:
    row_agent = repository.get_agent_by_id(db, agent.id)
    if not row_agent or row_agent.is_revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")
    if not profiles.allows_response_actions(profiles.of_agent(row_agent)):
        return []
    now = datetime.utcnow()
    rows = repository.list_pending_actions_for_agent(db, agent_id=agent.agent_id, limit=100, for_update=True)
    out: List[ResponseActionModel] = []
    lifecycle_events: list[tuple[ResponseActionModel, str]] = []
    for row in rows:
        expires_at = _to_utc_naive(row.expires_at)
        if expires_at is not None and expires_at <= now:
            row.status = "expired"
            row.finished_at = row.finished_at or now
            row.last_error = row.last_error or "action expired before execution"
            repository.save_action(db, row)
            lifecycle_events.append((row, "expired"))
            continue
        before_status = str(row.status or "").strip().lower()
        if before_status == "pending":
            before = {
                "id": row.id,
                "status": row.status,
                "action_type": row.action_type,
                "agent_id": row.agent_id,
            }
            row.status = "delivered"
            row.delivered_at = row.delivered_at or now
            repository.save_action(db, row)
            audit_writer(
                db,
                request=request,
                actor=audit_actor(None, None),
                event_type="admin_action",
                action="response.actions.delivered",
                resource_type="response_action",
                resource_id=str(row.id),
                outcome="success",
                before=before,
                after={
                    "id": row.id,
                    "status": row.status,
                    "action_type": row.action_type,
                    "agent_id": row.agent_id,
                    "delivered_at": row.delivered_at.isoformat() if row.delivered_at else None,
                },
                context={"reported_by_agent_id": agent.agent_id, "requested_by": row.requested_by},
            )
            lifecycle_events.append((row, "delivered"))
        out.append(row)
    repository.commit(db)
    for row, lifecycle_event in lifecycle_events:
        repository.refresh(db, row)
        publish_response_action_lifecycle(action=row, lifecycle_event=lifecycle_event)
    return out


def report_action_result(
    db: Session,
    *,
    payload: AgentResponseActionResultIn,
    request,
    agent: AgentPrincipal,
    audit_writer=write_audit_event,
) -> dict:
    row_agent = repository.get_agent_by_id(db, agent.id)
    if not row_agent or row_agent.is_revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")
    row_action = repository.get_action(db, action_id=payload.response_action_id, for_update=True)
    if not row_action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Response action not found")
    if row_action.agent_id != agent.agent_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Response action does not belong to this agent")
    if payload.agent_id is not None and payload.agent_id != agent.agent_id:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="agent_id mismatch")
    current_status = str(row_action.status or "").strip().lower()
    if current_status in {"cancelled", "expired"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Response action is not executable")

    result_payload: Dict[str, Any] = dict(payload.result_payload or {})
    before_action_status = row_action.status
    now = datetime.utcnow()
    latest = repository.get_latest_result_for_agent(
        db,
        action_id=row_action.id,
        agent_id=agent.agent_id,
    )
    if latest is None:
        latest = ResponseActionResultModel(response_action_id=row_action.id, agent_id=agent.agent_id)
    latest.status = payload.status
    latest.result_payload = result_payload
    latest.error = payload.error
    latest.started_at = payload.started_at
    latest.finished_at = payload.finished_at
    repository.save_result(db, latest)

    if payload.status == "running":
        row_action.status = "running"
        row_action.delivered_at = row_action.delivered_at or now
        row_action.started_at = payload.started_at or row_action.started_at or now
        repository.save_action(db, row_action)
    elif payload.status in {"success", "failed"}:
        row_action.status = payload.status
        row_action.delivered_at = row_action.delivered_at or now
        row_action.started_at = payload.started_at or row_action.started_at or now
        row_action.finished_at = payload.finished_at or now
        row_action.last_error = payload.error if payload.status == "failed" else None
        repository.save_action(db, row_action)
    if payload.status == "failed" and before_action_status != "failed":
        audit_writer(
            db,
            request=request,
            actor=audit_actor(None, None),
            event_type="admin_action",
            action="response.actions.failed",
            resource_type="response_action",
            resource_id=str(row_action.id),
            outcome="failure",
            reason="action_execution_failed",
            error=(payload.error or None),
            before={
                "id": row_action.id,
                "status": before_action_status,
                "action_type": row_action.action_type,
                "agent_id": row_action.agent_id,
            },
            after={
                "id": row_action.id,
                "status": row_action.status,
                "action_type": row_action.action_type,
                "agent_id": row_action.agent_id,
            },
            context={"result_status": payload.status, "reported_by_agent_id": agent.agent_id},
        )
    repository.commit(db)
    repository.refresh(db, row_action)
    repository.refresh(db, latest)
    lifecycle_event = {
        "running": "started" if before_action_status != "running" else "heartbeat",
        "success": "completed",
        "failed": "failed",
    }.get(str(payload.status or "").strip().lower(), "heartbeat")
    publish_response_action_lifecycle(action=row_action, lifecycle_event=lifecycle_event, result=latest)
    return {"status": row_action.status}
