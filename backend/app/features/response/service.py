from __future__ import annotations

from datetime import datetime, timezone
import re

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.features.response import repository
from app.features.response.models import ResponseActionModel
from app.features.response.schemas import ResponseActionCreateIn

_ACTION_TYPE_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,31}$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_action_type(action_type: str) -> str:
    s = (action_type or "").strip().lower()
    if not _ACTION_TYPE_RE.match(s):
        raise HTTPException(status_code=422, detail="action_type is invalid")
    return s


def create_response_action(
    db: Session,
    *,
    payload: ResponseActionCreateIn,
    request,
    admin,
    audit_writer=write_audit_event,
) -> ResponseActionModel:
    action_type = _validate_action_type(payload.action_type)
    row_agent = repository.get_agent(db, agent_id=payload.agent_id)
    if not row_agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if bool(row_agent.is_revoked):
        raise HTTPException(status_code=403, detail="Agent is revoked")

    now = _utc_now()
    expires_at = payload.expires_at
    if expires_at is not None and expires_at <= now:
        raise HTTPException(status_code=422, detail="expires_at must be in the future")

    row = repository.create_action(
        db,
        action_type=action_type,
        agent_id=payload.agent_id,
        status="pending",
        payload=dict(payload.payload or {}),
        requested_by=admin.username,
        requested_at=now,
        expires_at=expires_at,
    )
    repository.flush(db)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="response.actions.create",
        resource_type="response_action",
        resource_id=str(row.id),
        outcome="success",
        before={},
        after={
            "id": row.id,
            "action_type": row.action_type,
            "agent_id": row.agent_id,
            "status": row.status,
            "requested_by": row.requested_by,
            "expires_at": (row.expires_at.isoformat() if row.expires_at else None),
        },
        context={
            "payload_keys": sorted(list((row.payload or {}).keys())) if isinstance(row.payload, dict) else [],
            "payload_size": len(row.payload or {}) if isinstance(row.payload, dict) else 0,
        },
    )
    repository.commit(db)
    repository.refresh(db, row)
    return row


def list_response_actions_by_status(
    db: Session,
    *,
    status: str,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[ResponseActionModel]:
    return repository.list_actions_by_status(db, status=status, agent_id=agent_id, limit=limit)


def update_response_action_status(
    db: Session,
    *,
    action_id: int,
    new_status: str,
) -> ResponseActionModel:
    row = repository.get_action(db, action_id=action_id)
    if not row:
        raise HTTPException(status_code=404, detail="Response action not found")
    row.status = str(new_status or "").strip().lower()
    repository.save_action(db, row)
    repository.commit(db)
    repository.refresh(db, row)
    return row
