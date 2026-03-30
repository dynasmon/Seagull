from __future__ import annotations

from datetime import datetime, timezone
import re

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.audit import audit_actor, write_audit_event
from app.core.db import SessionLocal
from app.core.portal_auth import PortalPrincipal, require_admin
from app.features.agents.models import AgentModel
from app.features.response.models import ResponseActionModel
from app.features.response.schemas import ResponseActionCreateIn, ResponseActionOut


router = APIRouter(prefix="/response", tags=["response"])

_ACTION_TYPE_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,31}$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_action_type(action_type: str) -> str:
    s = (action_type or "").strip().lower()
    if not _ACTION_TYPE_RE.match(s):
        raise HTTPException(status_code=422, detail="action_type is invalid")
    return s


@router.post("/actions", response_model=ResponseActionOut, status_code=status.HTTP_201_CREATED)
def create_response_action(
    payload: ResponseActionCreateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
):
    db = SessionLocal()
    try:
        action_type = _validate_action_type(payload.action_type)
        row_agent: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == payload.agent_id).first()
        if not row_agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        if bool(row_agent.is_revoked):
            raise HTTPException(status_code=403, detail="Agent is revoked")

        now = _utc_now()
        expires_at = payload.expires_at
        if expires_at is not None and expires_at <= now:
            raise HTTPException(status_code=422, detail="expires_at must be in the future")

        row = ResponseActionModel(
            action_type=action_type,
            agent_id=payload.agent_id,
            status="pending",
            payload=dict(payload.payload or {}),
            requested_by=admin.username,
            requested_at=now,
            expires_at=expires_at,
        )
        db.add(row)
        db.flush()

        write_audit_event(
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
        db.commit()
        db.refresh(row)
        return row
    finally:
        db.close()
