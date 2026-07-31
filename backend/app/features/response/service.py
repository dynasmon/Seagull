from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.features.agents import profiles
from app.features.response import repository
from app.features.response.models import ResponseActionModel, ResponseActionResultModel
from app.features.response.realtime import publish_response_action_lifecycle
from app.features.response.registry import ACTION_REGISTRY, action_catalog
from app.features.response.schemas import BatchDispatchIn, ResponseActionCreateIn

_ACTION_TYPE_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,31}$")
_RUNNABLE_STATUSES = {"pending", "delivered"}

_SHELL_EXEC_ACTION_TYPE = "run_shell_command"
_SHELL_EXEC_RATE_WINDOW = timedelta(minutes=5)
_SHELL_EXEC_RATE_MAX = 3
_SHELL_EXEC_RATE_STATUSES = ["pending", "delivered"]


def _shell_exec_rate_exceeded(db: Session, *, agent_id: str, now: datetime) -> bool:
    recent = repository.count_recent_actions(
        db,
        agent_id=agent_id,
        action_type=_SHELL_EXEC_ACTION_TYPE,
        since=now - _SHELL_EXEC_RATE_WINDOW,
        statuses=_SHELL_EXEC_RATE_STATUSES,
    )
    return recent >= _SHELL_EXEC_RATE_MAX


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _normalize_action_type(action_type: str) -> str:
    s = (action_type or "").strip().lower()
    if not _ACTION_TYPE_RE.match(s):
        raise HTTPException(status_code=422, detail="action_type is invalid")
    return s


def _validate_payload_for_action(action_type: str, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    definition = ACTION_REGISTRY.get(action_type)
    if definition is None:
        raise HTTPException(status_code=422, detail="action_type is not supported")
    return definition.validate_payload(raw_payload)


def _action_types_for(category: str | None, risk_level: str | None) -> list[str] | None:
    c = (category or "").strip().lower() or None
    r = (risk_level or "").strip().lower() or None
    if c is None and r is None:
        return None
    return [
        key
        for key, definition in ACTION_REGISTRY.items()
        if (c is None or definition.category == c) and (r is None or definition.risk_level == r)
    ]


def list_action_types() -> List[Dict[str, Any]]:
    return action_catalog()


def _apply_expired_status(row: ResponseActionModel, *, now: datetime) -> bool:
    status = str(row.status or "").strip().lower()
    if status not in _RUNNABLE_STATUSES:
        return False
    expires_at = _to_utc(row.expires_at)
    if expires_at is None or expires_at > now:
        return False
    row.status = "expired"
    row.finished_at = row.finished_at or now
    if not (row.last_error or "").strip():
        row.last_error = "action expired before execution"
    return True


def _apply_expired_statuses(db: Session, rows: list[ResponseActionModel], *, now: datetime) -> None:
    changed = False
    for row in rows:
        if _apply_expired_status(row, now=now):
            repository.save_action(db, row)
            changed = True
    if changed:
        repository.commit(db)


def create_response_action(
    db: Session,
    *,
    payload: ResponseActionCreateIn,
    request,
    admin,
    audit_writer=write_audit_event,
) -> ResponseActionModel:
    action_type = _normalize_action_type(payload.action_type)
    row_agent = repository.get_agent(db, agent_id=payload.agent_id)
    if not row_agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if bool(row_agent.is_revoked):
        raise HTTPException(status_code=403, detail="Agent is revoked")
    profiles.require_response_action_capable(
        row_agent,
        agent_id=payload.agent_id,
        action_type=action_type,
    )

    now = _utc_now()
    expires_at = _to_utc(payload.expires_at)
    if expires_at is not None and expires_at <= now:
        raise HTTPException(status_code=422, detail="expires_at must be in the future")
    normalized_payload = _validate_payload_for_action(action_type, dict(payload.payload or {}))

    if action_type == _SHELL_EXEC_ACTION_TYPE and _shell_exec_rate_exceeded(db, agent_id=payload.agent_id, now=now):
        raise HTTPException(status_code=429, detail="Too many shell exec actions queued for this agent")

    row = repository.create_action(
        db,
        action_type=action_type,
        agent_id=payload.agent_id,
        status="pending",
        payload=normalized_payload,
        requested_by=admin.username,
        requested_at=now,
        expires_at=expires_at,
    )
    repository.flush(db)
    audit_context: Dict[str, Any] = {
        "payload_keys": sorted(list((row.payload or {}).keys())) if isinstance(row.payload, dict) else [],
        "payload_size": len(row.payload or {}) if isinstance(row.payload, dict) else 0,
    }
    if payload.justification:
        audit_context["justification"] = payload.justification
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
        context=audit_context,
    )
    repository.commit(db)
    repository.refresh(db, row)
    publish_response_action_lifecycle(action=row, lifecycle_event="queued")
    return row


def create_response_action_batch(
    db: Session,
    *,
    payload: BatchDispatchIn,
    request,
    admin,
    audit_writer=write_audit_event,
) -> Dict[str, Any]:
    action_type = _normalize_action_type(payload.action_type)
    if action_type not in ACTION_REGISTRY:
        raise HTTPException(status_code=422, detail="action_type is not supported")

    agent_ids: list[str] = []
    seen: set[str] = set()
    for raw_agent_id in payload.agent_ids or []:
        candidate = str(raw_agent_id or "").strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            agent_ids.append(candidate)
    if not agent_ids:
        raise HTTPException(status_code=422, detail="agent_ids must not be empty")

    now = _utc_now()
    expires_at = _to_utc(payload.expires_at)
    if expires_at is not None and expires_at <= now:
        raise HTTPException(status_code=422, detail="expires_at must be in the future")
    normalized_payload = _validate_payload_for_action(action_type, dict(payload.payload or {}))

    batch_id = f"batch_{now:%Y%m%d}_{uuid.uuid4().hex[:8]}"
    created_rows: list[ResponseActionModel] = []
    skipped: list[Dict[str, str]] = []
    for agent_id in agent_ids:
        row_agent = repository.get_agent(db, agent_id=agent_id)
        if not row_agent:
            skipped.append({"agent_id": agent_id, "reason": "not_found"})
            continue
        if bool(row_agent.is_revoked):
            skipped.append({"agent_id": agent_id, "reason": "revoked"})
            continue
        supported, unsupported_reason = profiles.response_action_support(
            row_agent,
            action_type=action_type,
        )
        if not supported:
            skipped.append({"agent_id": agent_id, "reason": unsupported_reason})
            continue
        if action_type == _SHELL_EXEC_ACTION_TYPE and _shell_exec_rate_exceeded(db, agent_id=agent_id, now=now):
            skipped.append({"agent_id": agent_id, "reason": "rate_limited"})
            continue
        created_rows.append(
            repository.create_action(
                db,
                action_type=action_type,
                agent_id=agent_id,
                status="pending",
                payload=normalized_payload,
                requested_by=admin.username,
                requested_at=now,
                expires_at=expires_at,
                batch_id=batch_id,
            )
        )
    repository.flush(db)

    queued = [{"agent_id": row.agent_id, "action_id": row.id} for row in created_rows]
    audit_context: Dict[str, Any] = {"agent_ids": agent_ids, "skipped": skipped}
    if payload.justification:
        audit_context["justification"] = payload.justification
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="response.actions.batch_create",
        resource_type="response_action",
        resource_id=batch_id,
        outcome="success",
        before={},
        after={
            "batch_id": batch_id,
            "action_type": action_type,
            "total": len(agent_ids),
            "queued": len(created_rows),
            "skipped": len(skipped),
        },
        context=audit_context,
    )
    repository.commit(db)
    for row in created_rows:
        repository.refresh(db, row)
        publish_response_action_lifecycle(action=row, lifecycle_event="queued")

    return {"batch_id": batch_id, "total": len(agent_ids), "queued": queued, "skipped": skipped}


def list_response_actions(
    db: Session,
    *,
    agent_id: str | None = None,
    agent_ids: list[str] | None = None,
    status: str | None = None,
    category: str | None = None,
    risk_level: str | None = None,
    batch_id: str | None = None,
    since: datetime | None = None,
    limit: int = 100,
) -> list[ResponseActionModel]:
    rows = repository.list_actions(
        db,
        agent_id=(agent_id or None),
        agent_ids=(agent_ids or None),
        status=(status or None),
        action_types=_action_types_for(category, risk_level),
        batch_id=(batch_id or None),
        since=_to_utc(since),
        limit=max(1, min(int(limit), 500)),
    )
    _apply_expired_statuses(db, rows, now=_utc_now())
    return rows


def get_response_action(
    db: Session,
    *,
    action_id: int,
) -> ResponseActionModel:
    row = repository.get_action(db, action_id=action_id)
    if not row:
        raise HTTPException(status_code=404, detail="Response action not found")
    if _apply_expired_status(row, now=_utc_now()):
        repository.save_action(db, row)
        repository.commit(db)
        repository.refresh(db, row)
    return row


def build_action_timeline(row: ResponseActionModel) -> List[Dict[str, Any]]:
    agent_actor = f"agent/{row.agent_id}"
    events: list[Dict[str, Any]] = []

    def add(at: datetime | None, event: str, actor: str | None, detail: str | None = None) -> None:
        if at is None:
            return
        events.append({"at": _to_utc(at), "event": event, "actor": (actor or "system"), "detail": detail})

    add(row.requested_at, "queued", row.requested_by)
    add(row.delivered_at, "delivered", agent_actor)
    add(row.started_at, "started", agent_actor)

    status = str(row.status or "").strip().lower()
    if status == "success":
        add(row.finished_at, "completed", agent_actor)
    elif status == "failed":
        add(row.finished_at, "failed", agent_actor, row.last_error)
    elif status == "cancelled":
        add(row.cancelled_at or row.finished_at, "cancelled", row.cancelled_by)
    elif status == "expired":
        add(row.finished_at, "expired", "system", row.last_error)

    events.sort(key=lambda e: e["at"])
    return events


def get_response_action_timeline(
    db: Session,
    *,
    action_id: int,
) -> List[Dict[str, Any]]:
    row = get_response_action(db, action_id=action_id)
    return build_action_timeline(row)


def get_latest_response_action_result(
    db: Session,
    *,
    action_id: int,
) -> ResponseActionResultModel:
    row = repository.get_action(db, action_id=action_id)
    if not row:
        raise HTTPException(status_code=404, detail="Response action not found")
    result = repository.get_latest_result(db, action_id=action_id)
    if not result:
        raise HTTPException(status_code=404, detail="Response action result not found")
    return result


def cancel_response_action(
    db: Session,
    *,
    action_id: int,
    request,
    admin,
    audit_writer=write_audit_event,
) -> ResponseActionModel:
    row = repository.get_action(db, action_id=action_id, for_update=True)
    if not row:
        raise HTTPException(status_code=404, detail="Response action not found")
    if _apply_expired_status(row, now=_utc_now()):
        repository.save_action(db, row)
        repository.commit(db)
        repository.refresh(db, row)

    status = str(row.status or "").strip().lower()
    if status not in {"pending", "delivered"}:
        raise HTTPException(status_code=409, detail="Only pending or delivered actions can be cancelled")

    now = _utc_now()
    before = {
        "id": row.id,
        "status": row.status,
        "delivered_at": row.delivered_at.isoformat() if row.delivered_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
    }
    row.status = "cancelled"
    row.cancelled_at = now
    row.cancelled_by = admin.username
    row.finished_at = row.finished_at or now
    repository.save_action(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="response.actions.cancel",
        resource_type="response_action",
        resource_id=str(row.id),
        outcome="success",
        before=before,
        after={
            "id": row.id,
            "status": row.status,
            "cancelled_at": row.cancelled_at.isoformat() if row.cancelled_at else None,
            "cancelled_by": row.cancelled_by,
        },
    )
    repository.commit(db)
    repository.refresh(db, row)
    publish_response_action_lifecycle(action=row, lifecycle_event="cancelled")
    return row
