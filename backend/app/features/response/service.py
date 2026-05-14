from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.features.response import repository
from app.features.response.models import ResponseActionModel, ResponseActionResultModel
from app.features.response.realtime import publish_response_action_lifecycle
from app.features.response.schemas import ResponseActionCreateIn

_ACTION_TYPE_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,31}$")
_RUNNABLE_STATUSES = {"pending", "delivered"}


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


def _as_dict(v: Any, field: str) -> Dict[str, Any]:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise HTTPException(status_code=422, detail=f"{field} must be an object")
    return dict(v)


def _as_bool(v: Any, field: str) -> bool:
    if isinstance(v, bool):
        return v
    raise HTTPException(status_code=422, detail=f"{field} must be a boolean")


def _as_int(v: Any, field: str, *, min_value: int, max_value: int) -> int:
    if isinstance(v, bool):
        raise HTTPException(status_code=422, detail=f"{field} must be an integer")
    try:
        n = int(v)
    except Exception:
        raise HTTPException(status_code=422, detail=f"{field} must be an integer") from None
    if n < min_value or n > max_value:
        raise HTTPException(status_code=422, detail=f"{field} must be between {min_value} and {max_value}")
    return n


def _validate_collect_triage_bundle_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    allowed_root = {"collectors", "limits", "redaction"}
    unknown = sorted([k for k in payload.keys() if k not in allowed_root])
    if unknown:
        raise HTTPException(status_code=422, detail=f"payload has unsupported keys: {', '.join(unknown)}")

    out: Dict[str, Any] = {}

    collectors_in = _as_dict(payload.get("collectors"), "payload.collectors")
    collectors_allowed = {
        "runtime",
        "host",
        "processes",
        "network",
        "auth_log",
        "recent_events",
        "effective_config",
    }
    collectors_unknown = sorted([k for k in collectors_in.keys() if k not in collectors_allowed])
    if collectors_unknown:
        raise HTTPException(
            status_code=422,
            detail=f"payload.collectors has unsupported keys: {', '.join(collectors_unknown)}",
        )
    out["collectors"] = {
        "runtime": _as_bool(collectors_in.get("runtime", True), "payload.collectors.runtime"),
        "host": _as_bool(collectors_in.get("host", True), "payload.collectors.host"),
        "processes": _as_bool(collectors_in.get("processes", True), "payload.collectors.processes"),
        "network": _as_bool(collectors_in.get("network", True), "payload.collectors.network"),
        "auth_log": _as_bool(collectors_in.get("auth_log", True), "payload.collectors.auth_log"),
        "recent_events": _as_bool(collectors_in.get("recent_events", True), "payload.collectors.recent_events"),
        "effective_config": _as_bool(
            collectors_in.get("effective_config", True),
            "payload.collectors.effective_config",
        ),
    }

    limits_in = _as_dict(payload.get("limits"), "payload.limits")
    out["limits"] = {
        "max_auth_log_lines": _as_int(
            limits_in.get("max_auth_log_lines", 500),
            "payload.limits.max_auth_log_lines",
            min_value=10,
            max_value=5000,
        ),
        "max_processes": _as_int(
            limits_in.get("max_processes", 200),
            "payload.limits.max_processes",
            min_value=10,
            max_value=2000,
        ),
        "max_connections": _as_int(
            limits_in.get("max_connections", 200),
            "payload.limits.max_connections",
            min_value=10,
            max_value=2000,
        ),
        "max_event_count": _as_int(
            limits_in.get("max_event_count", 300),
            "payload.limits.max_event_count",
            min_value=10,
            max_value=5000,
        ),
    }

    redaction_in = _as_dict(payload.get("redaction"), "payload.redaction")
    out["redaction"] = {
        "mask_secrets": _as_bool(redaction_in.get("mask_secrets", True), "payload.redaction.mask_secrets"),
    }
    return out


def _validate_refresh_runtime_config_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    if payload:
        unknown = ", ".join(sorted(payload.keys()))
        raise HTTPException(
            status_code=422,
            detail=f"payload has unsupported keys for refresh_runtime_config: {unknown}",
        )
    return {}


def _validate_trigger_inventory_snapshot_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = _as_dict(raw_payload, "payload")
    allowed_root = {"limits"}
    unknown = sorted([k for k in payload.keys() if k not in allowed_root])
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"payload has unsupported keys: {', '.join(unknown)}",
        )
    limits_in = _as_dict(payload.get("limits"), "payload.limits")
    limits_unknown = sorted([k for k in limits_in.keys() if k not in {"max_processes", "max_connections"}])
    if limits_unknown:
        raise HTTPException(
            status_code=422,
            detail=f"payload.limits has unsupported keys: {', '.join(limits_unknown)}",
        )
    return {
        "limits": {
            "max_processes": _as_int(
                limits_in.get("max_processes", 200),
                "payload.limits.max_processes",
                min_value=10,
                max_value=2000,
            ),
            "max_connections": _as_int(
                limits_in.get("max_connections", 200),
                "payload.limits.max_connections",
                min_value=10,
                max_value=2000,
            ),
        }
    }


_ACTION_PAYLOAD_VALIDATORS: dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "collect_triage_bundle": _validate_collect_triage_bundle_payload,
    "refresh_runtime_config": _validate_refresh_runtime_config_payload,
    "trigger_inventory_snapshot": _validate_trigger_inventory_snapshot_payload,
}


def _validate_payload_for_action(action_type: str, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    validator = _ACTION_PAYLOAD_VALIDATORS.get(action_type)
    if validator is None:
        raise HTTPException(status_code=422, detail="action_type is not supported")
    return validator(raw_payload)


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

    now = _utc_now()
    expires_at = _to_utc(payload.expires_at)
    if expires_at is not None and expires_at <= now:
        raise HTTPException(status_code=422, detail="expires_at must be in the future")
    normalized_payload = _validate_payload_for_action(action_type, dict(payload.payload or {}))

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
    publish_response_action_lifecycle(action=row, lifecycle_event="queued")
    return row


def list_response_actions(
    db: Session,
    *,
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[ResponseActionModel]:
    rows = repository.list_actions(
        db,
        agent_id=(agent_id or None),
        status=(status or None),
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


def list_response_actions_by_status(
    db: Session,
    *,
    status: str,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[ResponseActionModel]:
    return list_response_actions(db, status=status, agent_id=agent_id, limit=limit)


def update_response_action_status(
    db: Session,
    *,
    action_id: int,
    new_status: str,
) -> ResponseActionModel:
    row = repository.get_action(db, action_id=action_id, for_update=True)
    if not row:
        raise HTTPException(status_code=404, detail="Response action not found")
    before = str(row.status or "").strip().lower()
    after = str(new_status or "").strip().lower()
    if before == after:
        return row
    row.status = after
    now = _utc_now()
    if after == "delivered":
        row.delivered_at = row.delivered_at or now
    elif after == "running":
        row.started_at = row.started_at or now
        row.delivered_at = row.delivered_at or now
    elif after in {"success", "failed", "expired", "cancelled"}:
        row.finished_at = row.finished_at or now
    repository.save_action(db, row)
    repository.commit(db)
    repository.refresh(db, row)
    lifecycle_event = {
        "delivered": "delivered",
        "running": "started",
        "success": "completed",
        "failed": "failed",
        "expired": "expired",
        "cancelled": "cancelled",
    }.get(after, "heartbeat")
    publish_response_action_lifecycle(action=row, lifecycle_event=lifecycle_event)
    return row
