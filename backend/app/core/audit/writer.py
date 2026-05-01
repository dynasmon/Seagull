from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.observability import request_id
from app.features.admin.models import AdminAuditEventModel


_SENSITIVE_TOKENS = (
    "password",
    "secret",
    "token",
    "key",
    "credential",
    "cookie",
    "authorization",
    "pepper",
    "hash",
    "jwt",
    "private",
)


@dataclass(frozen=True)
class AuditActor:
    user_id: int | None
    username: str | None


def audit_actor(user_id: int | None, username: str | None) -> AuditActor:
    return AuditActor(user_id=user_id, username=(username or None))


def _is_sensitive_key(key: str) -> bool:
    lk = (key or "").strip().lower()
    if not lk:
        return False
    return any(tok in lk for tok in _SENSITIVE_TOKENS)


def _truncate_text(v: str, max_len: int = 512) -> str:
    if len(v) <= max_len:
        return v
    return v[: max_len - 3] + "..."


def _sanitize(obj: Any, *, depth: int = 0, max_depth: int = 8) -> Any:
    if depth > max_depth:
        return "<max_depth>"
    if obj is None:
        return None
    if isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, str):
        return _truncate_text(obj, 2048)
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            key = str(k)
            if _is_sensitive_key(key):
                out[key] = "<redacted>"
            else:
                out[key] = _sanitize(v, depth=depth + 1, max_depth=max_depth)
        return out
    if isinstance(obj, (list, tuple, set)):
        items = list(obj)
        if len(items) > 200:
            items = items[:200]
        return [_sanitize(x, depth=depth + 1, max_depth=max_depth) for x in items]
    if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
        try:
            return _sanitize(obj.dict(), depth=depth + 1, max_depth=max_depth)
        except Exception:
            return _truncate_text(str(obj), 512)
    return _truncate_text(str(obj), 512)


def sanitize_for_audit(obj: Any) -> Any:
    return _sanitize(obj, depth=0, max_depth=8)


def changed_fields(before: Any, after: Any) -> list[str]:
    b = before if isinstance(before, dict) else {}
    a = after if isinstance(after, dict) else {}
    keys: set[str] = set(b.keys()) | set(a.keys())
    out: list[str] = []
    for k in sorted(keys):
        if b.get(k) != a.get(k):
            out.append(str(k))
    return out


def _request_meta(request: Request | None) -> dict[str, Any]:
    if request is None:
        return {"ip": None, "user_agent": None, "method": None, "path": None}
    ip = (request.client.host if request.client else "") or None
    ua = (request.headers.get("user-agent") or "")[:256] or None
    method = (request.method or "")[:16] or None
    path = (request.url.path or "")[:255] or None
    return {"ip": ip, "user_agent": ua, "method": method, "path": path}


def _stable_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


def _sign_payload(payload: Dict[str, Any], prev_hash: str | None) -> str:
    secret = (settings.SEAGULL_AUDIT_HASH_PEPPER or settings.token_pepper() or settings.SEAGULL_JWT_SECRET or "").strip()
    msg = _stable_json({"payload": payload, "prev_event_hash": prev_hash or ""}).encode("utf-8")
    if secret:
        return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


def _latest_event_hash(db: Session) -> str | None:
    row: AdminAuditEventModel | None = (
        db.query(AdminAuditEventModel)
        .order_by(AdminAuditEventModel.created_at.desc(), AdminAuditEventModel.id.desc())
        .first()
    )
    if not row:
        return None
    return (row.event_hash or "").strip() or None


def write_audit_event(
    db: Session,
    *,
    request: Request | None,
    actor: AuditActor,
    event_type: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    outcome: str,
    before: Any = None,
    after: Any = None,
    context: Any = None,
    reason: str | None = None,
    error: str | None = None,
    operation_id: str | None = None,
) -> AdminAuditEventModel:
    before_s = sanitize_for_audit(before if before is not None else {})
    after_s = sanitize_for_audit(after if after is not None else {})
    context_s = sanitize_for_audit(context if context is not None else {})
    fields = changed_fields(before_s, after_s)

    meta = _request_meta(request)
    rid = request_id() or None
    trace_id = None
    if request is not None:
        trace_id = (request.headers.get("x-trace-id") or request.headers.get("X-Trace-Id") or "").strip()[:128] or None

    payload = {
        "created_at": datetime.utcnow().isoformat(),
        "event_type": (event_type or "admin_action").strip()[:32] or "admin_action",
        "action": (action or "").strip()[:96],
        "outcome": (outcome or "success").strip()[:16],
        "actor_user_id": actor.user_id,
        "actor_username": (actor.username or None),
        "resource_type": (resource_type or "").strip()[:48],
        "resource_id": (resource_id or None),
        "request_id": rid,
        "trace_id": trace_id,
        "ip": meta["ip"],
        "user_agent": meta["user_agent"],
        "method": meta["method"],
        "path": meta["path"],
        "reason": (reason or None),
        "error": (error or None),
        "before": before_s,
        "after": after_s,
        "changed_fields": fields,
        "context": context_s,
        "schema_version": 1,
    }
    prev_hash = _latest_event_hash(db)
    ev_hash = _sign_payload(payload, prev_hash)

    row = AdminAuditEventModel(
        id=str(uuid.uuid4()),
        operation_id=(operation_id or None),
        created_at=datetime.utcnow(),
        event_type=payload["event_type"],
        action=payload["action"],
        outcome=payload["outcome"],
        actor_user_id=actor.user_id,
        actor_username=(actor.username or None),
        resource_type=payload["resource_type"],
        resource_id=(str(resource_id)[:128] if resource_id is not None else None),
        request_id=rid,
        trace_id=trace_id,
        ip=meta["ip"],
        user_agent=meta["user_agent"],
        method=meta["method"],
        path=meta["path"],
        reason=(reason[:255] if reason else None),
        error=(error[:255] if error else None),
        before=before_s if isinstance(before_s, dict) else {"value": before_s},
        after=after_s if isinstance(after_s, dict) else {"value": after_s},
        changed_fields=fields,
        context=context_s if isinstance(context_s, dict) else {"value": context_s},
        prev_event_hash=prev_hash,
        event_hash=ev_hash,
        schema_version=1,
    )
    db.add(row)
    return row


def mask_dict_keys(data: dict[str, Any], keys: Iterable[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    wanted = {str(k).strip().lower() for k in keys}
    for k, v in (data or {}).items():
        lk = str(k).strip().lower()
        if lk in wanted:
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out
