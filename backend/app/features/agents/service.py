from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.agent_auth import (
    AgentPrincipal,
    generate_agent_credential,
    generate_bootstrap_token,
    hash_bootstrap_token,
)
from app.core.audit import audit_actor, write_audit_event
from app.core.config import settings
from app.core.observability import incr_counter
from app.core.portal_auth import PortalPrincipal
from app.features.agents import repository
from app.features.agents.models import AgentBootstrapTokenModel, AgentCredentialModel, AgentModel
from app.features.realtime.projectors import project_agent_presence_patch
from app.features.realtime.service import publish_realtime
from app.features.agents.schemas import (
    AgentBootstrapTokenCreateIn,
    AgentBootstrapTokenOut,
    AgentConfigUpdateIn,
    AgentCredentialOut,
    AgentDetail,
    AgentEnrollIn,
    AgentEnrollOut,
    AgentHeartbeatIn,
    AgentPublic,
    AgentUpdateIn,
)
from app.features.response.models import ResponseActionModel, ResponseActionResultModel
from app.features.response.realtime import publish_response_action_lifecycle
from app.features.response.schemas import AgentResponseActionResultIn

_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$")


def _to_utc_naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _normalize_tags(tags: Optional[List[str]]) -> List[str]:
    if not tags:
        return []
    out: List[str] = []
    seen = set()
    for t in tags:
        if t is None:
            continue
        s = str(t).strip()
        if not s:
            continue
        if not _TAG_RE.match(s):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= 50:
            break
    return out


def _safe_json_size(obj: Any, max_bytes: int, field_name: str) -> None:
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"{field_name} exceeds {max_bytes} bytes",
        )


def _build_agent_heartbeat_payload(*, row: AgentModel, status_text: str) -> Dict[str, Any]:
    return project_agent_presence_patch(
        agent_id=str(row.agent_id or "").strip(),
        status=str(status_text or "").strip()[:32],
        is_revoked=bool(row.is_revoked),
        last_seen_at=row.last_seen_at.isoformat() if row.last_seen_at is not None else None,
    )


def _publish_agent_heartbeat_realtime(*, row: AgentModel, status_text: str) -> None:
    payload = _build_agent_heartbeat_payload(row=row, status_text=status_text)
    if not payload.get("agent_id"):
        return
    try:
        publish_realtime("ui.agents.presence.patch", payload)
    except Exception:
        return


def _agent_to_public(a: AgentModel) -> AgentPublic:
    tags = a.tags if isinstance(a.tags, list) else []
    tags = [str(x) for x in tags if x is not None]
    metadata = a.agent_metadata if isinstance(a.agent_metadata, dict) else {}
    metrics = a.metrics if isinstance(a.metrics, dict) else {}
    return AgentPublic(
        agent_id=a.agent_id,
        display_name=a.display_name,
        description=a.description,
        tags=tags,
        created_at=a.created_at,
        last_seen_at=a.last_seen_at,
        is_revoked=a.is_revoked,
        metadata=metadata,
        metrics=metrics,
    )


def _agent_to_detail(a: AgentModel) -> AgentDetail:
    pub = _agent_to_public(a)
    return AgentDetail(**pub.dict(), config=a.config or {})


def _credential_overlap_until(now: datetime | None = None) -> datetime:
    base = now or datetime.utcnow()
    overlap_seconds = max(0, int(settings.SEAGULL_AGENT_CREDENTIAL_OVERLAP_SECONDS or 0))
    return base + timedelta(seconds=overlap_seconds)


def _consume_bootstrap_token(db: Session, agent_id: str, raw_token: str) -> AgentBootstrapTokenModel:
    now = datetime.utcnow()
    candidates = repository.list_active_bootstrap_tokens_for_update(db, agent_id)
    for tok in candidates:
        got = hash_bootstrap_token(raw_token, tok.token_salt)
        if not secrets.compare_digest(got, tok.token_hash):
            continue
        if tok.expires_at <= now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bootstrap token expired")
        if int(tok.used_uses or 0) >= int(tok.max_uses or 1):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bootstrap token already consumed")
        tok.used_uses = int(tok.used_uses or 0) + 1
        tok.last_used_at = now
        if int(tok.used_uses or 0) >= int(tok.max_uses or 1):
            tok.revoked_at = now
            tok.revoked_reason = "consumed"
        repository.save_bootstrap_token(db, tok)
        incr_counter("agent_bootstrap_token_consumed_total", token_type=str(tok.token_type or "enrollment"))
        return tok
    incr_counter("agent_bootstrap_token_consumed_total", outcome="invalid")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bootstrap token")


def _revoke_active_credentials(
    db: Session,
    agent_id: str,
    reason: str,
    *,
    rotated_at: datetime | None = None,
    overlap_until: datetime | None = None,
) -> None:
    active = repository.list_active_credentials(db, agent_id)
    now = datetime.utcnow()
    for row in active:
        row.revoked_at = overlap_until if overlap_until is not None else now
        row.rotated_at = rotated_at
        row.revoked_reason = reason
        repository.save_credential(db, row)


def _revoke_active_bootstrap_tokens(db: Session, agent_id: str, reason: str, *, token_type: str | None = None) -> None:
    active = repository.list_active_bootstrap_tokens_for_update(db, agent_id, token_type=token_type)
    now = datetime.utcnow()
    for row in active:
        row.revoked_at = now
        row.revoked_reason = reason
        repository.save_bootstrap_token(db, row)


def _prune_active_renewal_tokens(db: Session, agent_id: str) -> None:
    active = repository.list_active_renewal_tokens_for_update(db, agent_id)
    if not active:
        return
    keep = max(1, int(settings.SEAGULL_AGENT_RENEWAL_TOKEN_MAX_ACTIVE or 1))
    now = datetime.utcnow()
    for idx, row in enumerate(active):
        if row.expires_at <= now:
            row.revoked_at = now
            row.revoked_reason = "expired"
            repository.save_bootstrap_token(db, row)
            continue
        if idx >= keep:
            row.revoked_at = now
            row.revoked_reason = "superseded"
            repository.save_bootstrap_token(db, row)


def _issue_agent_credential(
    db: Session,
    *,
    agent_id: str,
    issued_from_bootstrap_token_id: int | None,
    replaces_credential_id: int | None,
) -> tuple[str, AgentCredentialModel]:
    ttl_seconds = max(300, int(settings.SEAGULL_AGENT_CREDENTIAL_TTL_SECONDS or 0))
    max_uses = max(1, int(settings.SEAGULL_AGENT_CREDENTIAL_MAX_USES or 0))
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    credential, salt, credential_hash = generate_agent_credential(agent_id)
    row = AgentCredentialModel(
        agent_id=agent_id,
        credential_salt=salt,
        credential_hash=credential_hash,
        expires_at=expires_at,
        max_uses=max_uses,
        used_uses=0,
        issued_from_bootstrap_token_id=issued_from_bootstrap_token_id,
        replaces_credential_id=replaces_credential_id,
    )
    repository.save_credential(db, row)
    repository.flush(db)
    return credential, row


def _issue_bootstrap_token(
    db: Session,
    *,
    agent_id: str,
    token_type: str,
    expires_at: datetime,
    max_uses: int,
    created_by_user_id: int | None = None,
    description: str | None = None,
) -> tuple[str, AgentBootstrapTokenModel]:
    token, salt, token_hash = generate_bootstrap_token(agent_id)
    row = AgentBootstrapTokenModel(
        agent_id=agent_id,
        token_salt=salt,
        token_hash=token_hash,
        token_type=token_type,
        expires_at=expires_at,
        max_uses=max_uses,
        used_uses=0,
        created_by_user_id=created_by_user_id,
        description=description,
    )
    repository.save_bootstrap_token(db, row)
    repository.flush(db)
    incr_counter("agent_bootstrap_token_issued_total", token_type=token_type)
    return token, row


def _issue_renewal_token(db: Session, *, agent_id: str) -> tuple[str, AgentBootstrapTokenModel]:
    ttl_seconds = max(3600, int(settings.SEAGULL_AGENT_RENEWAL_TOKEN_TTL_SECONDS or 0))
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    token, row = _issue_bootstrap_token(
        db,
        agent_id=agent_id,
        token_type="renewal",
        expires_at=expires_at,
        max_uses=1,
        description="agent-self-renewal",
    )
    _prune_active_renewal_tokens(db, agent_id)
    return token, row


def create_bootstrap_token(
    db: Session,
    *,
    agent_id: str,
    payload: AgentBootstrapTokenCreateIn,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> AgentBootstrapTokenOut:
    ttl_seconds = int(payload.ttl_seconds or settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS)
    max_uses = int(payload.max_uses or settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES)
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        default_cfg = settings.default_agent_config()
        if len(json.dumps(default_cfg, separators=(",", ":")).encode("utf-8")) > settings.SEAGULL_MAX_AGENT_CONFIG_BYTES:
            default_cfg = {}
        row = AgentModel(
            agent_id=agent_id,
            agent_metadata={},
            display_name=agent_id[:128],
            description=None,
            tags=[],
            config=default_cfg,
            metrics={},
            created_at=datetime.utcnow(),
            last_seen_at=None,
            is_revoked=False,
        )
        repository.save_agent(db, row)

    _revoke_active_bootstrap_tokens(db, agent_id, "superseded_by_admin_issue", token_type="enrollment")
    token, _rec = _issue_bootstrap_token(
        db,
        agent_id=agent_id,
        token_type="enrollment",
        expires_at=expires_at,
        max_uses=max_uses,
        created_by_user_id=admin.id,
        description=payload.description,
    )
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.bootstrap_token.create",
        resource_type="agent",
        resource_id=agent_id,
        outcome="success",
        before={},
        after={
            "agent_id": agent_id,
            "expires_at": expires_at.isoformat(),
            "max_uses": max_uses,
            "description": payload.description,
        },
    )
    repository.commit(db)
    incr_counter("agent_bootstrap_token_admin_issue_total", outcome="success")
    return AgentBootstrapTokenOut(
        agent_id=agent_id,
        bootstrap_token=token,
        expires_at=expires_at,
        max_uses=max_uses,
    )


def enroll(
    db: Session,
    *,
    payload: AgentEnrollIn,
    raw_bootstrap_token: str,
) -> AgentEnrollOut:
    bootstrap = _consume_bootstrap_token(db, payload.agent_id, raw_bootstrap_token)
    rotated_at = datetime.utcnow()
    overlap_until = _credential_overlap_until(rotated_at)
    agent = repository.get_agent_by_agent_id(db, payload.agent_id)
    meta = {"hostname": payload.hostname, "os": payload.os, "version": payload.version}
    if not agent:
        default_cfg = settings.default_agent_config()
        if len(json.dumps(default_cfg, separators=(",", ":")).encode("utf-8")) > settings.SEAGULL_MAX_AGENT_CONFIG_BYTES:
            default_cfg = {}
        agent = AgentModel(
            agent_id=payload.agent_id,
            agent_metadata=meta,
            display_name=(payload.hostname or payload.agent_id)[:128],
            description=None,
            tags=[],
            config=default_cfg,
            metrics={},
            created_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
            is_revoked=False,
        )
    else:
        if agent.is_revoked:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")
        agent.agent_metadata = {**(agent.agent_metadata or {}), **meta}
        agent.last_seen_at = datetime.utcnow()
        if not (agent.display_name or "").strip():
            agent.display_name = (payload.hostname or payload.agent_id)[:128]

    _revoke_active_credentials(
        db,
        payload.agent_id,
        "replaced_by_enroll",
        rotated_at=rotated_at,
        overlap_until=overlap_until,
    )

    credential, cred_row = _issue_agent_credential(
        db,
        agent_id=payload.agent_id,
        issued_from_bootstrap_token_id=bootstrap.id,
        replaces_credential_id=None,
    )
    renewal_token, renewal_row = _issue_renewal_token(db, agent_id=payload.agent_id)

    repository.save_agent(db, agent)
    repository.commit(db)
    incr_counter("agent_identity_enroll_total", outcome="success", token_type=str(bootstrap.token_type or "enrollment"))

    return AgentEnrollOut(
        agent_id=payload.agent_id,
        config=agent.config or {},
        credential=AgentCredentialOut(
            credential=credential,
            expires_at=cred_row.expires_at,
            max_uses=int(cred_row.max_uses or 1),
            used_uses=int(cred_row.used_uses or 0),
            renewal_token=renewal_token,
            renewal_token_expires_at=renewal_row.expires_at,
        ),
    )


def rotate_credential(db: Session, *, agent: AgentPrincipal) -> AgentCredentialOut:
    row = repository.get_agent_by_id(db, agent.id)
    if not row or row.is_revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")

    rotated_at = datetime.utcnow()
    _revoke_active_credentials(
        db,
        agent.agent_id,
        "rotated",
        rotated_at=rotated_at,
        overlap_until=_credential_overlap_until(rotated_at),
    )

    credential, cred_row = _issue_agent_credential(
        db,
        agent_id=agent.agent_id,
        issued_from_bootstrap_token_id=None,
        replaces_credential_id=agent.credential_id,
    )
    renewal_token, renewal_row = _issue_renewal_token(db, agent_id=agent.agent_id)

    repository.commit(db)
    incr_counter("agent_credential_rotate_total", outcome="success")
    return AgentCredentialOut(
        credential=credential,
        expires_at=cred_row.expires_at,
        max_uses=int(cred_row.max_uses or 1),
        used_uses=int(cred_row.used_uses or 0),
        renewal_token=renewal_token,
        renewal_token_expires_at=renewal_row.expires_at,
    )


def set_config(
    db: Session,
    *,
    agent_id: str,
    payload: AgentConfigUpdateIn,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> None:
    cfg: Dict[str, Any] = dict(payload.config or {})
    _safe_json_size(cfg, settings.SEAGULL_MAX_AGENT_CONFIG_BYTES, "config")
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    if row.is_revoked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")
    before = {"agent_id": row.agent_id, "config": row.config if isinstance(row.config, dict) else {}}
    row.config = cfg
    repository.save_agent(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.config.update",
        resource_type="agent",
        resource_id=row.agent_id,
        outcome="success",
        before=before,
        after={"agent_id": row.agent_id, "config": row.config},
    )
    repository.commit(db)


def heartbeat(db: Session, *, payload: AgentHeartbeatIn, agent: AgentPrincipal) -> None:
    row = repository.get_agent_by_id(db, agent.id)
    if not row or row.is_revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")
    status_text = str(payload.status or "").strip()[:32]
    row.last_seen_at = datetime.utcnow()
    row.metrics = {
        **(row.metrics or {}),
        "status": status_text,
        "uptime_seconds": payload.uptime_seconds,
        "modules": payload.modules,
        "metrics": payload.metrics,
        "auth_method": agent.auth_method,
        "credential_id": agent.credential_id,
    }
    repository.save_agent(db, row)
    repository.commit(db)
    _publish_agent_heartbeat_realtime(row=row, status_text=status_text)


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
            repository.save_response_action(db, row)
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
            repository.save_response_action(db, row)
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
    row_action = repository.get_response_action(db, payload.response_action_id, for_update=True)
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
    latest = repository.get_latest_response_action_result(
        db,
        response_action_id=row_action.id,
        agent_id=agent.agent_id,
    )
    if latest is None:
        latest = ResponseActionResultModel(response_action_id=row_action.id, agent_id=agent.agent_id)
    latest.status = payload.status
    latest.result_payload = result_payload
    latest.error = payload.error
    latest.started_at = payload.started_at
    latest.finished_at = payload.finished_at
    repository.save_response_action_result(db, latest)

    if payload.status == "running":
        row_action.status = "running"
        row_action.delivered_at = row_action.delivered_at or now
        row_action.started_at = payload.started_at or row_action.started_at or now
        repository.save_response_action(db, row_action)
    elif payload.status in {"success", "failed"}:
        row_action.status = payload.status
        row_action.delivered_at = row_action.delivered_at or now
        row_action.started_at = payload.started_at or row_action.started_at or now
        row_action.finished_at = payload.finished_at or now
        row_action.last_error = payload.error if payload.status == "failed" else None
        repository.save_response_action(db, row_action)
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


def get_config(db: Session, *, agent: AgentPrincipal) -> dict:
    row = repository.get_agent_by_id(db, agent.id)
    if not row or row.is_revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")
    return row.config or {}


def list_agents(db: Session) -> List[AgentPublic]:
    rows = repository.list_agents(db)
    return [_agent_to_public(a) for a in rows]


def get_agent(db: Session, *, agent_id: str) -> AgentDetail:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return _agent_to_detail(row)


def update_agent(
    db: Session,
    *,
    agent_id: str,
    payload: AgentUpdateIn,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> AgentDetail:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    before = {
        "agent_id": row.agent_id,
        "display_name": row.display_name,
        "description": row.description,
        "tags": row.tags if isinstance(row.tags, list) else [],
        "metadata": row.agent_metadata if isinstance(row.agent_metadata, dict) else {},
    }
    if payload.display_name is not None:
        dn = payload.display_name.strip()
        row.display_name = dn if dn else None
    if payload.description is not None:
        desc = payload.description.strip()
        row.description = desc if desc else None
    if payload.tags is not None:
        row.tags = _normalize_tags(payload.tags)
        _safe_json_size(row.tags, 8 * 1024, "tags")
    if payload.metadata is not None:
        meta = dict(row.agent_metadata or {})
        patch = dict(payload.metadata or {})
        for k, v in patch.items():
            key = str(k).strip()
            if not key:
                continue
            if v is None:
                meta.pop(key, None)
            else:
                meta[key] = v
        _safe_json_size(meta, 32 * 1024, "metadata")
        row.agent_metadata = meta
    repository.save_agent(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.update",
        resource_type="agent",
        resource_id=row.agent_id,
        outcome="success",
        before=before,
        after={
            "agent_id": row.agent_id,
            "display_name": row.display_name,
            "description": row.description,
            "tags": row.tags if isinstance(row.tags, list) else [],
            "metadata": row.agent_metadata if isinstance(row.agent_metadata, dict) else {},
        },
    )
    repository.commit(db)
    repository.refresh(db, row)
    return _agent_to_detail(row)


def reissue_agent_identity(
    db: Session,
    *,
    agent_id: str,
    payload: AgentBootstrapTokenCreateIn,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> AgentBootstrapTokenOut:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    if row.is_revoked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")

    ttl_seconds = int(payload.ttl_seconds or settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS)
    max_uses = int(payload.max_uses or settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES)
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

    _revoke_active_credentials(db, row.agent_id, "operator_reissue")
    _revoke_active_bootstrap_tokens(db, row.agent_id, "operator_reissue")
    token, _rec = _issue_bootstrap_token(
        db,
        agent_id=row.agent_id,
        token_type="enrollment",
        expires_at=expires_at,
        max_uses=max_uses,
        created_by_user_id=admin.id,
        description=payload.description or "operator-reissue",
    )
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.identity.reissue",
        resource_type="agent",
        resource_id=row.agent_id,
        outcome="success",
        before={"agent_id": row.agent_id, "is_revoked": bool(row.is_revoked)},
        after={
            "agent_id": row.agent_id,
            "bootstrap_token_expires_at": expires_at.isoformat(),
            "bootstrap_token_max_uses": max_uses,
        },
    )
    repository.commit(db)
    incr_counter("agent_identity_reissue_total", outcome="success")
    return AgentBootstrapTokenOut(
        agent_id=row.agent_id,
        bootstrap_token=token,
        expires_at=expires_at,
        max_uses=max_uses,
    )


def disable_agent(
    db: Session,
    *,
    agent_id: str,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> None:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    before = {"agent_id": row.agent_id, "is_revoked": bool(row.is_revoked)}
    row.is_revoked = True
    _revoke_active_credentials(db, row.agent_id, "agent_disabled")
    _revoke_active_bootstrap_tokens(db, row.agent_id, "agent_disabled")
    repository.save_agent(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.disable",
        resource_type="agent",
        resource_id=row.agent_id,
        outcome="success",
        before=before,
        after={"agent_id": row.agent_id, "is_revoked": True},
    )
    repository.commit(db)
    incr_counter("agent_disable_total", outcome="success")


def enable_agent(
    db: Session,
    *,
    agent_id: str,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> None:
    row = repository.get_agent_by_agent_id(db, agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    before = {"agent_id": row.agent_id, "is_revoked": bool(row.is_revoked)}
    row.is_revoked = False
    repository.save_agent(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="agents.enable",
        resource_type="agent",
        resource_id=row.agent_id,
        outcome="success",
        before=before,
        after={"agent_id": row.agent_id, "is_revoked": False},
    )
    repository.commit(db)
    incr_counter("agent_enable_total", outcome="success")
