import json
import re
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.audit import audit_actor, write_audit_event
from app.core.portal_auth import PortalPrincipal, require_admin, get_current_user
from app.core.agent_auth import (
    AgentPrincipal,
    generate_agent_credential,
    generate_bootstrap_token,
    get_current_agent,
    hash_bootstrap_token,
)
from app.core.config import settings
from app.core.db import SessionLocal
from app.features.agents.models import AgentCredentialModel
from app.features.agents.models import AgentBootstrapTokenModel
from app.features.agents.models import AgentModel
from app.features.response.models import ResponseActionResultModel
from app.features.response.models import ResponseActionModel
from app.features.response.schemas import AgentResponseActionOut, AgentResponseActionResultIn
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

router = APIRouter(prefix="/agents", tags=["agents"])

_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$")


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


def _consume_bootstrap_token(db, agent_id: str, raw_token: str) -> AgentBootstrapTokenModel:
    now = datetime.utcnow()
    candidates = (
        db.query(AgentBootstrapTokenModel)
        .filter(
            AgentBootstrapTokenModel.agent_id == agent_id,
            AgentBootstrapTokenModel.revoked_at.is_(None),
        )
        .with_for_update()
        .all()
    )

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
        db.add(tok)
        return tok

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bootstrap token")


def _revoke_active_credentials(db, agent_id: str, reason: str, *, rotated_at: datetime | None = None) -> None:
    active = (
        db.query(AgentCredentialModel)
        .filter(AgentCredentialModel.agent_id == agent_id, AgentCredentialModel.revoked_at.is_(None))
        .all()
    )
    now = datetime.utcnow()
    for row in active:
        row.revoked_at = now
        row.rotated_at = rotated_at
        row.revoked_reason = reason
        db.add(row)


def _issue_agent_credential(
    db,
    *,
    agent_id: str,
    issued_from_bootstrap_token_id: int | None,
    replaces_credential_id: int | None,
) -> tuple[str, AgentCredentialModel]:
    ttl_seconds = max(300, int(settings.NETWATCH_AGENT_CREDENTIAL_TTL_SECONDS or 0))
    max_uses = max(1, int(settings.NETWATCH_AGENT_CREDENTIAL_MAX_USES or 0))
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
    db.add(row)
    db.flush()
    return credential, row


@router.post("/{agent_id}/bootstrap-tokens", response_model=AgentBootstrapTokenOut, status_code=status.HTTP_201_CREATED)
async def create_agent_bootstrap_token(
    agent_id: str,
    payload: AgentBootstrapTokenCreateIn,
    request: Request,
    _admin: PortalPrincipal = Depends(require_admin),
):
    ttl_seconds = int(payload.ttl_seconds or settings.NETWATCH_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS)
    max_uses = int(payload.max_uses or settings.NETWATCH_AGENT_BOOTSTRAP_TOKEN_MAX_USES)
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

    token, salt, token_hash = generate_bootstrap_token(agent_id)

    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not row:
            default_cfg = settings.default_agent_config()
            if len(json.dumps(default_cfg, separators=(",", ":")).encode("utf-8")) > settings.NETWATCH_MAX_AGENT_CONFIG_BYTES:
                default_cfg = {}
            row = AgentModel(
                agent_id=agent_id,
                key_salt="",
                key_hash="",
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
            db.add(row)

        rec = AgentBootstrapTokenModel(
            agent_id=agent_id,
            token_salt=salt,
            token_hash=token_hash,
            expires_at=expires_at,
            max_uses=max_uses,
            used_uses=0,
            created_by_user_id=_admin.id,
            description=payload.description,
        )
        db.add(rec)

        write_audit_event(
            db,
            request=request,
            actor=audit_actor(_admin.id, _admin.username),
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
        db.commit()

        return AgentBootstrapTokenOut(
            agent_id=agent_id,
            bootstrap_token=token,
            expires_at=expires_at,
            max_uses=max_uses,
        )
    finally:
        db.close()


@router.post("/enroll", response_model=AgentEnrollOut, status_code=status.HTTP_201_CREATED)
async def enroll_agent(request: Request, payload: AgentEnrollIn):
    """Register an agent and issue a rotating credential."""

    raw_bootstrap = (request.headers.get("X-Agent-Bootstrap-Token") or "").strip()
    if not raw_bootstrap:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bootstrap token")

    db = SessionLocal()
    try:
        bootstrap = _consume_bootstrap_token(db, payload.agent_id, raw_bootstrap)
        agent: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == payload.agent_id).first()

        meta = {
            "hostname": payload.hostname,
            "os": payload.os,
            "version": payload.version,
        }

        if not agent:
            default_cfg = settings.default_agent_config()
            if len(json.dumps(default_cfg, separators=(",", ":")).encode("utf-8")) > settings.NETWATCH_MAX_AGENT_CONFIG_BYTES:
                default_cfg = {}

            agent = AgentModel(
                agent_id=payload.agent_id,
                key_salt="",
                key_hash="",
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

            agent.key_salt = ""
            agent.key_hash = ""
            agent.agent_metadata = {**(agent.agent_metadata or {}), **meta}
            agent.last_seen_at = datetime.utcnow()

            if not (agent.display_name or "").strip():
                agent.display_name = (payload.hostname or payload.agent_id)[:128]

        _revoke_active_credentials(db, payload.agent_id, "replaced_by_enroll")
        credential, cred_row = _issue_agent_credential(
            db,
            agent_id=payload.agent_id,
            issued_from_bootstrap_token_id=bootstrap.id,
            replaces_credential_id=None,
        )

        db.add(agent)
        db.commit()

        return AgentEnrollOut(
            agent_id=payload.agent_id,
            config=agent.config or {},
            credential=AgentCredentialOut(
                credential=credential,
                expires_at=cred_row.expires_at,
                max_uses=int(cred_row.max_uses or 1),
                used_uses=int(cred_row.used_uses or 0),
            ),
        )
    finally:
        db.close()


@router.post("/credential/rotate", response_model=AgentCredentialOut)
async def rotate_agent_credential(agent: AgentPrincipal = Depends(get_current_agent)):
    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.id == agent.id).first()
        if not row or row.is_revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")

        rotated_at = datetime.utcnow()
        _revoke_active_credentials(db, agent.agent_id, "rotated", rotated_at=rotated_at)
        credential, cred_row = _issue_agent_credential(
            db,
            agent_id=agent.agent_id,
            issued_from_bootstrap_token_id=None,
            replaces_credential_id=agent.credential_id,
        )

        db.commit()
        return AgentCredentialOut(
            credential=credential,
            expires_at=cred_row.expires_at,
            max_uses=int(cred_row.max_uses or 1),
            used_uses=int(cred_row.used_uses or 0),
        )
    finally:
        db.close()


@router.put("/{agent_id}/config", status_code=status.HTTP_204_NO_CONTENT)
async def set_agent_config(agent_id: str, payload: AgentConfigUpdateIn, request: Request, _admin: PortalPrincipal = Depends(require_admin)):
    """Admin: push a new config blob to an agent."""

    cfg: Dict[str, Any] = dict(payload.config or {})
    _safe_json_size(cfg, settings.NETWATCH_MAX_AGENT_CONFIG_BYTES, "config")

    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        if row.is_revoked:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")

        before = {"agent_id": row.agent_id, "config": row.config if isinstance(row.config, dict) else {}}
        row.config = cfg
        db.add(row)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(_admin.id, _admin.username),
            event_type="admin_action",
            action="agents.config.update",
            resource_type="agent",
            resource_id=row.agent_id,
            outcome="success",
            before=before,
            after={"agent_id": row.agent_id, "config": row.config},
        )
        db.commit()
        return None
    finally:
        db.close()


@router.post("/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
async def agent_heartbeat(payload: AgentHeartbeatIn, agent: AgentPrincipal = Depends(get_current_agent)):
    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.id == agent.id).first()
        if not row or row.is_revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")

        row.last_seen_at = datetime.utcnow()
        row.metrics = {
            **(row.metrics or {}),
            "status": payload.status,
            "uptime_seconds": payload.uptime_seconds,
            "modules": payload.modules,
            "metrics": payload.metrics,
            "auth_method": agent.auth_method,
            "credential_id": agent.credential_id,
        }

        db.add(row)
        db.commit()
        return None
    finally:
        db.close()


@router.get("/response-actions/pending", response_model=List[AgentResponseActionOut])
@router.get("/response/actions/pending", response_model=List[AgentResponseActionOut], include_in_schema=False)
async def list_pending_response_actions(request: Request, agent: AgentPrincipal = Depends(get_current_agent)):
    db = SessionLocal()
    try:
        row_agent: AgentModel | None = db.query(AgentModel).filter(AgentModel.id == agent.id).first()
        if not row_agent or row_agent.is_revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")

        now = datetime.utcnow()
        rows: List[ResponseActionModel] = (
            db.query(ResponseActionModel)
            .filter(
                ResponseActionModel.agent_id == agent.agent_id,
                ResponseActionModel.status == "pending",
            )
            .order_by(ResponseActionModel.requested_at.asc(), ResponseActionModel.id.asc())
            .limit(100)
            .all()
        )

        out: List[ResponseActionModel] = []
        for row in rows:
            if row.expires_at is not None and row.expires_at <= now:
                row.status = "failed"
                db.add(row)
                continue
            before = {
                "id": row.id,
                "status": row.status,
                "action_type": row.action_type,
                "agent_id": row.agent_id,
            }
            row.status = "running"
            db.add(row)
            write_audit_event(
                db,
                request=request,
                actor=audit_actor(None, None),
                event_type="admin_action",
                action="response.actions.running",
                resource_type="response_action",
                resource_id=str(row.id),
                outcome="success",
                before=before,
                after={
                    "id": row.id,
                    "status": row.status,
                    "action_type": row.action_type,
                    "agent_id": row.agent_id,
                },
                context={
                    "reported_by_agent_id": agent.agent_id,
                    "requested_by": row.requested_by,
                },
            )
            out.append(row)

        db.commit()
        return out
    finally:
        db.close()


@router.post("/response-actions/results", status_code=status.HTTP_201_CREATED)
@router.post("/response/actions/results", status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def report_response_action_result(
    payload: AgentResponseActionResultIn,
    request: Request,
    agent: AgentPrincipal = Depends(get_current_agent),
):
    db = SessionLocal()
    try:
        row_agent: AgentModel | None = db.query(AgentModel).filter(AgentModel.id == agent.id).first()
        if not row_agent or row_agent.is_revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")

        row_action: ResponseActionModel | None = (
            db.query(ResponseActionModel)
            .filter(ResponseActionModel.id == payload.response_action_id)
            .first()
        )
        if not row_action:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Response action not found")
        if row_action.agent_id != agent.agent_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Response action does not belong to this agent")
        if payload.agent_id is not None and payload.agent_id != agent.agent_id:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="agent_id mismatch")

        result_payload: Dict[str, Any] = dict(payload.result_payload or {})
        before_action_status = row_action.status
        latest: ResponseActionResultModel | None = (
            db.query(ResponseActionResultModel)
            .filter(
                ResponseActionResultModel.response_action_id == row_action.id,
                ResponseActionResultModel.agent_id == agent.agent_id,
            )
            .order_by(ResponseActionResultModel.id.desc())
            .first()
        )
        if latest is None:
            latest = ResponseActionResultModel(
                response_action_id=row_action.id,
                agent_id=agent.agent_id,
            )
        latest.status = payload.status
        latest.result_payload = result_payload
        latest.error = payload.error
        latest.started_at = payload.started_at
        latest.finished_at = payload.finished_at
        db.add(latest)

        if payload.status in {"success", "failed"}:
            row_action.status = payload.status
            db.add(row_action)
        if payload.status == "failed" and before_action_status != "failed":
            write_audit_event(
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
                context={
                    "result_status": payload.status,
                    "reported_by_agent_id": agent.agent_id,
                },
            )

        db.commit()
        return {"status": row_action.status}
    finally:
        db.close()


@router.get("/config")
async def get_agent_config(agent: AgentPrincipal = Depends(get_current_agent)):
    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.id == agent.id).first()
        if not row or row.is_revoked:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or revoked agent")
        return row.config or {}
    finally:
        db.close()


@router.get("", response_model=List[AgentPublic])
async def list_agents(_user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.query(AgentModel).order_by(AgentModel.agent_id.asc()).all()
        return [_agent_to_public(a) for a in rows]
    finally:
        db.close()


@router.get("/{agent_id}", response_model=AgentDetail)
async def get_agent(agent_id: str, _user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return _agent_to_detail(row)
    finally:
        db.close()


@router.patch("/{agent_id}", response_model=AgentDetail)
async def update_agent(agent_id: str, payload: AgentUpdateIn, request: Request, _admin: PortalPrincipal = Depends(require_admin)):

    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
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

        db.add(row)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(_admin.id, _admin.username),
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
        db.commit()
        db.refresh(row)
        return _agent_to_detail(row)
    finally:
        db.close()


@router.post("/{agent_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_agent(agent_id: str, request: Request, _admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        before = {"agent_id": row.agent_id, "is_revoked": bool(row.is_revoked)}
        row.is_revoked = True
        _revoke_active_credentials(db, row.agent_id, "agent_disabled")
        db.add(row)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(_admin.id, _admin.username),
            event_type="admin_action",
            action="agents.disable",
            resource_type="agent",
            resource_id=row.agent_id,
            outcome="success",
            before=before,
            after={"agent_id": row.agent_id, "is_revoked": True},
        )
        db.commit()
        return None
    finally:
        db.close()


@router.post("/{agent_id}/enable", status_code=status.HTTP_204_NO_CONTENT)
async def enable_agent(agent_id: str, request: Request, _admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        before = {"agent_id": row.agent_id, "is_revoked": bool(row.is_revoked)}
        row.is_revoked = False
        db.add(row)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(_admin.id, _admin.username),
            event_type="admin_action",
            action="agents.enable",
            resource_type="agent",
            resource_id=row.agent_id,
            outcome="success",
            before=before,
            after={"agent_id": row.agent_id, "is_revoked": False},
        )
        db.commit()
        return None
    finally:
        db.close()
