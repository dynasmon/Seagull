import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.audit import audit_actor, write_audit_event
from app.core.portal_auth import PortalPrincipal, require_admin, get_current_user
from app.core.agent_auth import (
    AgentPrincipal,
    generate_bootstrap_token,
    get_current_agent,
    get_presented_mtls_identity,
    hash_bootstrap_token,
)
from app.core.config import settings
from app.core.db import SessionLocal
from app.models.agent_identities import AgentBootstrapTokenModel, AgentIdentityModel
from app.models.agents import AgentModel
from app.schemas.agents import (
    AgentBootstrapTokenCreateIn,
    AgentBootstrapTokenOut,
    AgentConfigUpdateIn,
    AgentDetail,
    AgentEnrollIn,
    AgentEnrollOut,
    AgentHeartbeatIn,
    AgentIdentityPublic,
    AgentIdentityRevokeIn,
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
    return AgentPublic(
        agent_id=a.agent_id,
        display_name=a.display_name,
        description=a.description,
        tags=tags,
        created_at=a.created_at,
        last_seen_at=a.last_seen_at,
        is_revoked=a.is_revoked,
        metadata=a.agent_metadata or {},
        metrics=a.metrics or {},
    )


def _agent_to_detail(a: AgentModel) -> AgentDetail:
    pub = _agent_to_public(a)
    return AgentDetail(**pub.dict(), config=a.config or {})


def _identity_to_public(row: AgentIdentityModel) -> AgentIdentityPublic:
    return AgentIdentityPublic(
        id=row.id,
        agent_id=row.agent_id,
        fingerprint_sha256=row.fingerprint_sha256,
        serial_number=row.serial_number,
        subject_dn=row.subject_dn,
        issuer_dn=row.issuer_dn,
        not_before=row.not_before,
        not_after=row.not_after,
        is_revoked=bool(row.is_revoked),
        revoked_at=row.revoked_at,
        revoked_reason=row.revoked_reason,
        created_at=row.created_at,
        last_seen_at=row.last_seen_at,
        metadata=row.identity_metadata or {},
    )


def _parse_cert_time(raw: str | None) -> datetime | None:
    s = (raw or "").strip()
    if not s:
        return None
    # nginx $ssl_client_v_start / $ssl_client_v_end format (OpenSSL): "Jan  2 15:04:05 2006 GMT"
    for fmt in ["%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"]:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            continue
    return None


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
    """Register an agent and bind its identity."""

    mtls_identity = get_presented_mtls_identity(request, require_verified=True)
    if mtls_identity is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="mTLS identity required")

    db = SessionLocal()
    try:
        agent: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == payload.agent_id).first()

        meta = {
            "hostname": payload.hostname,
            "os": payload.os,
            "version": payload.version,
        }

        if mtls_identity.agent_id != payload.agent_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Certificate agent_id mismatch")

        raw_bootstrap = (request.headers.get("X-Agent-Bootstrap-Token") or "").strip()
        if not raw_bootstrap:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bootstrap token")
        _consume_bootstrap_token(db, payload.agent_id, raw_bootstrap)

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

        existing_identity = (
            db.query(AgentIdentityModel)
            .filter(AgentIdentityModel.fingerprint_sha256 == mtls_identity.fingerprint_sha256)
            .first()
        )
        if existing_identity and existing_identity.agent_id != payload.agent_id:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Certificate already bound to another agent")
        if existing_identity and existing_identity.is_revoked:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Certificate revoked")

        if not existing_identity:
            existing_identity = AgentIdentityModel(
                agent_id=payload.agent_id,
                fingerprint_sha256=mtls_identity.fingerprint_sha256,
                serial_number=mtls_identity.serial_number,
                subject_dn=mtls_identity.subject_dn,
                issuer_dn=mtls_identity.issuer_dn,
                not_before=_parse_cert_time(request.headers.get("X-Agent-TLS-Not-Before")),
                not_after=_parse_cert_time(request.headers.get("X-Agent-TLS-Not-After")),
                is_revoked=False,
                identity_metadata={"enrolled_via": "mtls"},
                created_at=datetime.utcnow(),
                last_seen_at=datetime.utcnow(),
            )
        else:
            existing_identity.serial_number = mtls_identity.serial_number
            existing_identity.subject_dn = mtls_identity.subject_dn
            existing_identity.issuer_dn = mtls_identity.issuer_dn
            existing_identity.not_before = _parse_cert_time(request.headers.get("X-Agent-TLS-Not-Before"))
            existing_identity.not_after = _parse_cert_time(request.headers.get("X-Agent-TLS-Not-After"))
            existing_identity.last_seen_at = datetime.utcnow()

        db.add(existing_identity)

        db.add(agent)
        db.commit()

        return AgentEnrollOut(agent_id=payload.agent_id, config=agent.config or {})
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
            "identity_fingerprint": agent.identity_fingerprint,
        }

        db.add(row)
        db.commit()
        return None
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


@router.get("/{agent_id}/identities", response_model=List[AgentIdentityPublic])
async def list_agent_identities(agent_id: str, _user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        ids = (
            db.query(AgentIdentityModel)
            .filter(AgentIdentityModel.agent_id == agent_id)
            .order_by(AgentIdentityModel.created_at.desc(), AgentIdentityModel.id.desc())
            .all()
        )
        return [_identity_to_public(x) for x in ids]
    finally:
        db.close()


@router.post("/{agent_id}/identities/{identity_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_agent_identity(
    agent_id: str,
    identity_id: int,
    payload: AgentIdentityRevokeIn,
    request: Request,
    _admin: PortalPrincipal = Depends(require_admin),
):
    db = SessionLocal()
    try:
        row: AgentIdentityModel | None = (
            db.query(AgentIdentityModel)
            .filter(AgentIdentityModel.id == identity_id, AgentIdentityModel.agent_id == agent_id)
            .first()
        )
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent identity not found")

        if not row.is_revoked:
            row.is_revoked = True
            row.revoked_at = datetime.utcnow()
            row.revoked_reason = (payload.reason or "").strip() or "manual_revocation"
            db.add(row)

        write_audit_event(
            db,
            request=request,
            actor=audit_actor(_admin.id, _admin.username),
            event_type="admin_action",
            action="agents.identity.revoke",
            resource_type="agent_identity",
            resource_id=str(row.id),
            outcome="success",
            before={"is_revoked": False, "revoked_reason": None},
            after={"is_revoked": True, "revoked_reason": row.revoked_reason},
        )
        db.commit()
        return None
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
