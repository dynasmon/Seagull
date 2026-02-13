import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.portal_auth import PortalPrincipal, require_admin, get_current_user
from app.core.agent_auth import AgentPrincipal, generate_agent_token, get_current_agent
from app.core.config import settings
from app.core.db import SessionLocal
from app.models.agents import AgentModel
from app.schemas.agents import (
    AgentConfigUpdateIn,
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


@router.post("/enroll", response_model=AgentEnrollOut, status_code=status.HTTP_201_CREATED)
async def enroll_agent(request: Request, payload: AgentEnrollIn):
    """Register an agent and return its token.

    Security note:
    - You should protect enroll in production (e.g., allowlisted networks, enroll token, etc.).
    """

    # Optional enroll hardening: if configured, require an enroll token.
    expected_enroll = (getattr(settings, "NETWATCH_ENROLL_TOKEN", None) or "").strip()
    if expected_enroll:
        got = (request.headers.get("X-Enroll-Token") or "").strip()
        if not got or got != expected_enroll:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    db = SessionLocal()
    try:
        agent: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == payload.agent_id).first()

        token, salt, secret_hash = generate_agent_token(payload.agent_id)

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
                key_salt=salt,
                key_hash=secret_hash,
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

            agent.key_salt = salt
            agent.key_hash = secret_hash
            agent.agent_metadata = {**(agent.agent_metadata or {}), **meta}
            agent.last_seen_at = datetime.utcnow()

            if not (agent.display_name or "").strip():
                agent.display_name = (payload.hostname or payload.agent_id)[:128]

        db.add(agent)
        db.commit()

        return AgentEnrollOut(agent_id=payload.agent_id, agent_token=token, config=agent.config or {})
    finally:
        db.close()


@router.put("/{agent_id}/config", status_code=status.HTTP_204_NO_CONTENT)
async def set_agent_config(agent_id: str, payload: AgentConfigUpdateIn, _admin: PortalPrincipal = Depends(require_admin)):
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

        row.config = cfg
        db.add(row)
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


@router.patch("/{agent_id}", response_model=AgentDetail)
async def update_agent(agent_id: str, payload: AgentUpdateIn, _admin: PortalPrincipal = Depends(require_admin)):

    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

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
        db.commit()
        db.refresh(row)
        return _agent_to_detail(row)
    finally:
        db.close()


@router.post("/{agent_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_agent(agent_id: str, _admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        row.is_revoked = True
        db.add(row)
        db.commit()
        return None
    finally:
        db.close()


@router.post("/{agent_id}/enable", status_code=status.HTTP_204_NO_CONTENT)
async def enable_agent(agent_id: str, _admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        row.is_revoked = False
        db.add(row)
        db.commit()
        return None
    finally:
        db.close()
