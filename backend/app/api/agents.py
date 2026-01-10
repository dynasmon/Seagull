import json
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.agent_auth import AgentPrincipal, generate_agent_token, get_current_agent
from app.core.admin_auth import require_admin
from app.core.config import settings
from app.core.db import SessionLocal
from app.models.agents import AgentModel
from app.schemas.agents import (
    AgentEnrollIn,
    AgentEnrollOut,
    AgentHeartbeatIn,
    AgentPublic,
    AgentConfigUpdateIn,
)


router = APIRouter(
    prefix="/agents",
    tags=["agents"],
)


@router.post("/enroll", response_model=AgentEnrollOut, status_code=status.HTTP_201_CREATED)
async def enroll_agent(payload: AgentEnrollIn):
    """Register an agent and return its token.

    This endpoint is intentionally unauthenticated.
    """

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
            # Default config only on first enroll
            default_cfg = settings.default_agent_config()
            # Enforce size limit defensively
            if len(json.dumps(default_cfg, separators=(",", ":")).encode("utf-8")) > settings.NETWATCH_MAX_AGENT_CONFIG_BYTES:
                default_cfg = {}
            agent = AgentModel(
                agent_id=payload.agent_id,
                key_salt=salt,
                key_hash=secret_hash,
                agent_metadata=meta,
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

        db.add(agent)
        db.commit()

        return AgentEnrollOut(agent_id=payload.agent_id, agent_token=token, config=agent.config or {})
    finally:
        db.close()


@router.put("/{agent_id}/config", status_code=status.HTTP_204_NO_CONTENT)
async def set_agent_config(request: Request, agent_id: str, payload: AgentConfigUpdateIn):
    """Admin: push a new config blob to an agent."""

    require_admin(request)

    cfg: Dict[str, Any] = dict(payload.config or {})
    raw = json.dumps(cfg, separators=(",", ":")).encode("utf-8")
    if len(raw) > settings.NETWATCH_MAX_AGENT_CONFIG_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"config exceeds {settings.NETWATCH_MAX_AGENT_CONFIG_BYTES} bytes",
        )

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
        # Keep the last heartbeat payload for troubleshooting.
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
async def list_agents():
    db = SessionLocal()
    try:
        rows = db.query(AgentModel).order_by(AgentModel.agent_id.asc()).all()
        return [
            AgentPublic(
                agent_id=a.agent_id,
                created_at=a.created_at,
                last_seen_at=a.last_seen_at,
                is_revoked=a.is_revoked,
                metadata=a.agent_metadata or {},
                metrics=a.metrics or {},
            )
            for a in rows
        ]
    finally:
        db.close()
