from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.agent_auth import AgentPrincipal, generate_agent_token, get_current_agent
from app.core.db import SessionLocal
from app.models.agents import AgentModel
from app.schemas.agents import AgentEnrollIn, AgentEnrollOut, AgentHeartbeatIn, AgentPublic


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
            agent = AgentModel(
                agent_id=payload.agent_id,
                key_salt=salt,
                key_hash=secret_hash,
                agent_metadata=meta,
                config={},
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
