from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.agent_auth import AgentPrincipal, get_current_agent
from app.core.api_db import managed_session
from app.core.audit import write_audit_event
from app.core.db import get_db
from app.core.portal_auth import PortalPrincipal, get_current_user, require_admin
from app.features.agents import service
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
from app.features.response.schemas import AgentResponseActionOut, AgentResponseActionResultIn

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("/{agent_id}/bootstrap-tokens", response_model=AgentBootstrapTokenOut, status_code=status.HTTP_201_CREATED)
async def create_agent_bootstrap_token(
    agent_id: str,
    payload: AgentBootstrapTokenCreateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.create_bootstrap_token(
            db_session,
            agent_id=agent_id,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )


@router.post("/{agent_id}/identity/reissue", response_model=AgentBootstrapTokenOut, status_code=status.HTTP_201_CREATED)
async def reissue_agent_identity(
    agent_id: str,
    payload: AgentBootstrapTokenCreateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.reissue_agent_identity(
            db_session,
            agent_id=agent_id,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )


@router.post("/enroll", response_model=AgentEnrollOut, status_code=status.HTTP_201_CREATED)
async def enroll_agent(request: Request, payload: AgentEnrollIn, db: Session = Depends(get_db)):
    raw_bootstrap = (request.headers.get("X-Agent-Bootstrap-Token") or "").strip()
    if not raw_bootstrap:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bootstrap token")

    with managed_session(db) as db_session:
        return service.enroll(db_session, payload=payload, raw_bootstrap_token=raw_bootstrap)


@router.post("/credential/rotate", response_model=AgentCredentialOut)
async def rotate_agent_credential(agent: AgentPrincipal = Depends(get_current_agent), db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.rotate_credential(db_session, agent=agent)


@router.put("/{agent_id}/config", status_code=status.HTTP_204_NO_CONTENT)
async def set_agent_config(
    agent_id: str,
    payload: AgentConfigUpdateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        service.set_config(
            db_session,
            agent_id=agent_id,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
        return None


@router.post("/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
async def agent_heartbeat(
    payload: AgentHeartbeatIn,
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        service.heartbeat(db_session, payload=payload, agent=agent)
        return None


@router.get("/response-actions/pending", response_model=List[AgentResponseActionOut])
@router.get("/response/actions/pending", response_model=List[AgentResponseActionOut], include_in_schema=False)
async def list_pending_response_actions(
    request: Request,
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_pending_actions(db_session, request=request, agent=agent, audit_writer=write_audit_event)


@router.post("/response-actions/results", status_code=status.HTTP_201_CREATED)
@router.post("/response/actions/results", status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def report_response_action_result(
    payload: AgentResponseActionResultIn,
    request: Request,
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.report_action_result(
            db_session,
            payload=payload,
            request=request,
            agent=agent,
            audit_writer=write_audit_event,
        )


@router.get("/config")
async def get_agent_config(agent: AgentPrincipal = Depends(get_current_agent), db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_config(db_session, agent=agent)


@router.get("", response_model=List[AgentPublic])
async def list_agents(_user=Depends(get_current_user), db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.list_agents(db_session)


@router.get("/{agent_id}", response_model=AgentDetail)
async def get_agent(agent_id: str, _user=Depends(get_current_user), db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_agent(db_session, agent_id=agent_id)


@router.patch("/{agent_id}", response_model=AgentDetail)
async def update_agent(
    agent_id: str,
    payload: AgentUpdateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.update_agent(
            db_session,
            agent_id=agent_id,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )


@router.post("/{agent_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_agent(
    agent_id: str,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        service.disable_agent(
            db_session,
            agent_id=agent_id,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
        return None


@router.post("/{agent_id}/enable", status_code=status.HTTP_204_NO_CONTENT)
async def enable_agent(
    agent_id: str,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        service.enable_agent(
            db_session,
            agent_id=agent_id,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
        return None
