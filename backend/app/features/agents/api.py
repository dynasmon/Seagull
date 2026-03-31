from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.agent_auth import AgentPrincipal, get_current_agent
from app.core.audit import write_audit_event
from app.core.db import SessionLocal
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
):
    db = SessionLocal()
    try:
        return service.create_bootstrap_token(
            db,
            agent_id=agent_id,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.post("/enroll", response_model=AgentEnrollOut, status_code=status.HTTP_201_CREATED)
async def enroll_agent(request: Request, payload: AgentEnrollIn):
    raw_bootstrap = (request.headers.get("X-Agent-Bootstrap-Token") or "").strip()
    if not raw_bootstrap:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bootstrap token")

    db = SessionLocal()
    try:
        return service.enroll(db, payload=payload, raw_bootstrap_token=raw_bootstrap)
    finally:
        db.close()


@router.post("/credential/rotate", response_model=AgentCredentialOut)
async def rotate_agent_credential(agent: AgentPrincipal = Depends(get_current_agent)):
    db = SessionLocal()
    try:
        return service.rotate_credential(db, agent=agent)
    finally:
        db.close()


@router.put("/{agent_id}/config", status_code=status.HTTP_204_NO_CONTENT)
async def set_agent_config(agent_id: str, payload: AgentConfigUpdateIn, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        service.set_config(
            db,
            agent_id=agent_id,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
        return None
    finally:
        db.close()


@router.post("/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
async def agent_heartbeat(payload: AgentHeartbeatIn, agent: AgentPrincipal = Depends(get_current_agent)):
    db = SessionLocal()
    try:
        service.heartbeat(db, payload=payload, agent=agent)
        return None
    finally:
        db.close()


@router.get("/response-actions/pending", response_model=List[AgentResponseActionOut])
@router.get("/response/actions/pending", response_model=List[AgentResponseActionOut], include_in_schema=False)
async def list_pending_response_actions(request: Request, agent: AgentPrincipal = Depends(get_current_agent)):
    db = SessionLocal()
    try:
        return service.list_pending_actions(db, request=request, agent=agent, audit_writer=write_audit_event)
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
        return service.report_action_result(
            db,
            payload=payload,
            request=request,
            agent=agent,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.get("/config")
async def get_agent_config(agent: AgentPrincipal = Depends(get_current_agent)):
    db = SessionLocal()
    try:
        return service.get_config(db, agent=agent)
    finally:
        db.close()


@router.get("", response_model=List[AgentPublic])
async def list_agents(_user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        return service.list_agents(db)
    finally:
        db.close()


@router.get("/{agent_id}", response_model=AgentDetail)
async def get_agent(agent_id: str, _user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        return service.get_agent(db, agent_id=agent_id)
    finally:
        db.close()


@router.patch("/{agent_id}", response_model=AgentDetail)
async def update_agent(agent_id: str, payload: AgentUpdateIn, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        return service.update_agent(
            db,
            agent_id=agent_id,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.post("/{agent_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_agent(agent_id: str, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        service.disable_agent(
            db,
            agent_id=agent_id,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
        return None
    finally:
        db.close()


@router.post("/{agent_id}/enable", status_code=status.HTTP_204_NO_CONTENT)
async def enable_agent(agent_id: str, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        service.enable_agent(
            db,
            agent_id=agent_id,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
        return None
    finally:
        db.close()
