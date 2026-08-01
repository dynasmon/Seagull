from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event
from app.core.db import get_db, routed_db
from app.core.db.session import managed_session
from app.features.agents import onboarding, service
from app.features.agents.auth import AgentPrincipal, get_current_agent
from app.features.agents.schemas import (
    AgentBootstrapTokenCreateIn,
    AgentBootstrapTokenOut,
    AgentCertificateRenewIn,
    AgentCertificateRenewOut,
    AgentConfigUpdateIn,
    AgentCredentialOut,
    AgentDetail,
    AgentEnrollIn,
    AgentEnrollmentTicketIn,
    AgentEnrollmentTicketOut,
    AgentEnrollOut,
    AgentHeartbeatIn,
    AgentOnboardingOut,
    AgentPackageSyncOut,
    AgentProtocolOut,
    AgentPublic,
    AgentUpdateIn,
)
from app.features.auth.session import PortalPrincipal, get_current_user, require_admin

router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("/onboarding", response_model=AgentOnboardingOut)
def get_agent_onboarding(
    request: Request,
    _admin: PortalPrincipal = Depends(require_admin),
):
    return onboarding.describe(request)


@router.post("/packages/sync", response_model=AgentPackageSyncOut)
def sync_agent_packages(_admin: PortalPrincipal = Depends(require_admin)):
    version, states = service.sync_packages()
    return AgentPackageSyncOut(version=version, packages=states)


@router.get("/installer")
def download_agent_installer(request: Request, db: Session = Depends(get_db)):
    raw_bootstrap = (request.headers.get("X-Agent-Bootstrap-Token") or "").strip()
    if not raw_bootstrap:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing enrollment token")

    with managed_session(db) as db_session:
        name, body = service.build_installer(
            db_session,
            raw_bootstrap_token=raw_bootstrap,
            request=request,
            audit_writer=write_audit_event,
        )
    return Response(
        content=body,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/enrollment-tickets", response_model=AgentEnrollmentTicketOut, status_code=status.HTTP_201_CREATED)
def create_agent_enrollment_ticket(
    payload: AgentEnrollmentTicketIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.create_enrollment_ticket(
            db_session,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )


@router.post("/{agent_id}/bootstrap-tokens", response_model=AgentBootstrapTokenOut, status_code=status.HTTP_201_CREATED)
def create_agent_bootstrap_token(
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
def reissue_agent_identity(
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
def enroll_agent(request: Request, payload: AgentEnrollIn, db: Session = Depends(get_db)):
    raw_bootstrap = (request.headers.get("X-Agent-Bootstrap-Token") or "").strip()
    if not raw_bootstrap:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bootstrap token")

    with managed_session(db) as db_session:
        return service.enroll(
            db_session,
            payload=payload,
            raw_bootstrap_token=raw_bootstrap,
            request=request,
            audit_writer=write_audit_event,
        )


@router.post("/credential/rotate", response_model=AgentCredentialOut)
def rotate_agent_credential(agent: AgentPrincipal = Depends(get_current_agent), db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.rotate_credential(db_session, agent=agent)


@router.post("/certificate/renew", response_model=AgentCertificateRenewOut)
def renew_agent_certificate(
    payload: AgentCertificateRenewIn,
    request: Request,
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.renew_agent_certificate(
            db_session,
            payload=payload,
            request=request,
            agent=agent,
            audit_writer=write_audit_event,
        )


@router.put("/{agent_id}/config", status_code=status.HTTP_204_NO_CONTENT)
def set_agent_config(
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


@router.post("/heartbeat", response_model=AgentProtocolOut)
def agent_heartbeat(
    payload: AgentHeartbeatIn,
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.heartbeat(db_session, payload=payload, agent=agent)


@router.get("/config")
def get_agent_config(agent: AgentPrincipal = Depends(get_current_agent), db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_config(db_session, agent=agent)


@router.get("", response_model=List[AgentPublic])
def list_agents(_user=Depends(get_current_user), db: Session = Depends(routed_db("agents-list"))):
    with managed_session(db) as db_session:
        return service.list_agents(db_session)


@router.get("/{agent_id}", response_model=AgentDetail)
def get_agent(agent_id: str, _user=Depends(get_current_user), db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_agent(db_session, agent_id=agent_id)


@router.patch("/{agent_id}", response_model=AgentDetail)
def update_agent(
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
def disable_agent(
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
def enable_agent(
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
