from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event
from app.core.db import get_db
from app.core.db.session import managed_session
from app.features.agents.auth import AgentPrincipal, get_current_agent
from app.features.response import agent_actions as service
from app.features.response.schemas import AgentResponseActionOut, AgentResponseActionResultIn

router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("/response-actions/pending", response_model=List[AgentResponseActionOut])
@router.get("/response/actions/pending", response_model=List[AgentResponseActionOut], include_in_schema=False)
def list_pending_response_actions(
    request: Request,
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_pending_actions(db_session, request=request, agent=agent, audit_writer=write_audit_event)


@router.post("/response-actions/results", status_code=status.HTTP_201_CREATED)
@router.post("/response/actions/results", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def report_response_action_result(
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
