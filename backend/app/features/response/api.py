from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event
from app.core.db import get_db
from app.core.db.session import managed_session
from app.features.auth.session import PortalPrincipal, require_admin
from app.features.response import service
from app.features.response.schemas import ResponseActionCreateIn, ResponseActionOut, ResponseActionResultOut

router = APIRouter(prefix="/response", tags=["response"])


@router.post("/actions", response_model=ResponseActionOut, status_code=status.HTTP_201_CREATED)
def create_response_action(
    payload: ResponseActionCreateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.create_response_action(
            db_session,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )


@router.get("/actions", response_model=List[ResponseActionOut], status_code=status.HTTP_200_OK)
def list_response_actions(
    agent_id: Optional[str] = None,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = 100,
    _admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_response_actions(db_session, agent_id=agent_id, status=status_filter, limit=limit)


@router.get("/actions/{action_id}", response_model=ResponseActionOut, status_code=status.HTTP_200_OK)
def get_response_action(
    action_id: int,
    _admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.get_response_action(db_session, action_id=action_id)


@router.get("/actions/{action_id}/result", response_model=ResponseActionResultOut, status_code=status.HTTP_200_OK)
def get_response_action_result(
    action_id: int,
    _admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.get_latest_response_action_result(db_session, action_id=action_id)


@router.post("/actions/{action_id}/cancel", response_model=ResponseActionOut, status_code=status.HTTP_200_OK)
def cancel_response_action(
    action_id: int,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.cancel_response_action(
            db_session,
            action_id=action_id,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
