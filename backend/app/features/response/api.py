from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event
from app.core.db import get_db
from app.core.db.session import managed_session
from app.features.auth.session import (
    PortalPrincipal,
    get_current_user,
    require_admin,
    require_min_risk_level,
)
from app.features.response import service
from app.features.response.registry import ACTION_REGISTRY
from app.features.response.schemas import (
    ActionTypeOut,
    BatchDispatchIn,
    BatchDispatchOut,
    ResponseActionCreateIn,
    ResponseActionOut,
    ResponseActionResultOut,
    TimelineEventOut,
)

router = APIRouter(prefix="/response", tags=["response"])


def _gate_action_risk(
    payload: ResponseActionCreateIn,
    user: PortalPrincipal = Depends(get_current_user),
) -> PortalPrincipal:
    definition = ACTION_REGISTRY.get(payload.action_type)
    if definition is not None:
        return require_min_risk_level(definition.risk_level)(user)
    return user


def _gate_batch_action_risk(
    payload: BatchDispatchIn,
    user: PortalPrincipal = Depends(get_current_user),
) -> PortalPrincipal:
    definition = ACTION_REGISTRY.get(payload.action_type)
    if definition is not None:
        return require_min_risk_level(definition.risk_level)(user)
    return user


@router.get("/action-types", response_model=List[ActionTypeOut], status_code=status.HTTP_200_OK)
def list_action_types(
    _admin: PortalPrincipal = Depends(require_admin),
):
    return service.list_action_types()


@router.post("/actions", response_model=ResponseActionOut, status_code=status.HTTP_201_CREATED)
def create_response_action(
    payload: ResponseActionCreateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    _risk_gate: PortalPrincipal = Depends(_gate_action_risk),
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


@router.post("/actions/batch", response_model=BatchDispatchOut, status_code=status.HTTP_201_CREATED)
def create_response_action_batch(
    payload: BatchDispatchIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    _risk_gate: PortalPrincipal = Depends(_gate_batch_action_risk),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.create_response_action_batch(
            db_session,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )


@router.get("/actions", response_model=List[ResponseActionOut], status_code=status.HTTP_200_OK)
def list_response_actions(
    agent_id: Optional[str] = None,
    agent_ids: Optional[str] = None,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    category: Optional[str] = None,
    risk_level: Optional[str] = None,
    batch_id: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = 100,
    _admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    parsed_ids = None
    if agent_ids:
        parsed_ids = [s.strip() for s in agent_ids.split(",") if s.strip()]
    with managed_session(db) as db_session:
        return service.list_response_actions(
            db_session,
            agent_id=agent_id,
            agent_ids=parsed_ids,
            status=status_filter,
            category=category,
            risk_level=risk_level,
            batch_id=batch_id,
            since=since,
            limit=limit,
        )


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


@router.get("/actions/{action_id}/timeline", response_model=List[TimelineEventOut], status_code=status.HTTP_200_OK)
def get_response_action_timeline(
    action_id: int,
    _admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.get_response_action_timeline(db_session, action_id=action_id)


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
