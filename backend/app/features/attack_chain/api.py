from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event
from app.core.db import get_db
from app.core.db.session import managed_session
from app.features.attack_chain import service
from app.features.attack_chain.schemas import (
    AttackChainAllowlistCreate,
    AttackChainAllowlistDB,
    AttackChainAllowlistUpdate,
    AttackChainCaseDB,
    AttackChainCaseWithSteps,
    AttackChainStepDB,
)
from app.features.auth.session import PortalPrincipal, get_current_user, require_admin
from app.shared.schemas import CursorPage

router = APIRouter(
    prefix="/attack-chain",
    tags=["attack_chain"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/cases", response_model=CursorPage[AttackChainCaseDB])
def list_cases(
    page_size: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    suspect_ip: Optional[str] = Query(None, min_length=1, max_length=45),
    status: Optional[str] = Query(None, description="open | closed"),
    min_score: Optional[int] = Query(None, ge=0, le=1000),
    since: Optional[str] = Query(None, description="ISO timestamp (filters by last_seen_at)"),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_cases(
            db_session,
            page_size=page_size,
            cursor=cursor,
            agent_id=agent_id,
            suspect_ip=suspect_ip,
            status=status,
            min_score=min_score,
            since=since,
        )


@router.get("/cases/{case_id}", response_model=AttackChainCaseDB)
def get_case(case_id: int, db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_case(db_session, case_id=case_id)


@router.get("/cases/{case_id}/steps", response_model=list[AttackChainStepDB])
def list_case_steps(case_id: int, db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.list_case_steps(db_session, case_id=case_id)


@router.get("/cases/{case_id}/full", response_model=AttackChainCaseWithSteps)
def get_case_with_steps(case_id: int, db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.get_case_with_steps(db_session, case_id=case_id)


@router.post("/cases/{case_id}/close")
def close_case(case_id: int, request: Request, admin: PortalPrincipal = Depends(require_admin), db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return service.close_case(db_session, case_id=case_id, request=request, admin=admin, audit_writer=write_audit_event)


@router.get("/allowlist", response_model=list[AttackChainAllowlistDB])
def list_allowlist(
    rule_type: str = Query("sudo_cmd", min_length=1, max_length=32),
    _: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_allowlist(db_session, rule_type=rule_type)


@router.post("/allowlist", response_model=AttackChainAllowlistDB)
def create_allowlist(
    payload: AttackChainAllowlistCreate,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.create_allowlist(db_session, payload=payload, request=request, admin=admin, audit_writer=write_audit_event)


@router.put("/allowlist/{rule_id}", response_model=AttackChainAllowlistDB)
def update_allowlist(
    rule_id: int,
    payload: AttackChainAllowlistUpdate,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.update_allowlist(
            db_session,
            rule_id=rule_id,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )


@router.delete("/allowlist/{rule_id}")
def delete_allowlist(
    rule_id: int,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.delete_allowlist(db_session, rule_id=rule_id, request=request, admin=admin, audit_writer=write_audit_event)
