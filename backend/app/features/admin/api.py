from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.db import get_db, routed_db
from app.core.db.session import managed_session
from app.features.admin import service
from app.features.admin.schemas import AdminAuditQueryOut, LoginEventOut, RuntimeConfigOut
from app.features.auth.session import PortalPrincipal, require_admin

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/audit/events", response_model=AdminAuditQueryOut)
def admin_audit_events(
    limit: int = Query(100, ge=1, le=500),
    event_type: str | None = Query(None),
    action: str | None = Query(None),
    outcome: str | None = Query(None),
    resource_type: str | None = Query(None),
    actor_username: str | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    _: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(routed_db("admin-audit-events")),
):
    with managed_session(db) as db_session:
        return service.admin_audit_events(
            db_session,
            limit=limit,
            event_type=event_type,
            action=action,
            outcome=outcome,
            resource_type=resource_type,
            actor_username=actor_username,
            since=since,
            until=until,
        )


@router.get("/runtime-config", response_model=RuntimeConfigOut)
def admin_runtime_config(_: PortalPrincipal = Depends(require_admin)):
    return service.admin_runtime_config()


@router.get("/login-history", response_model=list[LoginEventOut])
def admin_login_history(
    limit: int = Query(20, ge=1, le=100),
    include_failed: bool = Query(False),
    _: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(routed_db("admin-login-history")),
):
    with managed_session(db) as db_session:
        return service.admin_login_history(db_session, limit=limit, include_failed=include_failed)


@router.get("/system-status")
def admin_system_status(
    _: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.admin_system_status(db_session)


@router.get("/metrics-snapshot")
def admin_metrics_snapshot(_: PortalPrincipal = Depends(require_admin)):
    return service.admin_metrics_snapshot()
