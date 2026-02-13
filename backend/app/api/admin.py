from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.db import SessionLocal
from app.core.portal_auth import PortalPrincipal, require_admin
from app.models.portal_login_events import PortalLoginEventModel
from app.models.portal_users import PortalUserModel
from app.schemas.admin import LoginEventOut


router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/login-history", response_model=list[LoginEventOut])
def admin_login_history(
    limit: int = Query(20, ge=1, le=100),
    include_failed: bool = Query(False),
    admin: PortalPrincipal = Depends(require_admin),
):
    """Return recent login events for admin accounts.

    Only admins can call this endpoint.
    """
    db = SessionLocal()
    try:
        q = (
            db.query(PortalLoginEventModel)
            .join(PortalUserModel, PortalUserModel.username == PortalLoginEventModel.username)
            .filter(PortalUserModel.role == "admin")
            .order_by(PortalLoginEventModel.created_at.desc())
        )
        if not include_failed:
            q = q.filter(PortalLoginEventModel.succeeded.is_(True))
        rows = q.limit(limit).all()

        out: list[LoginEventOut] = []
        for r in rows:
            out.append(
                {
                    "created_at": r.created_at,
                    "username": r.username or "",
                    "method": r.method,
                    "ip": r.ip,
                    "user_agent": r.user_agent,
                    "succeeded": bool(r.succeeded),
                }
            )
        return out
    finally:
        db.close()
