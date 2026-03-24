from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.core.audit import audit_actor, write_audit_event
from app.core.db import SessionLocal
from app.core.portal_auth import PortalPrincipal, get_current_user, logout
from app.core.password_policy import validate_password_policy
from app.core.security import hash_password, verify_password
from app.models.portal_refresh_sessions import PortalRefreshSessionModel
from app.models.portal_users import PortalUserModel
from app.schemas.account import ChangePasswordIn


router = APIRouter(prefix="/account", tags=["account"])


@router.post("/change-password", status_code=204)
def change_password_endpoint(
    body: ChangePasswordIn,
    request: Request,
    response: Response,
    principal: PortalPrincipal = Depends(get_current_user),
):
    """Change the current user's password (secure-by-default).

    - Requires a valid Bearer access token (portal session).
    - Verifies current password (prevents session hijack from silently rotating creds).
    - Enforces a basic strong-password policy.
    - Revokes ALL refresh sessions for the user.
    """

    db = SessionLocal()
    try:
        user: PortalUserModel | None = db.get(PortalUserModel, principal.id)
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

        # Verify current password
        if not verify_password(body.current_password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid current password")

        # Policy + prevent reuse
        if verify_password(body.new_password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different")

        msg = validate_password_policy(body.new_password, username=user.username)
        if msg:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

        # Update password
        user.password_hash = hash_password(body.new_password)
        user.token_version = int(getattr(user, "token_version", 1) or 1) + 1
        db.add(user)

        # Revoke all refresh sessions (forces re-login on other devices)
        now = datetime.utcnow()
        db.query(PortalRefreshSessionModel).filter(
            PortalRefreshSessionModel.user_id == user.id,
            PortalRefreshSessionModel.revoked_at.is_(None),
        ).update({"revoked_at": now})

        write_audit_event(
            db,
            request=request,
            actor=audit_actor(principal.id, principal.username),
            event_type="admin_action",
            action="account.change_password",
            resource_type="user",
            resource_id=str(user.id),
            outcome="success",
            before={"id": user.id, "username": user.username},
            after={"id": user.id, "username": user.username, "password_rotated": True},
            context={"revoked_refresh_sessions": True},
        )
        db.commit()

        # Clear cookies for this client as well (best-effort)
        logout(request, response)
        return None
    finally:
        db.close()
