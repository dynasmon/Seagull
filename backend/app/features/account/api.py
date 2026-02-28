from __future__ import annotations

import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.core.db import SessionLocal
from app.core.portal_auth import PortalPrincipal, get_current_user, logout
from app.core.security import hash_password, verify_password
from app.models.portal_refresh_sessions import PortalRefreshSessionModel
from app.models.portal_users import PortalUserModel
from app.schemas.account import ChangePasswordIn


router = APIRouter(prefix="/account", tags=["account"])


def _password_policy(pw: str, *, username: str) -> str | None:
    # Returns an error message if invalid, else None.
    if len(pw) < 12:
        return "Password must be at least 12 characters."
    if any(ch.isspace() for ch in pw):
        return "Password cannot contain whitespace."
    if username and username.lower() in pw.lower():
        return "Password must not contain your username."
    if not re.search(r"[a-z]", pw):
        return "Password must include at least one lowercase letter."
    if not re.search(r"[A-Z]", pw):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[0-9]", pw):
        return "Password must include at least one digit."
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "Password must include at least one symbol."
    return None


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

        msg = _password_policy(body.new_password, username=user.username)
        if msg:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

        # Update password
        user.password_hash = hash_password(body.new_password)
        db.add(user)

        # Revoke all refresh sessions (forces re-login on other devices)
        now = datetime.utcnow()
        db.query(PortalRefreshSessionModel).filter(
            PortalRefreshSessionModel.user_id == user.id,
            PortalRefreshSessionModel.revoked_at.is_(None),
        ).update({"revoked_at": now})

        db.commit()

        # Clear cookies for this client as well (best-effort)
        logout(request, response)
        return None
    finally:
        db.close()
