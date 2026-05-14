from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.audit import audit_actor
from app.core.security import hash_password, verify_password
from app.core.security.password_policy import validate_password_policy
from app.features.account import repository
from app.features.account.schemas import ChangePasswordIn
from app.features.auth.session import PortalPrincipal, _clear_auth_cookies


def change_password(
    db: Session,
    *,
    body: ChangePasswordIn,
    request: Request,
    response: Response,
    principal: PortalPrincipal,
) -> None:
    user = repository.get_user_by_id(db, principal.id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid current password")

    if verify_password(body.new_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different")

    msg = validate_password_policy(body.new_password, username=user.username)
    if msg:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    user.password_hash = hash_password(body.new_password)
    user.token_version = int(getattr(user, "token_version", 1) or 1) + 1
    repository.save_user(db, user)

    repository.revoke_active_refresh_sessions_by_user(db, user_id=user.id, revoked_at=datetime.utcnow())
    repository.record_audit_event(
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
    repository.commit(db)
    _clear_auth_cookies(response)
