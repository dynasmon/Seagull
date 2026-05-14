from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.audit import audit_actor
from app.core.security import hash_password
from app.core.security.identity import canonicalize_username
from app.core.security.password_policy import validate_password_policy
from app.features.auth.models import PortalUserModel
from app.features.auth.session import PortalPrincipal
from app.features.users import repository
from app.features.users.schemas import AdminUserCreateIn, AdminUserOut, AdminUserUpdateIn


def _normalize_role(role: str | None) -> str:
    r = (role or "").strip().lower()
    if r not in {"admin", "user"}:
        raise HTTPException(status_code=422, detail="role must be one of: admin, user")
    return r


def _to_out(row: PortalUserModel) -> AdminUserOut:
    return AdminUserOut(
        id=row.id,
        username=row.username,
        role=row.role,
        is_active=bool(row.is_active),
        created_at=row.created_at,
        last_login_at=row.last_login_at,
        failed_login_count=int(row.failed_login_count or 0),
    )


def list_users(db: Session) -> list[AdminUserOut]:
    rows = repository.list_users(db)
    return [_to_out(r) for r in rows]


def create_user(db: Session, *, payload: AdminUserCreateIn, request, admin: PortalPrincipal) -> AdminUserOut:
    uname = canonicalize_username(payload.username)
    if not uname:
        raise HTTPException(status_code=422, detail="username is required")

    msg = validate_password_policy(payload.password, username=uname)
    if msg:
        raise HTTPException(status_code=422, detail=msg)

    exists = repository.get_user_by_username(db, uname)
    if exists:
        raise HTTPException(status_code=409, detail="username already exists")

    row = repository.create_user(
        db,
        username=uname,
        password_hash=hash_password(payload.password),
        role=_normalize_role(payload.role),
        is_active=bool(payload.is_active),
        created_at=datetime.utcnow(),
    )
    repository.flush(db)
    repository.record_audit_event(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="users.create",
        resource_type="user",
        resource_id=str(row.id),
        outcome="success",
        after={"id": row.id, "username": row.username, "role": row.role, "is_active": bool(row.is_active)},
        reason=payload.reason,
        context={"username": row.username},
    )
    repository.commit(db)
    repository.refresh(db, row)
    return _to_out(row)


def update_user(
    db: Session,
    *,
    user_id: int,
    payload: AdminUserUpdateIn,
    request,
    admin: PortalPrincipal,
) -> AdminUserOut:
    row = repository.get_user(db, int(user_id))
    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    before = {"id": row.id, "username": row.username, "role": row.role, "is_active": bool(row.is_active)}

    if payload.role is not None:
        row.role = _normalize_role(payload.role)
    if payload.is_active is not None:
        if row.id == admin.id and payload.is_active is False:
            raise HTTPException(status_code=400, detail="You cannot disable your own account")
        row.is_active = bool(payload.is_active)
    if payload.password is not None:
        msg = validate_password_policy(payload.password, username=row.username)
        if msg:
            raise HTTPException(status_code=422, detail=msg)
        row.password_hash = hash_password(payload.password)
        row.failed_login_count = 0
        row.token_version = int(getattr(row, "token_version", 1) or 1) + 1

    if payload.password is not None or payload.is_active is False:
        repository.revoke_active_refresh_sessions_by_user(db, user_id=row.id, revoked_at=datetime.utcnow())
        if payload.is_active is False and payload.password is None:
            row.token_version = int(getattr(row, "token_version", 1) or 1) + 1

    if row.role != "admin":
        admins_active = repository.count_active_admins_excluding(db, row.id)
        if admins_active < 1:
            raise HTTPException(status_code=400, detail="At least one active admin is required")

    repository.save_user(db, row)
    repository.flush(db)
    after = {"id": row.id, "username": row.username, "role": row.role, "is_active": bool(row.is_active)}
    repository.record_audit_event(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="users.update",
        resource_type="user",
        resource_id=str(row.id),
        outcome="success",
        before=before,
        after=after,
        reason=payload.reason,
        context={"username": row.username, "password_rotated": payload.password is not None},
    )
    repository.commit(db)
    repository.refresh(db, row)
    return _to_out(row)


def delete_user(db: Session, *, user_id: int, request, admin: PortalPrincipal) -> None:
    row = repository.get_user(db, int(user_id))
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    if row.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    if row.role == "admin":
        admins_active = repository.count_active_admins_excluding(db, row.id)
        if admins_active < 1:
            raise HTTPException(status_code=400, detail="At least one active admin is required")

    before = {"id": row.id, "username": row.username, "role": row.role, "is_active": bool(row.is_active)}
    repository.deactivate_user(db, row)
    repository.revoke_active_refresh_sessions_by_user(db, user_id=row.id, revoked_at=datetime.utcnow())
    repository.flush(db)
    repository.record_audit_event(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="users.delete",
        resource_type="user",
        resource_id=str(row.id),
        outcome="success",
        before=before,
        after={"id": row.id, "username": row.username, "role": row.role, "is_active": False},
        context={"username": row.username, "deletion_mode": "soft_delete"},
    )
    repository.commit(db)
