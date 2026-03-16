from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.audit import audit_actor, write_audit_event
from app.core.db import SessionLocal
from app.core.portal_auth import PortalPrincipal, require_admin
from app.core.security import hash_password
from app.models.portal_refresh_sessions import PortalRefreshSessionModel
from app.models.portal_users import PortalUserModel
from app.schemas.users import AdminUserCreateIn, AdminUserOut, AdminUserUpdateIn


router = APIRouter(prefix="/users", tags=["users"])


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


@router.get("", response_model=list[AdminUserOut])
def list_users(_: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        rows = db.query(PortalUserModel).order_by(PortalUserModel.username.asc()).all()
        return [_to_out(r) for r in rows]
    finally:
        db.close()


@router.post("", response_model=AdminUserOut, status_code=status.HTTP_201_CREATED)
def create_user(payload: AdminUserCreateIn, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        uname = (payload.username or "").strip()
        if not uname:
            raise HTTPException(status_code=422, detail="username is required")
        exists = db.query(PortalUserModel).filter(PortalUserModel.username == uname).first()
        if exists:
            raise HTTPException(status_code=409, detail="username already exists")

        row = PortalUserModel(
            username=uname,
            password_hash=hash_password(payload.password),
            role=_normalize_role(payload.role),
            is_active=bool(payload.is_active),
            created_at=datetime.utcnow(),
        )
        db.add(row)
        db.flush()
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="users.create",
            resource_type="user",
            resource_id=str(row.id),
            outcome="success",
            before={},
            after={"id": row.id, "username": row.username, "role": row.role, "is_active": bool(row.is_active)},
            reason=payload.reason,
            context={"username": row.username},
        )
        db.commit()
        db.refresh(row)
        return _to_out(row)
    finally:
        db.close()


@router.put("/{user_id}", response_model=AdminUserOut)
def update_user(user_id: int, payload: AdminUserUpdateIn, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        row = db.get(PortalUserModel, int(user_id))
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
            row.password_hash = hash_password(payload.password)
            row.failed_login_count = 0

        if payload.password is not None or payload.is_active is False:
            now = datetime.utcnow()
            db.query(PortalRefreshSessionModel).filter(
                PortalRefreshSessionModel.user_id == row.id,
                PortalRefreshSessionModel.revoked_at.is_(None),
            ).update({"revoked_at": now})

        if row.role != "admin":
            admins_active = (
                db.query(PortalUserModel)
                .filter(PortalUserModel.role == "admin", PortalUserModel.is_active.is_(True), PortalUserModel.id != row.id)
                .count()
            )
            if admins_active < 1:
                raise HTTPException(status_code=400, detail="At least one active admin is required")

        db.add(row)
        db.flush()
        after = {"id": row.id, "username": row.username, "role": row.role, "is_active": bool(row.is_active)}
        write_audit_event(
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
        db.commit()
        db.refresh(row)
        return _to_out(row)
    finally:
        db.close()


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        row = db.get(PortalUserModel, int(user_id))
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        if row.id == admin.id:
            raise HTTPException(status_code=400, detail="You cannot delete your own account")
        if row.role == "admin":
            admins_active = (
                db.query(PortalUserModel)
                .filter(PortalUserModel.role == "admin", PortalUserModel.is_active.is_(True), PortalUserModel.id != row.id)
                .count()
            )
            if admins_active < 1:
                raise HTTPException(status_code=400, detail="At least one active admin is required")

        before = {"id": row.id, "username": row.username, "role": row.role, "is_active": bool(row.is_active)}
        row.is_active = False
        db.add(row)
        now = datetime.utcnow()
        db.query(PortalRefreshSessionModel).filter(
            PortalRefreshSessionModel.user_id == row.id,
            PortalRefreshSessionModel.revoked_at.is_(None),
        ).update({"revoked_at": now})
        db.flush()
        write_audit_event(
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
        db.commit()
        return None
    finally:
        db.close()
