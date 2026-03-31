from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from fastapi.params import Depends as DependsParam
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event  # backward-compatible symbol for tests
from app.core.db import SessionLocal, get_db
from app.core.portal_auth import PortalPrincipal, require_admin
from app.features.users.schemas import AdminUserCreateIn, AdminUserOut, AdminUserUpdateIn
from app.features.users import service


router = APIRouter(prefix="/users", tags=["users"])


def _resolve_db(db: Session) -> tuple[Session, bool]:
    if isinstance(db, Session):
        return db, False
    if isinstance(db, DependsParam):
        real = SessionLocal()
        return real, True
    return db, False


@router.get("", response_model=list[AdminUserOut])
def list_users(
    _: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db2, owns_db = _resolve_db(db)
    try:
        return service.list_users(db2)
    finally:
        if owns_db:
            db2.close()


@router.post("", response_model=AdminUserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: AdminUserCreateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db2, owns_db = _resolve_db(db)
    try:
        return service.create_user(db2, payload=payload, request=request, admin=admin)
    finally:
        if owns_db:
            db2.close()


@router.put("/{user_id}", response_model=AdminUserOut)
def update_user(
    user_id: int,
    payload: AdminUserUpdateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db2, owns_db = _resolve_db(db)
    try:
        return service.update_user(db2, user_id=user_id, payload=payload, request=request, admin=admin)
    finally:
        if owns_db:
            db2.close()


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db2, owns_db = _resolve_db(db)
    try:
        service.delete_user(db2, user_id=user_id, request=request, admin=admin)
        return None
    finally:
        if owns_db:
            db2.close()
