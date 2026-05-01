from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event  # backward-compatible symbol for tests
from app.core.db.session import managed_session
from app.core.db import SessionLocal, get_db
from app.features.auth.session import PortalPrincipal, require_admin
from app.features.users.schemas import AdminUserCreateIn, AdminUserOut, AdminUserUpdateIn
from app.features.users import service


router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[AdminUserOut])
def list_users(
    _: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.list_users(db_session)


@router.post("", response_model=AdminUserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: AdminUserCreateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.create_user(db_session, payload=payload, request=request, admin=admin)


@router.put("/{user_id}", response_model=AdminUserOut)
def update_user(
    user_id: int,
    payload: AdminUserUpdateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.update_user(db_session, user_id=user_id, payload=payload, request=request, admin=admin)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        service.delete_user(db_session, user_id=user_id, request=request, admin=admin)
        return None
