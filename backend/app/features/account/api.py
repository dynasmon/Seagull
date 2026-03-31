from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.params import Depends as DependsParam
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event  # backward-compatible symbol for tests
from app.core.db import SessionLocal, get_db
from app.core.portal_auth import PortalPrincipal, get_current_user
from app.features.account.schemas import ChangePasswordIn
from app.features.account import service


router = APIRouter(prefix="/account", tags=["account"])


def _resolve_db(db: Session) -> tuple[Session, bool]:
    if isinstance(db, Session):
        return db, False
    if isinstance(db, DependsParam):
        real = SessionLocal()
        return real, True
    return db, False


@router.post("/change-password", status_code=204)
def change_password_endpoint(
    body: ChangePasswordIn,
    request: Request,
    response: Response,
    principal: PortalPrincipal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db2, owns_db = _resolve_db(db)
    try:
        service.change_password(
            db2,
            body=body,
            request=request,
            response=response,
            principal=principal,
        )
        return None
    finally:
        if owns_db:
            db2.close()
