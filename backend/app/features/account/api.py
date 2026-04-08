from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event  # backward-compatible symbol for tests
from app.core.api_db import managed_session
from app.core.db import get_db
from app.core.portal_auth import PortalPrincipal, get_current_user
from app.features.account.schemas import ChangePasswordIn
from app.features.account import service


router = APIRouter(prefix="/account", tags=["account"])


@router.post("/change-password", status_code=204)
def change_password_endpoint(
    body: ChangePasswordIn,
    request: Request,
    response: Response,
    principal: PortalPrincipal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        service.change_password(
            db_session,
            body=body,
            request=request,
            response=response,
            principal=principal,
        )
        return None
