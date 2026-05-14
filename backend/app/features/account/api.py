from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.db.session import managed_session
from app.features.account import service
from app.features.account.schemas import ChangePasswordIn
from app.features.auth.session import PortalPrincipal, get_current_user

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
