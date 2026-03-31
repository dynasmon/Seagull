from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from app.core.audit import write_audit_event
from app.core.db import SessionLocal
from app.core.portal_auth import PortalPrincipal, require_admin
from app.features.response.schemas import ResponseActionCreateIn, ResponseActionOut
from app.features.response import service


router = APIRouter(prefix="/response", tags=["response"])


@router.post("/actions", response_model=ResponseActionOut, status_code=status.HTTP_201_CREATED)
def create_response_action(
    payload: ResponseActionCreateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
):
    db = SessionLocal()
    try:
        return service.create_response_action(
            db,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()
