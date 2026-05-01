from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.core.audit import write_audit_event  # backward-compatible symbol for tests
from app.core.db.session import managed_session
from app.core.db import SessionLocal, get_db
from app.features.auth.session import PortalPrincipal, get_current_user, require_admin
from app.features.auth.schemas import LoginIn, OtpCreateIn, OtpCreateOut, OtpLoginIn, TokenOut, UserOut
from app.features.auth import service


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenOut)
def login_endpoint(
    body: LoginIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.login(db_session, body=body, request=request, response=response)


@router.post("/refresh", response_model=TokenOut)
def refresh_endpoint(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.refresh(db_session, request=request, response=response)


@router.post("/logout", status_code=204)
def logout_endpoint(
    request: Request,
    response: Response,
    user: PortalPrincipal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        service.logout(db_session, request=request, response=response, user=user)
    return None


@router.post("/logout-all", status_code=204)
def logout_all_endpoint(
    request: Request,
    response: Response,
    user: PortalPrincipal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        service.logout_all(db_session, request=request, response=response, user=user)
    return None


@router.get("/me", response_model=UserOut)
def me_endpoint(user: PortalPrincipal = Depends(get_current_user)):
    return service.me(user=user)


@router.get("/features")
def auth_features_endpoint():
    return service.auth_features()


@router.post("/otp/login", response_model=TokenOut)
def otp_login_endpoint(
    body: OtpLoginIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.otp_login(db_session, body=body, request=request, response=response)


@router.post("/otp/create", response_model=OtpCreateOut)
def otp_create_endpoint(
    body: OtpCreateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.otp_create(db_session, body=body, request=request, admin=admin)
