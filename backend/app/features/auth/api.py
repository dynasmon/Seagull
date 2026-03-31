from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.params import Depends as DependsParam
from sqlalchemy.orm import Session

from app.core.db import SessionLocal, get_db
from app.core.portal_auth import PortalPrincipal, get_current_user, require_admin
from app.features.auth.schemas import LoginIn, OtpCreateIn, OtpCreateOut, OtpLoginIn, TokenOut, UserOut
from app.features.auth import service


router = APIRouter(prefix="/auth", tags=["auth"])


def _resolve_db(db: Session) -> tuple[Session, bool]:
    if isinstance(db, Session):
        return db, False
    if isinstance(db, DependsParam):
        real = SessionLocal()
        return real, True
    return db, False


@router.post("/login", response_model=TokenOut)
def login_endpoint(
    body: LoginIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    db2, owns_db = _resolve_db(db)
    try:
        return service.login(db2, body=body, request=request, response=response)
    finally:
        if owns_db:
            db2.close()


@router.post("/refresh", response_model=TokenOut)
def refresh_endpoint(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    db2, owns_db = _resolve_db(db)
    try:
        return service.refresh(db2, request=request, response=response)
    finally:
        if owns_db:
            db2.close()


@router.post("/logout", status_code=204)
def logout_endpoint(
    request: Request,
    response: Response,
    user: PortalPrincipal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db2, owns_db = _resolve_db(db)
    try:
        service.logout(db2, request=request, response=response, user=user)
    finally:
        if owns_db:
            db2.close()
    return None


@router.post("/logout-all", status_code=204)
def logout_all_endpoint(
    request: Request,
    response: Response,
    user: PortalPrincipal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db2, owns_db = _resolve_db(db)
    try:
        service.logout_all(db2, request=request, response=response, user=user)
    finally:
        if owns_db:
            db2.close()
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
    db2, owns_db = _resolve_db(db)
    try:
        return service.otp_login(db2, body=body, request=request, response=response)
    finally:
        if owns_db:
            db2.close()


@router.post("/otp/create", response_model=OtpCreateOut)
def otp_create_endpoint(
    body: OtpCreateIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db2, owns_db = _resolve_db(db)
    try:
        return service.otp_create(db2, body=body, request=request, admin=admin)
    finally:
        if owns_db:
            db2.close()
