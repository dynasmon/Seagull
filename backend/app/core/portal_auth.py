from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import (
    constant_time_eq,
    decode_token,
    make_access_token,
    new_csrf_token,
    new_refresh_token,
    token_hash,
)
from app.models.portal_refresh_sessions import PortalRefreshSessionModel
from app.models.portal_users import PortalUserModel


REFRESH_COOKIE_NAME = "nw_refresh"
CSRF_COOKIE_NAME = "nw_csrf"


@dataclass(frozen=True)
class PortalPrincipal:
    id: int
    username: str
    role: str

    @property
    def is_admin(self) -> bool:
        return (self.role or "").lower() == "admin"


def _parse_bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth:
        return None
    parts = auth.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0].strip().lower(), parts[1].strip()
    if scheme != "bearer" or not token:
        return None
    return token


def _client_meta(request: Request) -> Tuple[str, str]:
    ip = (request.client.host if request.client else "") or "unknown"
    ua = (request.headers.get("user-agent") or "")[:256]
    return ip, ua


def get_current_user(request: Request) -> PortalPrincipal:
    token = _parse_bearer(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")

    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")

    if (payload.get("typ") or "") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")

    sub = str(payload.get("sub") or "").strip()
    if not sub.isdigit():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")

    uid = int(sub, 10)
    token_version_raw = payload.get("tv")
    try:
        token_version = int(token_version_raw)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")

    db = SessionLocal()
    try:
        row: PortalUserModel | None = db.get(PortalUserModel, uid)
        if not row or not row.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
        if int(getattr(row, "token_version", 1) or 1) != token_version:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
        return PortalPrincipal(id=row.id, username=row.username, role=row.role)
    finally:
        db.close()


def require_admin(user: PortalPrincipal = Depends(get_current_user)) -> PortalPrincipal:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user


def _cookie_kwargs() -> dict:
    same_site = (settings.NETWATCH_COOKIE_SAMESITE or "lax").lower()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "lax"

    kw = {
        "httponly": True,
        "secure": bool(settings.NETWATCH_COOKIE_SECURE),
        "samesite": same_site,
        # Keep refresh cookie valid for both direct backend routes (/auth/*)
        # and reverse-proxied routes (/api/auth/*), avoiding session drops on reload.
        "path": "/",
    }
    if settings.NETWATCH_COOKIE_DOMAIN:
        kw["domain"] = settings.NETWATCH_COOKIE_DOMAIN
    return kw


def _csrf_cookie_kwargs() -> dict:
    same_site = (settings.NETWATCH_COOKIE_SAMESITE or "lax").lower()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "lax"

    kw = {
        "httponly": False,
        "secure": bool(settings.NETWATCH_COOKIE_SECURE),
        "samesite": same_site,
        "path": "/",
    }
    if settings.NETWATCH_COOKIE_DOMAIN:
        kw["domain"] = settings.NETWATCH_COOKIE_DOMAIN
    return kw


def _set_refresh_cookie(response: Response, refresh_token: str, *, max_age_seconds: int) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=max_age_seconds,
        **_cookie_kwargs(),
    )


def _set_csrf_cookie(response: Response, csrf_token: str, *, max_age_seconds: int) -> None:
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age_seconds,
        **_csrf_cookie_kwargs(),
    )


def _clear_auth_cookies(response: Response) -> None:
    kw = _cookie_kwargs()
    response.delete_cookie(REFRESH_COOKIE_NAME, path=kw.get("path", "/"), domain=kw.get("domain"))
    # Backward compatibility for older deployments that scoped refresh cookie to /auth.
    response.delete_cookie(REFRESH_COOKIE_NAME, path="/auth", domain=kw.get("domain"))
    kw2 = _csrf_cookie_kwargs()
    response.delete_cookie(CSRF_COOKIE_NAME, path=kw2.get("path", "/"), domain=kw2.get("domain"))


def _make_session(
    *,
    user_id: int,
    refresh_token: str,
    ttl_seconds: int,
    request: Request,
    family_id: Optional[str] = None,
) -> PortalRefreshSessionModel:
    now = datetime.utcnow()
    ip, ua = _client_meta(request)
    sid = str(uuid.uuid4())
    fam = family_id or str(uuid.uuid4())
    return PortalRefreshSessionModel(
        id=sid,
        family_id=fam,
        user_id=user_id,
        token_hash=token_hash(refresh_token),
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        revoked_at=None,
        replaced_by_id=None,
        last_ip=ip,
        last_user_agent=ua,
    )


def issue_login_tokens(
    response: Response,
    *,
    user: PortalUserModel,
    request: Request,
    db: Optional[Session] = None,
) -> dict:
    token_version = int(getattr(user, "token_version", 1) or 1)
    access = make_access_token(
        sub=str(user.id),
        ttl_seconds=settings.NETWATCH_ACCESS_TOKEN_TTL_SECONDS,
        extra={"tv": token_version},
    )

    refresh = new_refresh_token()
    csrf = new_csrf_token()

    owns_db = db is None
    db2 = db or SessionLocal()
    try:
        sess = _make_session(user_id=user.id, refresh_token=refresh, ttl_seconds=settings.NETWATCH_REFRESH_TOKEN_TTL_SECONDS, request=request)
        db2.add(sess)
        if owns_db:
            db2.commit()
    finally:
        if owns_db:
            db2.close()

    _set_refresh_cookie(response, refresh, max_age_seconds=settings.NETWATCH_REFRESH_TOKEN_TTL_SECONDS)
    _set_csrf_cookie(response, csrf, max_age_seconds=settings.NETWATCH_REFRESH_TOKEN_TTL_SECONDS)

    return {
        "access_token": access,
        "token_type": "bearer",
        "expires_in": settings.NETWATCH_ACCESS_TOKEN_TTL_SECONDS,
        "user": {"id": user.id, "username": user.username, "role": user.role},
    }


def verify_refresh_csrf(request: Request) -> None:
    cookie = (request.cookies.get(CSRF_COOKIE_NAME) or "").strip()
    hdr = (request.headers.get("X-CSRF-Token") or request.headers.get("x-csrf-token") or "").strip()
    if not cookie or not hdr or not constant_time_eq(cookie, hdr):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")


def refresh_access_token(request: Request, response: Response) -> dict:
    verify_refresh_csrf(request)

    raw = (request.cookies.get(REFRESH_COOKIE_NAME) or "").strip()
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")

    h = token_hash(raw)
    now = datetime.utcnow()
    ip, ua = _client_meta(request)

    db = SessionLocal()
    try:
        sess: PortalRefreshSessionModel | None = db.query(PortalRefreshSessionModel).filter(PortalRefreshSessionModel.token_hash == h).first()

        # Token reuse detection: if a rotated token is replayed, revoke the whole family.
        if sess and sess.revoked_at is not None and sess.replaced_by_id:
            fam = sess.family_id
            db.query(PortalRefreshSessionModel).filter(PortalRefreshSessionModel.family_id == fam).update({"revoked_at": now})
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked")

        if not sess or sess.revoked_at is not None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        if sess.expires_at <= now:
            sess.revoked_at = now
            db.add(sess)
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

        user: PortalUserModel | None = db.get(PortalUserModel, sess.user_id)
        if not user or not user.is_active:
            sess.revoked_at = now
            db.add(sess)
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

        # Rotate refresh token
        new_refresh = new_refresh_token()
        new_sess = _make_session(
            user_id=user.id,
            refresh_token=new_refresh,
            ttl_seconds=settings.NETWATCH_REFRESH_TOKEN_TTL_SECONDS,
            request=request,
            family_id=sess.family_id,
        )

        sess.revoked_at = now
        sess.replaced_by_id = new_sess.id
        sess.last_ip = ip
        sess.last_user_agent = ua

        db.add(sess)
        db.add(new_sess)
        db.commit()

        csrf = new_csrf_token()
        _set_refresh_cookie(response, new_refresh, max_age_seconds=settings.NETWATCH_REFRESH_TOKEN_TTL_SECONDS)
        _set_csrf_cookie(response, csrf, max_age_seconds=settings.NETWATCH_REFRESH_TOKEN_TTL_SECONDS)

        token_version = int(getattr(user, "token_version", 1) or 1)
        access = make_access_token(
            sub=str(user.id),
            ttl_seconds=settings.NETWATCH_ACCESS_TOKEN_TTL_SECONDS,
            extra={"tv": token_version},
        )
        return {
            "access_token": access,
            "token_type": "bearer",
            "expires_in": settings.NETWATCH_ACCESS_TOKEN_TTL_SECONDS,
            "user": {"id": user.id, "username": user.username, "role": user.role},
        }
    finally:
        db.close()


def logout(request: Request, response: Response) -> None:
    raw = (request.cookies.get(REFRESH_COOKIE_NAME) or "").strip()
    if raw:
        h = token_hash(raw)
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            sess: PortalRefreshSessionModel | None = db.query(PortalRefreshSessionModel).filter(PortalRefreshSessionModel.token_hash == h).first()
            if sess and sess.revoked_at is None:
                sess.revoked_at = now
                db.add(sess)
                db.commit()
        finally:
            db.close()

    _clear_auth_cookies(response)


def logout_all(request: Request, response: Response, *, user_id: int) -> None:
    now = datetime.utcnow()
    db = SessionLocal()
    try:
        db.query(PortalRefreshSessionModel).filter(
            PortalRefreshSessionModel.user_id == int(user_id),
            PortalRefreshSessionModel.revoked_at.is_(None),
        ).update({"revoked_at": now})
        user: PortalUserModel | None = db.get(PortalUserModel, int(user_id))
        if user:
            user.token_version = int(getattr(user, "token_version", 1) or 1) + 1
            db.add(user)
        db.commit()
    finally:
        db.close()
    _clear_auth_cookies(response)
