from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Request, Response, status

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import constant_time_eq, decode_token
from app.features.auth.models import PortalUserModel

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


def get_current_user(request: Request) -> PortalPrincipal:
    token = _parse_bearer(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")

    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from None

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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from None

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


_RISK_LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_ROLE_MAX_RISK = {"admin": "critical", "analyst": "medium"}


def _role_max_risk_rank(role: str) -> int:
    max_risk = _ROLE_MAX_RISK.get((role or "").lower(), "low")
    return _RISK_LEVEL_ORDER[max_risk]


def require_min_risk_level(min_risk: str):
    required_rank = _RISK_LEVEL_ORDER.get((min_risk or "").lower(), 0)

    def _dependency(user: PortalPrincipal = Depends(get_current_user)) -> PortalPrincipal:
        if _role_max_risk_rank(user.role) < required_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privilege for this action risk level",
            )
        return user

    return _dependency


def _cookie_kwargs() -> dict:
    same_site = (settings.SEAGULL_COOKIE_SAMESITE or "lax").lower()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "lax"

    kw = {
        "httponly": True,
        "secure": bool(settings.SEAGULL_COOKIE_SECURE),
        "samesite": same_site,
        "path": "/",
    }
    if settings.SEAGULL_COOKIE_DOMAIN:
        kw["domain"] = settings.SEAGULL_COOKIE_DOMAIN
    return kw


def _csrf_cookie_kwargs() -> dict:
    same_site = (settings.SEAGULL_COOKIE_SAMESITE or "lax").lower()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "lax"

    kw = {
        "httponly": False,
        "secure": bool(settings.SEAGULL_COOKIE_SECURE),
        "samesite": same_site,
        "path": "/",
    }
    if settings.SEAGULL_COOKIE_DOMAIN:
        kw["domain"] = settings.SEAGULL_COOKIE_DOMAIN
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
    response.delete_cookie(REFRESH_COOKIE_NAME, path="/auth", domain=kw.get("domain"))
    kw2 = _csrf_cookie_kwargs()
    response.delete_cookie(CSRF_COOKIE_NAME, path=kw2.get("path", "/"), domain=kw2.get("domain"))


def verify_refresh_csrf(request: Request) -> None:
    cookie = (request.cookies.get(CSRF_COOKIE_NAME) or "").strip()
    hdr = (request.headers.get("X-CSRF-Token") or request.headers.get("x-csrf-token") or "").strip()
    if not cookie or not hdr or not constant_time_eq(cookie, hdr):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
