from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import NoReturn

from fastapi import HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.audit import audit_actor
from app.core.config import settings
from app.core.observability.metrics import incr_counter
from app.core.security import (
    make_access_token,
    new_csrf_token,
    new_one_time_token,
    new_refresh_token,
    token_hash,
    verify_and_upgrade_password,
)
from app.core.security.identity import canonicalize_username
from app.core.security.rate_limit import guard_login_rate_limit, guard_otp_rate_limit
from app.features.auth import repository
from app.features.auth.models import PortalUserModel
from app.features.auth.schemas import LoginIn, OtpCreateIn, OtpLoginIn
from app.features.auth.session import (
    REFRESH_COOKIE_NAME,
    PortalPrincipal,
    _clear_auth_cookies,
    _set_csrf_cookie,
    _set_refresh_cookie,
    verify_refresh_csrf,
)


def _client_meta(request: Request) -> tuple[str, str]:
    ip = (request.client.host if request.client else "") or "unknown"
    ua = (request.headers.get("user-agent") or "")[:256]
    return ip, ua


def _commit_quietly(db: Session) -> None:
    try:
        repository.commit(db)
    except Exception:
        try:
            repository.rollback(db)
        except Exception:
            pass


def _make_token_payload(*, user: PortalUserModel) -> dict:
    token_version = int(getattr(user, "token_version", 1) or 1)
    return {
        "access_token": make_access_token(
            sub=str(user.id),
            ttl_seconds=settings.SEAGULL_ACCESS_TOKEN_TTL_SECONDS,
            extra={"tv": token_version},
        ),
        "token_type": "bearer",
        "expires_in": settings.SEAGULL_ACCESS_TOKEN_TTL_SECONDS,
        "user": {"id": user.id, "username": user.username, "role": user.role},
    }


def _create_refresh_session(
    db: Session,
    *,
    user_id: int,
    request: Request,
    response: Response,
    session_id: str | None = None,
    family_id: str | None = None,
) -> None:
    now = datetime.utcnow()
    ip, ua = _client_meta(request)
    raw_refresh = new_refresh_token()
    csrf = new_csrf_token()
    repository.create_refresh_session(
        db,
        session_id=(session_id or str(uuid.uuid4())),
        user_id=user_id,
        token_hash_value=token_hash(raw_refresh),
        created_at=now,
        expires_at=now + timedelta(seconds=settings.SEAGULL_REFRESH_TOKEN_TTL_SECONDS),
        family_id=(family_id or str(uuid.uuid4())),
        last_ip=ip,
        last_user_agent=ua,
    )
    _set_refresh_cookie(response, raw_refresh, max_age_seconds=settings.SEAGULL_REFRESH_TOKEN_TTL_SECONDS)
    _set_csrf_cookie(response, csrf, max_age_seconds=settings.SEAGULL_REFRESH_TOKEN_TTL_SECONDS)


def _audit_login_event(
    db: Session,
    *,
    request: Request,
    method: str,
    succeeded: bool,
    user_id: int | None,
    username: str | None,
    reason: str | None = None,
) -> None:
    try:
        ip, ua = _client_meta(request)
        repository.create_login_event(
            db,
            user_id=user_id,
            username=username,
            method=method,
            succeeded=succeeded,
            ip=ip,
            user_agent=ua,
            created_at=datetime.utcnow(),
        )
        repository.record_audit_event(
            db,
            request=request,
            actor=audit_actor(user_id=user_id, username=username),
            event_type="auth",
            action=f"auth.login.{method}",
            resource_type="auth_session",
            resource_id=(str(user_id) if user_id is not None else None),
            outcome=("success" if succeeded else "failure"),
            after={"method": method, "succeeded": bool(succeeded)},
            context={"ip": ip, "user_agent": ua},
            reason=(None if succeeded else (reason or "login_failed")),
        )
    except Exception:
        return


def _audit_refresh_event(
    db: Session,
    *,
    request: Request,
    succeeded: bool,
    user_id: int | None,
    username: str | None,
    reason: str | None = None,
    error: str | None = None,
) -> None:
    try:
        repository.record_audit_event(
            db,
            request=request,
            actor=audit_actor(user_id=user_id, username=username),
            event_type="auth",
            action="auth.refresh",
            resource_type="auth_session",
            resource_id=(str(user_id) if user_id is not None else None),
            outcome=("success" if succeeded else "failure"),
            after=({"token_refreshed": True} if succeeded else {}),
            reason=reason,
            error=error,
        )
    except Exception:
        return


def login(db: Session, *, body: LoginIn, request: Request, response: Response) -> dict:
    username = canonicalize_username(body.username)
    guard_login_rate_limit(request, username=username)

    user = repository.get_user_by_username(db, username)
    if not user or not user.is_active:
        _audit_login_event(
            db,
            request=request,
            method="password",
            succeeded=False,
            user_id=None,
            username=username,
            reason="invalid_credentials",
        )
        _commit_quietly(db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    verified, upgraded_hash = verify_and_upgrade_password(body.password, user.password_hash)
    if not verified:
        try:
            user.failed_login_count = int(user.failed_login_count or 0) + 1
            repository.save_user(db, user)
        except Exception:
            pass
        _audit_login_event(
            db,
            request=request,
            method="password",
            succeeded=False,
            user_id=user.id,
            username=username,
            reason="invalid_credentials",
        )
        _commit_quietly(db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if upgraded_hash:
        user.password_hash = upgraded_hash
    user.failed_login_count = 0
    user.last_login_at = datetime.utcnow()
    repository.save_user(db, user)
    _audit_login_event(db, request=request, method="password", succeeded=True, user_id=user.id, username=user.username)
    _create_refresh_session(db, user_id=user.id, request=request, response=response)
    payload = _make_token_payload(user=user)
    repository.commit(db)
    return payload


def _reject_refresh(db: Session, *, request: Request, detail: str, outcome: str) -> NoReturn:
    incr_counter("auth_refresh_rotation_total", outcome=outcome)
    _audit_refresh_event(db, request=request, succeeded=False, user_id=None, username=None, reason=detail, error="http_401")
    repository.commit(db)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def refresh(db: Session, *, request: Request, response: Response) -> dict:
    verify_refresh_csrf(request)
    raw_refresh = (request.cookies.get(REFRESH_COOKIE_NAME) or "").strip()
    if not raw_refresh:
        _reject_refresh(db, request=request, detail="Missing refresh token", outcome="missing")

    now = datetime.utcnow()
    ip, ua = _client_meta(request)
    current = repository.get_refresh_session_by_token_hash(db, token_hash(raw_refresh))

    if current and current.revoked_at is not None and current.replaced_by_id:
        repository.revoke_refresh_family(db, family_id=current.family_id, revoked_at=now)
        _reject_refresh(db, request=request, detail="Session revoked", outcome="reuse_detected")

    if not current or current.revoked_at is not None:
        _reject_refresh(db, request=request, detail="Invalid refresh token", outcome="invalid")

    if current.expires_at <= now:
        repository.revoke_refresh_session(db, session_id=current.id, revoked_at=now)
        _reject_refresh(db, request=request, detail="Refresh token expired", outcome="expired")

    user = repository.get_user_by_id(db, current.user_id)
    if not user or not user.is_active:
        repository.revoke_refresh_session(db, session_id=current.id, revoked_at=now)
        _reject_refresh(db, request=request, detail="Unauthorized", outcome="unauthorized")

    successor_id = str(uuid.uuid4())
    rotated = repository.revoke_refresh_session(
        db,
        session_id=current.id,
        revoked_at=now,
        replaced_by_id=successor_id,
        last_ip=ip,
        last_user_agent=ua,
    )
    if not rotated:
        _reject_refresh(db, request=request, detail="Invalid refresh token", outcome="lost_race")

    _create_refresh_session(
        db,
        user_id=user.id,
        request=request,
        response=response,
        session_id=successor_id,
        family_id=current.family_id,
    )
    _audit_refresh_event(db, request=request, succeeded=True, user_id=user.id, username=user.username)
    payload = _make_token_payload(user=user)
    incr_counter("auth_refresh_rotation_total", outcome="rotated")
    repository.commit(db)
    return payload


def logout(db: Session, *, request: Request, response: Response, user: PortalPrincipal) -> None:
    raw_refresh = (request.cookies.get(REFRESH_COOKIE_NAME) or "").strip()
    if raw_refresh:
        current = repository.get_refresh_session_by_token_hash(db, token_hash(raw_refresh))
        if current:
            repository.revoke_refresh_session(db, session_id=current.id, revoked_at=datetime.utcnow())

    _clear_auth_cookies(response)
    try:
        repository.record_audit_event(
            db,
            request=request,
            actor=audit_actor(user_id=user.id, username=user.username),
            event_type="auth",
            action="auth.logout",
            resource_type="auth_session",
            resource_id=str(user.id),
            outcome="success",
            after={"logged_out": True},
        )
    except Exception:
        pass
    _commit_quietly(db)


def logout_all(db: Session, *, request: Request, response: Response, user: PortalPrincipal) -> None:
    now = datetime.utcnow()
    repository.revoke_active_refresh_sessions_by_user(db, user_id=user.id, revoked_at=now)
    row = repository.get_user_by_id(db, user.id)
    if row:
        row.token_version = int(getattr(row, "token_version", 1) or 1) + 1
        repository.save_user(db, row)

    _clear_auth_cookies(response)
    try:
        repository.record_audit_event(
            db,
            request=request,
            actor=audit_actor(user_id=user.id, username=user.username),
            event_type="auth",
            action="auth.logout_all",
            resource_type="auth_session",
            resource_id=str(user.id),
            outcome="success",
            after={"logged_out_all": True},
        )
    except Exception:
        pass
    _commit_quietly(db)


def me(*, user: PortalPrincipal) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role}


def auth_features() -> dict:
    return {"otp_enabled": bool(settings.SEAGULL_AUTH_OTP_ENABLED)}


def _reject_otp_login(
    db: Session,
    *,
    request: Request,
    user_id: int | None,
    username: str | None,
    outcome: str,
) -> NoReturn:
    incr_counter("auth_one_time_token_login_total", outcome=outcome)
    _audit_login_event(
        db,
        request=request,
        method="otp",
        succeeded=False,
        user_id=user_id,
        username=username,
        reason="invalid_token",
    )
    _commit_quietly(db)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def otp_login(db: Session, *, body: OtpLoginIn, request: Request, response: Response) -> dict:
    if not settings.SEAGULL_AUTH_OTP_ENABLED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    guard_otp_rate_limit(request)

    raw = (body.token or "").strip()
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    now = datetime.utcnow()
    row = repository.get_one_time_token_by_hash(db, token_hash(raw))
    if not row or row.revoked_at is not None or row.used_at is not None or row.expires_at <= now:
        _reject_otp_login(db, request=request, user_id=None, username=None, outcome="invalid")

    user = repository.get_user_by_id(db, row.user_id)
    if not user or not user.is_active:
        _reject_otp_login(
            db,
            request=request,
            user_id=(user.id if user else None),
            username=(user.username if user else None),
            outcome="unauthorized",
        )

    ip, ua = _client_meta(request)
    consumed = repository.consume_one_time_token(
        db,
        token_id=row.id,
        used_at=now,
        used_ip=ip,
        used_user_agent=ua,
    )
    if not consumed:
        _reject_otp_login(db, request=request, user_id=user.id, username=user.username, outcome="lost_race")

    user.last_login_at = now
    repository.save_user(db, user)
    _audit_login_event(db, request=request, method="otp", succeeded=True, user_id=user.id, username=user.username)
    _create_refresh_session(db, user_id=user.id, request=request, response=response)
    payload = _make_token_payload(user=user)
    incr_counter("auth_one_time_token_login_total", outcome="consumed")
    repository.commit(db)
    return payload


def otp_create(
    db: Session,
    *,
    body: OtpCreateIn,
    request: Request,
    admin: PortalPrincipal,
) -> dict:
    if not settings.SEAGULL_AUTH_OTP_ENABLED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if body.username:
        target_username = canonicalize_username(body.username)
        target_user = repository.get_user_by_username(db, target_username)
    else:
        target_user = repository.get_user_by_id(db, admin.id)

    if not target_user or not target_user.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    token = new_one_time_token()
    now = datetime.utcnow()
    expires_in = int(settings.SEAGULL_OTP_TOKEN_TTL_SECONDS)
    row = repository.create_one_time_token(
        db,
        user_id=target_user.id,
        created_by_user_id=admin.id,
        label=(body.label or None),
        token_hash_value=token_hash(token),
        created_at=now,
        expires_at=now + timedelta(seconds=expires_in),
    )
    repository.record_audit_event(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="auth.otp.create",
        resource_type="otp_token",
        resource_id=row.id,
        outcome="success",
        after={"user_id": row.user_id, "expires_at": row.expires_at.isoformat(), "label": row.label},
        reason=body.label,
        context={"target_username": target_user.username},
    )
    repository.commit(db)
    return {"token": token, "expires_in": expires_in}
