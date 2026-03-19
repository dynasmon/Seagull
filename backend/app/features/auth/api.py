from __future__ import annotations

from datetime import datetime, timedelta
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.core.audit import audit_actor, write_audit_event
from app.core.config import settings
from app.core.portal_auth import (
    PortalPrincipal,
    get_current_user,
    issue_login_tokens,
    logout,
    refresh_access_token,
    require_admin,
)
from app.core.rate_limit import guard_login_rate_limit, guard_otp_rate_limit
from app.core.security import new_one_time_token, token_hash
from app.core.db import SessionLocal
from app.models.portal_users import PortalUserModel
from app.models.portal_otp_tokens import PortalOneTimeTokenModel
from app.models.portal_login_events import PortalLoginEventModel
from app.schemas.auth import LoginIn, OtpCreateIn, OtpCreateOut, OtpLoginIn, TokenOut, UserOut


router = APIRouter(prefix="/auth", tags=["auth"])


def _audit_login_event(
    *,
    db,
    request: Request,
    method: str,
    succeeded: bool,
    user_id: int | None,
    username: str | None,
    reason: str | None = None,
) -> None:
    """Best-effort login audit logging.

    Audit must never break auth flows.
    """
    try:
        ip = (request.client.host if request.client else "") or "unknown"
        ua = (request.headers.get("user-agent") or "")[:256]
        db.add(
            PortalLoginEventModel(
                id=str(uuid.uuid4()),
                user_id=user_id,
                username=(username or None),
                method=method,
                succeeded=bool(succeeded),
                ip=ip,
                user_agent=ua,
                created_at=datetime.utcnow(),
            )
        )
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(user_id=user_id, username=username),
            event_type="auth",
            action=f"auth.login.{method}",
            resource_type="auth_session",
            resource_id=(str(user_id) if user_id is not None else None),
            outcome="success" if succeeded else "failure",
            before={},
            after={"method": method, "succeeded": bool(succeeded)},
            context={"ip": ip, "user_agent": ua},
            reason=(None if succeeded else (reason or "login_failed")),
        )
    except Exception:
        return


@router.post("/login", response_model=TokenOut)
def login_endpoint(body: LoginIn, request: Request, response: Response):
    guard_login_rate_limit(request, username=body.username)

    db = SessionLocal()
    try:
        user: PortalUserModel | None = db.query(PortalUserModel).filter(PortalUserModel.username == body.username).first()
        if not user or not user.is_active:
            _audit_login_event(
                db=db, request=request, method="password", succeeded=False, user_id=None, username=body.username, reason="invalid_credentials"
            )
            try:
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        # Verify password (supports legacy hash formats) and opportunistically
        # migrate hash to the current scheme.
        from app.core.security import verify_and_upgrade_password

        verified, upgraded_hash = verify_and_upgrade_password(body.password, user.password_hash)
        if not verified:
            # best-effort counter (doesn't lock users out permanently)
            try:
                user.failed_login_count = int(user.failed_login_count or 0) + 1
                db.add(user)
            except Exception:
                pass
            _audit_login_event(
                db=db, request=request, method="password", succeeded=False, user_id=user.id, username=body.username, reason="invalid_credentials"
            )
            try:
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        if upgraded_hash:
            user.password_hash = upgraded_hash
        user.failed_login_count = 0
        user.last_login_at = datetime.utcnow()
        db.add(user)
        _audit_login_event(db=db, request=request, method="password", succeeded=True, user_id=user.id, username=user.username)
        payload = issue_login_tokens(response, user=user, request=request, db=db)
        db.commit()
        return payload
    finally:
        db.close()


@router.post("/refresh", response_model=TokenOut)
def refresh_endpoint(request: Request, response: Response):
    try:
        payload = refresh_access_token(request, response)
    except HTTPException as exc:
        db = SessionLocal()
        try:
            write_audit_event(
                db,
                request=request,
                actor=audit_actor(user_id=None, username=None),
                event_type="auth",
                action="auth.refresh",
                resource_type="auth_session",
                resource_id=None,
                outcome="failure",
                before={},
                after={},
                reason=str(exc.detail)[:255],
                error=f"http_{exc.status_code}",
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        finally:
            db.close()
        raise

    db = SessionLocal()
    try:
        u = (payload.get("user") or {}) if isinstance(payload, dict) else {}
        uid = u.get("id")
        uname = u.get("username")
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(user_id=(int(uid) if isinstance(uid, int) else None), username=(str(uname) if uname else None)),
            event_type="auth",
            action="auth.refresh",
            resource_type="auth_session",
            resource_id=(str(uid) if uid is not None else None),
            outcome="success",
            before={},
            after={"token_refreshed": True},
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()
    return payload


@router.post("/logout", status_code=204)
def logout_endpoint(request: Request, response: Response, user: PortalPrincipal = Depends(get_current_user)):
    logout(request, response)
    db = SessionLocal()
    try:
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(user_id=user.id, username=user.username),
            event_type="auth",
            action="auth.logout",
            resource_type="auth_session",
            resource_id=str(user.id),
            outcome="success",
            before={},
            after={"logged_out": True},
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()
    return None


@router.get("/me", response_model=UserOut)
def me_endpoint(user: PortalPrincipal = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/otp/login", response_model=TokenOut)
def otp_login_endpoint(body: OtpLoginIn, request: Request, response: Response):
    guard_otp_rate_limit(request)

    raw = (body.token or "").strip()
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    h = token_hash(raw)
    now = datetime.utcnow()

    db = SessionLocal()
    try:
        row: PortalOneTimeTokenModel | None = db.query(PortalOneTimeTokenModel).filter(PortalOneTimeTokenModel.token_hash == h).first()
        if (
            not row
            or row.revoked_at is not None
            or row.used_at is not None
            or row.expires_at <= now
        ):
            _audit_login_event(db=db, request=request, method="otp", succeeded=False, user_id=None, username=None, reason="invalid_token")
            try:
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        user: PortalUserModel | None = db.get(PortalUserModel, row.user_id)
        if not user or not user.is_active:
            _audit_login_event(
                db=db,
                request=request,
                method="otp",
                succeeded=False,
                user_id=(user.id if user else None),
                username=(user.username if user else None),
                reason="invalid_token",
            )
            try:
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        # Mark token as used (single-use).
        ip = (request.client.host if request.client else "") or "unknown"
        ua = (request.headers.get("user-agent") or "")[:256]
        row.used_at = now
        row.used_ip = ip
        row.used_user_agent = ua
        db.add(row)

        user.last_login_at = now
        db.add(user)
        _audit_login_event(db=db, request=request, method="otp", succeeded=True, user_id=user.id, username=user.username)
        payload = issue_login_tokens(response, user=user, request=request, db=db)
        db.commit()
        return payload
    finally:
        db.close()


@router.post("/otp/create", response_model=OtpCreateOut)
def otp_create_endpoint(
    body: OtpCreateIn,
    request: Request,
    response: Response,
    admin: PortalPrincipal = Depends(require_admin),
):
    """Create a single-use login token.

    Only admins can create OTP tokens.
    """
    db = SessionLocal()
    try:
        target_user: PortalUserModel | None
        if body.username:
            target_user = db.query(PortalUserModel).filter(PortalUserModel.username == body.username).first()
        else:
            target_user = db.get(PortalUserModel, admin.id)

        if not target_user or not target_user.is_active:
            raise HTTPException(status_code=404, detail="User not found")

        token = new_one_time_token()
        now = datetime.utcnow()
        expires_in = int(settings.NETWATCH_OTP_TOKEN_TTL_SECONDS)

        row = PortalOneTimeTokenModel(
            id=str(__import__("uuid").uuid4()),
            user_id=target_user.id,
            created_by_user_id=admin.id,
            label=(body.label or None),
            token_hash=token_hash(token),
            created_at=now,
            expires_at=now + timedelta(seconds=expires_in),
            used_at=None,
            revoked_at=None,
        )
        db.add(row)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="auth.otp.create",
            resource_type="otp_token",
            resource_id=row.id,
            outcome="success",
            before={},
            after={"user_id": row.user_id, "expires_at": row.expires_at.isoformat(), "label": row.label},
            reason=body.label,
            context={"target_username": target_user.username},
        )
        db.commit()

        return {"token": token, "expires_in": expires_in}
    finally:
        db.close()
