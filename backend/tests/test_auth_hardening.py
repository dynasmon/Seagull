from __future__ import annotations

from datetime import datetime
from http.cookies import SimpleCookie

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from app.core.security import decode_token, hash_password
from app.core.security.identity import canonicalize_username
from app.core.security.password_policy import validate_password_policy
from app.features.account import service as account_service
from app.features.account.schemas import ChangePasswordIn
from app.features.auth import bootstrap as portal_bootstrap
from app.features.auth import service as auth_service
from app.features.auth.models import (
    PortalLoginEventModel,
    PortalOneTimeTokenModel,
    PortalRefreshSessionModel,
    PortalUserModel,
)
from app.features.auth.schemas import LoginIn, OtpLoginIn
from app.features.auth.session import PortalPrincipal, get_current_user
from app.features.users import service as users_service
from app.features.users.schemas import AdminUserCreateIn, AdminUserUpdateIn


def _mk_request(
    *,
    path: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> Request:
    hdrs: list[tuple[bytes, bytes]] = []
    for k, v in (headers or {}).items():
        hdrs.append((k.lower().encode("utf-8"), str(v).encode("utf-8")))
    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        hdrs.append((b"cookie", cookie_str.encode("utf-8")))
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": hdrs,
            "client": ("127.0.0.1", 43123),
            "query_string": b"",
            "scheme": "http",
        }
    )


def _cookies_from_response(res: Response) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (res.raw_headers or []):
        if k.lower() != b"set-cookie":
            continue
        parsed = SimpleCookie()
        parsed.load(v.decode("utf-8"))
        for name, morsel in parsed.items():
            out[name] = morsel.value
    return out


@pytest.fixture()
def db_factory(monkeypatch: pytest.MonkeyPatch):
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)

    PortalUserModel.__table__.create(bind=engine)
    PortalRefreshSessionModel.__table__.create(bind=engine)
    PortalOneTimeTokenModel.__table__.create(bind=engine)
    PortalLoginEventModel.__table__.create(bind=engine)

    monkeypatch.setattr("app.features.auth.session.SessionLocal", Session)
    monkeypatch.setattr("app.features.auth.bootstrap.SessionLocal", Session)
    monkeypatch.setattr("app.features.auth.repository.record_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.features.account.repository.record_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.features.users.repository.record_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.features.auth.bootstrap.write_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)
    monkeypatch.setattr(auth_service, "guard_otp_rate_limit", lambda *args, **kwargs: None)
    return Session


@pytest.fixture(autouse=True)
def auth_settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "SEAGULL_JWT_SECRET", "s" * 48)
    monkeypatch.setattr(settings, "SEAGULL_JWT_ISSUER", "seagull-backend")
    monkeypatch.setattr(settings, "SEAGULL_JWT_AUDIENCE", "seagull-portal")
    monkeypatch.setattr(settings, "SEAGULL_ACCESS_TOKEN_TTL_SECONDS", 600)
    monkeypatch.setattr(settings, "SEAGULL_REFRESH_TOKEN_TTL_SECONDS", 3600)
    monkeypatch.setattr(settings, "SEAGULL_COOKIE_SECURE", False)
    monkeypatch.setattr(settings, "SEAGULL_COOKIE_SAMESITE", "lax")
    monkeypatch.setattr(settings, "SEAGULL_COOKIE_DOMAIN", None)
    monkeypatch.setattr(settings, "SEAGULL_AUTH_OTP_ENABLED", False)


def _seed_user(Session, *, username: str, password: str) -> PortalUserModel:
    db = Session()
    try:
        user = PortalUserModel(
            username=canonicalize_username(username),
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
            created_at=datetime.utcnow(),
            token_version=1,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _login(Session, *, username: str, password: str) -> tuple[dict, dict[str, str]]:
    db = Session()
    try:
        res = Response()
        out = auth_service.login(
            db,
            body=LoginIn(username=username, password=password),
            request=_mk_request(path="/auth/login", headers={"User-Agent": "pytest"}),
            response=res,
        )
        return out, _cookies_from_response(res)
    finally:
        db.close()


def _refresh(Session, *, cookies: dict[str, str], csrf: str | None = None) -> tuple[dict, dict[str, str]]:
    db = Session()
    try:
        res = Response()
        out = auth_service.refresh(
            db,
            request=_mk_request(
                path="/auth/refresh",
                headers={"X-CSRF-Token": csrf or cookies["nw_csrf"]},
                cookies=cookies,
            ),
            response=res,
        )
        return out, _cookies_from_response(res)
    finally:
        db.close()


def test_login_valid_credentials_and_strong_claims(db_factory):
    user = _seed_user(db_factory, username="admin", password="ValidPass!123")

    out, _cookies = _login(db_factory, username="ADMIN", password="ValidPass!123")
    payload = decode_token(out["access_token"])

    assert out["user"]["id"] == user.id
    assert payload["iss"] == "seagull-backend"
    assert payload["aud"] == "seagull-portal"
    assert payload["typ"] == "access"
    assert "jti" in payload
    assert "iat" in payload
    assert "exp" in payload
    assert payload["tv"] == 1


def test_login_invalid_credentials(db_factory):
    _seed_user(db_factory, username="admin", password="ValidPass!123")

    with pytest.raises(HTTPException) as exc:
        _login(db_factory, username="admin", password="wrong")
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid credentials"


def test_rate_limit_redis_unavailable_uses_local_fallback(monkeypatch: pytest.MonkeyPatch):
    from app.core.security import rate_limit as rl

    rl._local_state.clear()
    monkeypatch.setattr("app.core.security.rate_limit._get_redis", lambda: None)
    allowed = 0
    blocked = 0
    for _ in range(5):
        result = rl.rate_limit("rl:test:login:127.0.0.1", limit=3, window_seconds=60)
        if result.allowed:
            allowed += 1
        else:
            blocked += 1
    assert allowed == 3
    assert blocked == 2


def test_refresh_rotation_and_replay_revokes_family(db_factory):
    _seed_user(db_factory, username="admin", password="ValidPass!123")

    _out, c0 = _login(db_factory, username="admin", password="ValidPass!123")
    old_cookies = {"nw_refresh": c0["nw_refresh"], "nw_csrf": c0["nw_csrf"]}

    out1, c1 = _refresh(db_factory, cookies=old_cookies)
    assert out1["access_token"]
    assert c1["nw_refresh"] != old_cookies["nw_refresh"]

    with pytest.raises(HTTPException) as exc:
        _refresh(db_factory, cookies=old_cookies)
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc2:
        _refresh(db_factory, cookies={"nw_refresh": c1["nw_refresh"], "nw_csrf": c1["nw_csrf"]})
    assert exc2.value.status_code == 401


def test_refresh_requires_csrf_header_matching_cookie(db_factory):
    _seed_user(db_factory, username="admin", password="ValidPass!123")
    _out, cookies = _login(db_factory, username="admin", password="ValidPass!123")

    with pytest.raises(HTTPException) as exc:
        _refresh(
            db_factory,
            cookies={"nw_refresh": cookies["nw_refresh"], "nw_csrf": cookies["nw_csrf"]},
            csrf="not-the-cookie-value",
        )
    assert exc.value.status_code == 403


def test_logout_revokes_refresh_session(db_factory):
    _seed_user(db_factory, username="admin", password="ValidPass!123")

    login_out, cookies = _login(db_factory, username="admin", password="ValidPass!123")
    principal = PortalPrincipal(id=login_out["user"]["id"], username="admin", role="admin")

    db = db_factory()
    try:
        auth_service.logout(
            db,
            request=_mk_request(path="/auth/logout", cookies={"nw_refresh": cookies["nw_refresh"]}),
            response=Response(),
            user=principal,
        )
    finally:
        db.close()

    with pytest.raises(HTTPException):
        _refresh(db_factory, cookies={"nw_refresh": cookies["nw_refresh"], "nw_csrf": cookies["nw_csrf"]})


def test_change_password_invalidates_sessions_and_old_access(db_factory):
    _seed_user(db_factory, username="admin", password="ValidPass!123")

    login_out, cookies = _login(db_factory, username="admin", password="ValidPass!123")
    old_access = login_out["access_token"]
    principal = PortalPrincipal(id=login_out["user"]["id"], username="admin", role="admin")

    db = db_factory()
    try:
        account_service.change_password(
            db,
            body=ChangePasswordIn(current_password="ValidPass!123", new_password="NewValid!456"),
            request=_mk_request(path="/account/change-password"),
            response=Response(),
            principal=principal,
        )
        db.commit()
    finally:
        db.close()

    with pytest.raises(HTTPException) as exc:
        get_current_user(_mk_request(path="/auth/me", method="GET", headers={"Authorization": f"Bearer {old_access}"}))
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException):
        _refresh(db_factory, cookies={"nw_refresh": cookies["nw_refresh"], "nw_csrf": cookies["nw_csrf"]})


def test_otp_blocked_when_feature_disabled(db_factory):
    _seed_user(db_factory, username="admin", password="ValidPass!123")

    db = db_factory()
    try:
        with pytest.raises(HTTPException) as exc:
            auth_service.otp_login(
                db,
                body=OtpLoginIn(token="nw_otp_deadbeef"),
                request=_mk_request(path="/auth/otp/login"),
                response=Response(),
            )
    finally:
        db.close()
    assert exc.value.status_code == 404


def test_password_policy_applied_across_flows(db_factory, monkeypatch: pytest.MonkeyPatch):
    user = _seed_user(db_factory, username="admin", password="ValidPass!123")
    principal = PortalPrincipal(id=user.id, username="admin", role="admin")
    weak = "weakpass"
    assert validate_password_policy(weak, username="admin") is not None

    db = db_factory()
    try:
        with pytest.raises(HTTPException) as create_exc:
            users_service.create_user(
                db,
                payload=AdminUserCreateIn(username="new-user", password=weak, role="user", is_active=True),
                request=_mk_request(path="/users"),
                admin=principal,
            )
        assert create_exc.value.status_code == 422

        with pytest.raises(HTTPException) as update_exc:
            users_service.update_user(
                db,
                user_id=user.id,
                payload=AdminUserUpdateIn(password=weak),
                request=_mk_request(path=f"/users/{user.id}", method="PUT"),
                admin=principal,
            )
        assert update_exc.value.status_code == 422

        with pytest.raises(HTTPException) as change_exc:
            account_service.change_password(
                db,
                body=ChangePasswordIn(current_password="ValidPass!123", new_password=weak),
                request=_mk_request(path="/account/change-password"),
                response=Response(),
                principal=principal,
            )
        assert change_exc.value.status_code == 400
    finally:
        db.close()

    monkeypatch.setattr(settings, "SEAGULL_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setattr(settings, "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", weak)
    monkeypatch.setattr(settings, "SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START", False)
    monkeypatch.setattr(settings, "SEAGULL_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START", False)

    Session = db_factory
    db = Session()
    try:
        db.query(PortalUserModel).delete()
        db.commit()
    finally:
        db.close()
    with pytest.raises(RuntimeError):
        portal_bootstrap.bootstrap_portal_admin()


def test_username_canonicalization_and_login_case_insensitive(db_factory):
    admin = _seed_user(db_factory, username="ADMIN", password="ValidPass!123")
    assert admin.username == "admin"

    out, _cookies = _login(db_factory, username="AdMiN", password="ValidPass!123")
    assert out["user"]["username"] == "admin"


def test_access_token_rejected_after_token_version_bump(db_factory):
    _seed_user(db_factory, username="admin", password="ValidPass!123")

    login_out, _cookies = _login(db_factory, username="admin", password="ValidPass!123")
    tok = login_out["access_token"]

    db = db_factory()
    try:
        user = db.get(PortalUserModel, login_out["user"]["id"])
        user.token_version = int(user.token_version or 1) + 1
        db.add(user)
        db.commit()
    finally:
        db.close()

    with pytest.raises(HTTPException) as exc:
        get_current_user(_mk_request(path="/auth/me", method="GET", headers={"Authorization": f"Bearer {tok}"}))
    assert exc.value.status_code == 401


def test_logout_all_invalidates_access_and_refresh(db_factory):
    _seed_user(db_factory, username="admin", password="ValidPass!123")

    login_out, cookies = _login(db_factory, username="admin", password="ValidPass!123")
    old_access = login_out["access_token"]
    principal = PortalPrincipal(id=login_out["user"]["id"], username="admin", role="admin")

    db = db_factory()
    try:
        auth_service.logout_all(
            db,
            request=_mk_request(path="/auth/logout-all"),
            response=Response(),
            user=principal,
        )
    finally:
        db.close()

    with pytest.raises(HTTPException):
        get_current_user(_mk_request(path="/auth/me", method="GET", headers={"Authorization": f"Bearer {old_access}"}))
    with pytest.raises(HTTPException):
        _refresh(db_factory, cookies={"nw_refresh": cookies["nw_refresh"], "nw_csrf": cookies["nw_csrf"]})


def test_frontend_restore_session_flow_with_csrf_and_refresh(db_factory):
    _seed_user(db_factory, username="admin", password="ValidPass!123")

    _out, cookies = _login(db_factory, username="admin", password="ValidPass!123")
    assert "nw_refresh" in cookies
    assert "nw_csrf" in cookies

    out, _c = _refresh(db_factory, cookies={"nw_refresh": cookies["nw_refresh"], "nw_csrf": cookies["nw_csrf"]})
    assert out["access_token"]
    assert out["user"]["username"] == "admin"
