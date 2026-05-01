from __future__ import annotations

from datetime import datetime
from http.cookies import SimpleCookie

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request
from starlette.responses import Response

from app.features.auth import bootstrap as portal_bootstrap
from app.core.config import settings
from app.core.security.identity import canonicalize_username
from app.core.security.password_policy import validate_password_policy
from app.features.auth.session import PortalPrincipal, get_current_user, logout, refresh_access_token
from app.core.security import decode_token, hash_password
from app.features.account import api as account_api
from app.features.auth import api as auth_api
from app.features.auth import service as auth_service
from app.features.users import api as users_api
from app.features.auth.models import PortalLoginEventModel
from app.features.auth.models import PortalOneTimeTokenModel
from app.features.auth.models import PortalRefreshSessionModel
from app.features.auth.models import PortalUserModel
from app.features.account.schemas import ChangePasswordIn
from app.features.auth.schemas import LoginIn, OtpLoginIn
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
    monkeypatch.setattr("app.core.db.session.SessionLocal", Session)
    monkeypatch.setattr("app.features.auth.api.SessionLocal", Session)
    monkeypatch.setattr("app.features.account.api.SessionLocal", Session)
    monkeypatch.setattr("app.features.users.api.SessionLocal", Session)
    monkeypatch.setattr("app.features.auth.bootstrap.SessionLocal", Session)

    monkeypatch.setattr("app.features.auth.api.write_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.features.account.api.write_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.features.account.repository.record_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.features.users.api.write_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.features.auth.bootstrap.write_audit_event", lambda *args, **kwargs: None)
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


def test_login_valid_credentials_and_strong_claims(db_factory, monkeypatch: pytest.MonkeyPatch):
    user = _seed_user(db_factory, username="admin", password="ValidPass!123")
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)

    req = _mk_request(path="/auth/login", headers={"User-Agent": "pytest"})
    res = Response()
    out = auth_api.login_endpoint(LoginIn(username="ADMIN", password="ValidPass!123"), req, res)
    payload = decode_token(out["access_token"])

    assert out["user"]["id"] == user.id
    assert payload["iss"] == "seagull-backend"
    assert payload["aud"] == "seagull-portal"
    assert payload["typ"] == "access"
    assert "jti" in payload
    assert "iat" in payload
    assert "exp" in payload
    assert payload["tv"] == 1


def test_login_invalid_credentials(db_factory, monkeypatch: pytest.MonkeyPatch):
    _seed_user(db_factory, username="admin", password="ValidPass!123")
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)

    with pytest.raises(HTTPException) as exc:
        auth_api.login_endpoint(LoginIn(username="admin", password="wrong"), _mk_request(path="/auth/login"), Response())
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


def test_refresh_rotation_and_replay_revokes_family(db_factory, monkeypatch: pytest.MonkeyPatch):
    _seed_user(db_factory, username="admin", password="ValidPass!123")
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)

    login_res = Response()
    auth_api.login_endpoint(LoginIn(username="admin", password="ValidPass!123"), _mk_request(path="/auth/login"), login_res)
    c0 = _cookies_from_response(login_res)
    old_refresh = c0["nw_refresh"]
    old_csrf = c0["nw_csrf"]

    r1_req = _mk_request(path="/auth/refresh", headers={"X-CSRF-Token": old_csrf}, cookies={"nw_refresh": old_refresh, "nw_csrf": old_csrf})
    r1_res = Response()
    out1 = refresh_access_token(r1_req, r1_res)
    assert out1["access_token"]
    c1 = _cookies_from_response(r1_res)
    assert c1["nw_refresh"] != old_refresh

    # Replay old rotated token -> family revoked.
    with pytest.raises(HTTPException) as exc:
        refresh_access_token(
            _mk_request(
                path="/auth/refresh",
                headers={"X-CSRF-Token": old_csrf},
                cookies={"nw_refresh": old_refresh, "nw_csrf": old_csrf},
            ),
            Response(),
        )
    assert exc.value.status_code == 401

    # New token from same family is now revoked too.
    with pytest.raises(HTTPException) as exc2:
        refresh_access_token(
            _mk_request(
                path="/auth/refresh",
                headers={"X-CSRF-Token": c1["nw_csrf"]},
                cookies={"nw_refresh": c1["nw_refresh"], "nw_csrf": c1["nw_csrf"]},
            ),
            Response(),
        )
    assert exc2.value.status_code == 401


def test_logout_revokes_refresh_session(db_factory, monkeypatch: pytest.MonkeyPatch):
    _seed_user(db_factory, username="admin", password="ValidPass!123")
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)

    login_res = Response()
    auth_api.login_endpoint(LoginIn(username="admin", password="ValidPass!123"), _mk_request(path="/auth/login"), login_res)
    cookies = _cookies_from_response(login_res)

    logout(_mk_request(path="/auth/logout", cookies={"nw_refresh": cookies["nw_refresh"]}), Response())
    with pytest.raises(HTTPException):
        refresh_access_token(
            _mk_request(
                path="/auth/refresh",
                headers={"X-CSRF-Token": cookies["nw_csrf"]},
                cookies={"nw_refresh": cookies["nw_refresh"], "nw_csrf": cookies["nw_csrf"]},
            ),
            Response(),
        )


def test_change_password_invalidates_sessions_and_old_access(db_factory, monkeypatch: pytest.MonkeyPatch):
    _seed_user(db_factory, username="admin", password="ValidPass!123")
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)

    login_res = Response()
    login_out = auth_api.login_endpoint(LoginIn(username="admin", password="ValidPass!123"), _mk_request(path="/auth/login"), login_res)
    old_access = login_out["access_token"]
    cookies = _cookies_from_response(login_res)

    account_api.change_password_endpoint(
        ChangePasswordIn(current_password="ValidPass!123", new_password="NewValid!456"),
        _mk_request(path="/account/change-password", method="POST"),
        Response(),
        PortalPrincipal(id=login_out["user"]["id"], username="admin", role="admin"),
    )

    with pytest.raises(HTTPException) as exc:
        get_current_user(_mk_request(path="/auth/me", method="GET", headers={"Authorization": f"Bearer {old_access}"}))
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException):
        refresh_access_token(
            _mk_request(
                path="/auth/refresh",
                headers={"X-CSRF-Token": cookies["nw_csrf"]},
                cookies={"nw_refresh": cookies["nw_refresh"], "nw_csrf": cookies["nw_csrf"]},
            ),
            Response(),
        )


def test_otp_blocked_when_feature_disabled(db_factory):
    _seed_user(db_factory, username="admin", password="ValidPass!123")
    with pytest.raises(HTTPException) as exc:
        auth_api.otp_login_endpoint(OtpLoginIn(token="nw_otp_deadbeef"), _mk_request(path="/auth/otp/login"), Response())
    assert exc.value.status_code == 404


def test_password_policy_applied_across_flows(db_factory, monkeypatch: pytest.MonkeyPatch):
    user = _seed_user(db_factory, username="admin", password="ValidPass!123")
    weak = "weakpass"
    assert validate_password_policy(weak, username="admin") is not None

    with pytest.raises(HTTPException) as create_exc:
        users_api.create_user(
            AdminUserCreateIn(username="new-user", password=weak, role="user", is_active=True),
            _mk_request(path="/users"),
            PortalPrincipal(id=user.id, username="admin", role="admin"),
        )
    assert create_exc.value.status_code == 422

    with pytest.raises(HTTPException) as update_exc:
        users_api.update_user(
            user.id,
            AdminUserUpdateIn(password=weak),
            _mk_request(path=f"/users/{user.id}", method="PUT"),
            PortalPrincipal(id=user.id, username="admin", role="admin"),
        )
    assert update_exc.value.status_code == 422

    with pytest.raises(HTTPException) as change_exc:
        account_api.change_password_endpoint(
            ChangePasswordIn(current_password="ValidPass!123", new_password=weak),
            _mk_request(path="/account/change-password"),
            Response(),
            PortalPrincipal(id=user.id, username="admin", role="admin"),
        )
    assert change_exc.value.status_code == 400

    monkeypatch.setattr(settings, "SEAGULL_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setattr(settings, "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", weak)
    monkeypatch.setattr(settings, "SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START", False)
    monkeypatch.setattr(settings, "SEAGULL_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START", False)
    # Empty DB for bootstrap policy check.
    Session = db_factory
    db = Session()
    try:
        db.query(PortalUserModel).delete()
        db.commit()
    finally:
        db.close()
    with pytest.raises(RuntimeError):
        portal_bootstrap.bootstrap_portal_admin()


def test_username_canonicalization_and_login_case_insensitive(db_factory, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)
    admin = _seed_user(db_factory, username="ADMIN", password="ValidPass!123")
    assert admin.username == "admin"

    out = auth_api.login_endpoint(LoginIn(username="AdMiN", password="ValidPass!123"), _mk_request(path="/auth/login"), Response())
    assert out["user"]["username"] == "admin"


def test_access_token_rejected_after_token_version_bump(db_factory, monkeypatch: pytest.MonkeyPatch):
    _seed_user(db_factory, username="admin", password="ValidPass!123")
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)

    login_out = auth_api.login_endpoint(LoginIn(username="admin", password="ValidPass!123"), _mk_request(path="/auth/login"), Response())
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


def test_logout_all_invalidates_access_and_refresh(db_factory, monkeypatch: pytest.MonkeyPatch):
    _seed_user(db_factory, username="admin", password="ValidPass!123")
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)

    login_res = Response()
    login_out = auth_api.login_endpoint(LoginIn(username="admin", password="ValidPass!123"), _mk_request(path="/auth/login"), login_res)
    old_access = login_out["access_token"]
    cookies = _cookies_from_response(login_res)
    principal = PortalPrincipal(id=login_out["user"]["id"], username="admin", role="admin")

    auth_api.logout_all_endpoint(_mk_request(path="/auth/logout-all"), Response(), principal)

    with pytest.raises(HTTPException):
        get_current_user(_mk_request(path="/auth/me", method="GET", headers={"Authorization": f"Bearer {old_access}"}))
    with pytest.raises(HTTPException):
        refresh_access_token(
            _mk_request(
                path="/auth/refresh",
                headers={"X-CSRF-Token": cookies["nw_csrf"]},
                cookies={"nw_refresh": cookies["nw_refresh"], "nw_csrf": cookies["nw_csrf"]},
            ),
            Response(),
        )


def test_frontend_restore_session_flow_with_csrf_and_refresh(db_factory, monkeypatch: pytest.MonkeyPatch):
    _seed_user(db_factory, username="admin", password="ValidPass!123")
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)

    login_res = Response()
    auth_api.login_endpoint(LoginIn(username="admin", password="ValidPass!123"), _mk_request(path="/auth/login"), login_res)
    cookies = _cookies_from_response(login_res)
    assert "nw_refresh" in cookies
    assert "nw_csrf" in cookies

    refresh_req = _mk_request(
        path="/auth/refresh",
        headers={"X-CSRF-Token": cookies["nw_csrf"]},
        cookies={"nw_refresh": cookies["nw_refresh"], "nw_csrf": cookies["nw_csrf"]},
    )
    out = refresh_access_token(refresh_req, Response())
    assert out["access_token"]
    assert out["user"]["username"] == "admin"
