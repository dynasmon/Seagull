from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite+pysqlite:///:memory:")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from app.core.security import hash_password, new_one_time_token, token_hash
from app.features.auth import repository
from app.features.auth import service as auth_service
from app.features.auth.models import (
    PortalLoginEventModel,
    PortalOneTimeTokenModel,
    PortalRefreshSessionModel,
    PortalUserModel,
)
from app.features.auth.schemas import LoginIn, OtpLoginIn

NOW = datetime(2026, 8, 12, 12, 0)


def _mk_request(*, path: str, cookies: dict[str, str] | None = None, csrf: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = [(b"user-agent", b"pytest")]
    if csrf:
        headers.append((b"x-csrf-token", csrf.encode("utf-8")))
    if cookies:
        headers.append((b"cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()).encode("utf-8")))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": headers,
            "client": ("127.0.0.1", 43123),
            "query_string": b"",
            "scheme": "http",
        }
    )


def _cookies_from(response: Response) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in response.raw_headers or []:
        if key.lower() != b"set-cookie":
            continue
        pair = value.decode("utf-8").split(";", 1)[0]
        name, _, raw = pair.partition("=")
        out[name] = raw
    return out


@pytest.fixture(autouse=True)
def auth_settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "SEAGULL_JWT_SECRET", "s" * 48)
    monkeypatch.setattr(settings, "SEAGULL_ACCESS_TOKEN_TTL_SECONDS", 600)
    monkeypatch.setattr(settings, "SEAGULL_REFRESH_TOKEN_TTL_SECONDS", 3600)
    monkeypatch.setattr(settings, "SEAGULL_AUTH_OTP_ENABLED", True)


@pytest.fixture()
def db_factory(monkeypatch: pytest.MonkeyPatch):
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    for model in (PortalUserModel, PortalRefreshSessionModel, PortalOneTimeTokenModel, PortalLoginEventModel):
        model.__table__.create(bind=engine)

    monkeypatch.setattr(repository, "record_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)
    monkeypatch.setattr(auth_service, "guard_otp_rate_limit", lambda *args, **kwargs: None)
    return Session


def _seed_user(Session) -> PortalUserModel:
    db = Session()
    try:
        user = PortalUserModel(
            username="admin",
            password_hash=hash_password("ValidPass!123"),
            role="admin",
            is_active=True,
            created_at=NOW,
            token_version=1,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _login(Session) -> dict[str, str]:
    db = Session()
    try:
        response = Response()
        auth_service.login(
            db,
            body=LoginIn(username="admin", password="ValidPass!123"),
            request=_mk_request(path="/auth/login"),
            response=response,
        )
        return _cookies_from(response)
    finally:
        db.close()


def _refresh(Session, cookies: dict[str, str]) -> dict[str, str]:
    db = Session()
    try:
        response = Response()
        auth_service.refresh(
            db,
            request=_mk_request(path="/auth/refresh", cookies=cookies, csrf=cookies["nw_csrf"]),
            response=response,
        )
        return _cookies_from(response)
    finally:
        db.close()


def _sessions(Session) -> list[PortalRefreshSessionModel]:
    db = Session()
    try:
        return db.query(PortalRefreshSessionModel).order_by(PortalRefreshSessionModel.created_at).all()
    finally:
        db.close()


def _seed_refresh_session(Session, *, user_id: int, revoked_at: datetime | None = None) -> str:
    db = Session()
    try:
        row = repository.create_refresh_session(
            db,
            session_id=str(uuid.uuid4()),
            user_id=user_id,
            token_hash_value=token_hash(str(uuid.uuid4())),
            created_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            family_id="family-1",
            last_ip="127.0.0.1",
            last_user_agent="pytest",
        )
        row.revoked_at = revoked_at
        db.commit()
        return row.id
    finally:
        db.close()


def _seed_one_time_token(Session, *, user_id: int, raw: str, revoked_at: datetime | None = None) -> str:
    db = Session()
    try:
        row = repository.create_one_time_token(
            db,
            user_id=user_id,
            created_by_user_id=user_id,
            label=None,
            token_hash_value=token_hash(raw),
            created_at=NOW,
            expires_at=datetime.utcnow() + timedelta(minutes=15),
        )
        row.revoked_at = revoked_at
        db.commit()
        return row.id
    finally:
        db.close()


def test_revoking_a_refresh_session_succeeds_for_exactly_one_caller(db_factory):
    user = _seed_user(db_factory)
    session_id = _seed_refresh_session(db_factory, user_id=user.id)

    db = db_factory()
    try:
        first = repository.revoke_refresh_session(db, session_id=session_id, revoked_at=NOW, replaced_by_id="child-a")
        second = repository.revoke_refresh_session(db, session_id=session_id, revoked_at=NOW, replaced_by_id="child-b")
        db.commit()
    finally:
        db.close()

    assert first is True
    assert second is False
    assert _sessions(db_factory)[0].replaced_by_id == "child-a"


def test_revoking_a_family_leaves_earlier_revocations_untouched(db_factory):
    user = _seed_user(db_factory)
    already_revoked = _seed_refresh_session(db_factory, user_id=user.id, revoked_at=NOW - timedelta(hours=2))
    still_active = _seed_refresh_session(db_factory, user_id=user.id)

    db = db_factory()
    try:
        revoked = repository.revoke_refresh_family(db, family_id="family-1", revoked_at=NOW)
        db.commit()
    finally:
        db.close()

    rows = {row.id: row for row in _sessions(db_factory)}
    assert revoked == 1
    assert rows[already_revoked].revoked_at == NOW - timedelta(hours=2)
    assert rows[still_active].revoked_at == NOW


def test_consuming_a_one_time_token_succeeds_for_exactly_one_caller(db_factory):
    user = _seed_user(db_factory)
    token_id = _seed_one_time_token(db_factory, user_id=user.id, raw=new_one_time_token())

    db = db_factory()
    try:
        first = repository.consume_one_time_token(
            db, token_id=token_id, used_at=NOW, used_ip="10.0.0.1", used_user_agent="first"
        )
        second = repository.consume_one_time_token(
            db, token_id=token_id, used_at=NOW, used_ip="10.0.0.2", used_user_agent="second"
        )
        db.commit()
    finally:
        db.close()

    assert first is True
    assert second is False

    db = db_factory()
    try:
        row = db.get(PortalOneTimeTokenModel, token_id)
        assert row.used_ip == "10.0.0.1"
        assert row.used_user_agent == "first"
    finally:
        db.close()


def test_consuming_a_revoked_one_time_token_is_refused(db_factory):
    user = _seed_user(db_factory)
    token_id = _seed_one_time_token(db_factory, user_id=user.id, raw=new_one_time_token(), revoked_at=NOW)

    db = db_factory()
    try:
        consumed = repository.consume_one_time_token(
            db, token_id=token_id, used_at=NOW, used_ip="10.0.0.1", used_user_agent="pytest"
        )
        db.commit()
    finally:
        db.close()

    assert consumed is False


def test_losing_the_rotation_race_mints_no_session_and_spares_the_family(db_factory, monkeypatch: pytest.MonkeyPatch):
    _seed_user(db_factory)
    cookies = _login(db_factory)
    assert len(_sessions(db_factory)) == 1

    real_revoke = repository.revoke_refresh_session
    lost = False

    def lose_the_first_rotation(db, **kwargs):
        nonlocal lost
        if kwargs.get("replaced_by_id") and not lost:
            lost = True
            return False
        return real_revoke(db, **kwargs)

    monkeypatch.setattr(repository, "revoke_refresh_session", lose_the_first_rotation)

    with pytest.raises(HTTPException) as exc:
        _refresh(db_factory, cookies)

    assert exc.value.status_code == 401
    rows = _sessions(db_factory)
    assert len(rows) == 1
    assert rows[0].revoked_at is None

    rotated = _refresh(db_factory, cookies)
    assert rotated["nw_refresh"] != cookies["nw_refresh"]


def test_losing_the_one_time_token_race_refuses_the_login(db_factory, monkeypatch: pytest.MonkeyPatch):
    user = _seed_user(db_factory)
    raw = new_one_time_token()
    _seed_one_time_token(db_factory, user_id=user.id, raw=raw)

    monkeypatch.setattr(repository, "consume_one_time_token", lambda *args, **kwargs: False)

    db = db_factory()
    try:
        with pytest.raises(HTTPException) as exc:
            auth_service.otp_login(
                db,
                body=OtpLoginIn(token=raw),
                request=_mk_request(path="/auth/otp/login"),
                response=Response(),
            )
    finally:
        db.close()

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"
    assert _sessions(db_factory) == []
