from __future__ import annotations

import os
import threading
import uuid
from datetime import datetime, timedelta

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite+pysqlite:///:memory:")

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
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

MODELS = (PortalUserModel, PortalRefreshSessionModel, PortalOneTimeTokenModel, PortalLoginEventModel)
CONTENDERS = 8

DSN = (os.environ.get("SEAGULL_TEST_DB_URL") or "").strip()

pytestmark = pytest.mark.skipif(
    not DSN.startswith("postgresql"),
    reason="set SEAGULL_TEST_DB_URL to a PostgreSQL database to run the concurrency tests",
)


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
    monkeypatch.setattr(repository, "record_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(auth_service, "guard_login_rate_limit", lambda *args, **kwargs: None)
    monkeypatch.setattr(auth_service, "guard_otp_rate_limit", lambda *args, **kwargs: None)


@pytest.fixture()
def db_factory():
    schema = f"auth_race_{uuid.uuid4().hex[:12]}"
    admin = create_engine(DSN, poolclass=NullPool, future=True)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))

    engine = create_engine(
        DSN,
        poolclass=NullPool,
        future=True,
        connect_args={"options": f"-csearch_path={schema}"},
    )
    for model in MODELS:
        model.__table__.create(bind=engine)

    try:
        yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def _seed_user(Session) -> PortalUserModel:
    db = Session()
    try:
        user = PortalUserModel(
            username="admin",
            password_hash=hash_password("ValidPass!123"),
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


def _sync_after_read(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    everyone_read = threading.Barrier(CONTENDERS)
    original = getattr(repository, name)

    def read_then_wait(db, token_hash_value):
        row = original(db, token_hash_value)
        everyone_read.wait(timeout=30)
        return row

    monkeypatch.setattr(repository, name, read_then_wait)


def _race(call) -> tuple[list, list[tuple[int, str]]]:
    start = threading.Barrier(CONTENDERS)
    granted: list = []
    refused: list[tuple[int, str]] = []
    guard = threading.Lock()

    def contend() -> None:
        start.wait(timeout=30)
        try:
            outcome = call()
        except HTTPException as exc:
            with guard:
                refused.append((exc.status_code, str(exc.detail)))
            return
        with guard:
            granted.append(outcome)

    threads = [threading.Thread(target=contend) for _ in range(CONTENDERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    return granted, refused


def test_concurrent_refreshes_rotate_a_session_once(db_factory, monkeypatch: pytest.MonkeyPatch):
    _seed_user(db_factory)
    cookies = _login(db_factory)
    _sync_after_read(monkeypatch, "get_refresh_session_by_token_hash")

    def rotate() -> dict[str, str]:
        db = db_factory()
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

    granted, refused = _race(rotate)

    assert len(granted) == 1
    assert refused == [(401, "Invalid refresh token")] * (CONTENDERS - 1)

    db = db_factory()
    try:
        rows = db.query(PortalRefreshSessionModel).all()
        active = [row for row in rows if row.revoked_at is None]
        rotated = [row for row in rows if row.replaced_by_id is not None]
    finally:
        db.close()

    assert len(rows) == 2
    assert len(active) == 1
    assert len(rotated) == 1
    assert rotated[0].replaced_by_id == active[0].id
    assert active[0].token_hash == token_hash(granted[0]["nw_refresh"])


def test_concurrent_one_time_token_logins_admit_one(db_factory, monkeypatch: pytest.MonkeyPatch):
    user = _seed_user(db_factory)
    raw = new_one_time_token()

    db = db_factory()
    try:
        repository.create_one_time_token(
            db,
            user_id=user.id,
            created_by_user_id=user.id,
            label=None,
            token_hash_value=token_hash(raw),
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=15),
        )
        db.commit()
    finally:
        db.close()

    _sync_after_read(monkeypatch, "get_one_time_token_by_hash")

    def redeem() -> dict:
        db = db_factory()
        try:
            return auth_service.otp_login(
                db,
                body=OtpLoginIn(token=raw),
                request=_mk_request(path="/auth/otp/login"),
                response=Response(),
            )
        finally:
            db.close()

    granted, refused = _race(redeem)

    assert len(granted) == 1
    assert refused == [(401, "Invalid token")] * (CONTENDERS - 1)

    db = db_factory()
    try:
        sessions = db.query(PortalRefreshSessionModel).count()
        used = db.query(PortalOneTimeTokenModel).one().used_at
    finally:
        db.close()

    assert sessions == 1
    assert used is not None
