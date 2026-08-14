from __future__ import annotations

import os

from fastapi import HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.core.db import routed_db
from app.features.auth.session import PortalPrincipal, get_current_user, require_admin
from app.main import app


class _FakeQuery:
    def join(self, *args, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def all(self):
        return []


class _FakeDB:
    def query(self, *args, **kwargs):
        return _FakeQuery()

    def close(self):
        return None


def test_health_endpoint_ok() -> None:
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


def test_auth_me_requires_authentication() -> None:
    with TestClient(app) as client:
        r = client.get("/auth/me")
        assert r.status_code == 401


def test_auth_me_with_overridden_user() -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=5, username="bob", role="admin")
    try:
        with TestClient(app) as client:
            r = client.get("/auth/me")
            assert r.status_code == 200
            assert r.json()["username"] == "bob"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_admin_route_forbidden_when_not_admin() -> None:
    def _deny():
        raise HTTPException(status_code=403, detail="Forbidden")

    app.dependency_overrides[require_admin] = _deny
    try:
        with TestClient(app) as client:
            r = client.get("/admin/login-history")
            assert r.status_code == 403
    finally:
        app.dependency_overrides.pop(require_admin, None)


def test_admin_route_ok_with_admin_and_mocked_db() -> None:
    login_history_db = routed_db("admin-login-history")
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=1, username="root", role="admin")
    app.dependency_overrides[login_history_db] = lambda: _FakeDB()
    try:
        with TestClient(app) as client:
            r = client.get("/admin/login-history?limit=5")
            assert r.status_code == 200
            assert r.json() == []
    finally:
        app.dependency_overrides.pop(require_admin, None)
        app.dependency_overrides.pop(login_history_db, None)


def test_events_hunt_explain_forbidden_for_non_admin() -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=2, username="ana", role="analyst")
    try:
        with TestClient(app) as client:
            r = client.get("/events/hunt/explain?search=needle&since_minutes=60")
            assert r.status_code == 403
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_events_hunt_explain_returns_route_plan_for_admin() -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="root", role="admin")
    try:
        with TestClient(app) as client:
            r = client.get("/events/hunt/explain?search=needle&since_minutes=60")
            assert r.status_code == 200
            body = r.json()
            assert body["decision_backend"] == "elasticsearch"
            assert body["decision_reason"] == "fulltext"
            assert body["chain"][0] == "elasticsearch"
            assert set(body["timeouts_seconds"]) == set(body["chain"])
            assert set(body["circuit"]) == set(body["chain"])
            assert body["signals"]["has_search"] is True
    finally:
        app.dependency_overrides.pop(get_current_user, None)
