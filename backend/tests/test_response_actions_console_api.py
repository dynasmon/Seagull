from __future__ import annotations

import os
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core.portal_auth import PortalPrincipal, require_admin
from app.features.response import api as response_api
from app.features.response.models import ResponseActionModel, ResponseActionResultModel
from app.main import app


class _FakeQuery:
    def __init__(self, *, first_row=None, all_rows=None):
        self._first = first_row
        self._all = all_rows or []

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def first(self):
        return self._first

    def all(self):
        return list(self._all)


class _FakeDB:
    def __init__(self):
        now = datetime.utcnow()
        self.action = ResponseActionModel(
            id=401,
            action_type="collect_triage_bundle",
            agent_id="agent-1",
            status="pending",
            payload={"collectors": {"runtime": True}},
            requested_by="root",
            requested_at=now - timedelta(minutes=2),
            expires_at=now + timedelta(minutes=5),
            created_at=now - timedelta(minutes=2),
            updated_at=now - timedelta(minutes=2),
        )
        self.result = ResponseActionResultModel(
            id=701,
            response_action_id=401,
            agent_id="agent-1",
            status="success",
            result_payload={"schema_version": "v1"},
            error=None,
            started_at=now - timedelta(seconds=5),
            finished_at=now - timedelta(seconds=1),
            created_at=now - timedelta(seconds=1),
            updated_at=now - timedelta(seconds=1),
        )

    def query(self, model):
        if model is ResponseActionModel:
            return _FakeQuery(first_row=self.action, all_rows=[self.action])
        if model is ResponseActionResultModel:
            return _FakeQuery(first_row=self.result, all_rows=[self.result])
        raise AssertionError(f"unexpected model query: {model}")

    def add(self, obj):
        return None

    def flush(self):
        return None

    def commit(self):
        return None

    def refresh(self, obj):
        return None

    def close(self):
        return None


def test_response_actions_list_and_detail(monkeypatch) -> None:
    fake_db = _FakeDB()
    monkeypatch.setattr(response_api, "SessionLocal", lambda: fake_db)
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=1, username="root", role="admin")
    try:
        with TestClient(app) as client:
            r_list = client.get("/response/actions?agent_id=agent-1&status=pending&limit=20")
            assert r_list.status_code == 200
            rows = r_list.json()
            assert len(rows) == 1
            assert rows[0]["id"] == 401
            assert rows[0]["status"] == "pending"

            r_get = client.get("/response/actions/401")
            assert r_get.status_code == 200
            body = r_get.json()
            assert body["id"] == 401
            assert body["action_type"] == "collect_triage_bundle"
    finally:
        app.dependency_overrides.pop(require_admin, None)


def test_response_actions_result_endpoint(monkeypatch) -> None:
    fake_db = _FakeDB()
    monkeypatch.setattr(response_api, "SessionLocal", lambda: fake_db)
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=1, username="root", role="admin")
    try:
        with TestClient(app) as client:
            r = client.get("/response/actions/401/result")
            assert r.status_code == 200
            body = r.json()
            assert body["response_action_id"] == 401
            assert body["status"] == "success"
            assert body["result_payload"]["schema_version"] == "v1"
    finally:
        app.dependency_overrides.pop(require_admin, None)


def test_response_actions_cancel_pending(monkeypatch) -> None:
    fake_db = _FakeDB()
    monkeypatch.setattr(response_api, "SessionLocal", lambda: fake_db)
    audits = []
    monkeypatch.setattr(response_api, "write_audit_event", lambda *args, **kwargs: audits.append(kwargs))
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=1, username="root", role="admin")
    try:
        with TestClient(app) as client:
            r = client.post("/response/actions/401/cancel")
            assert r.status_code == 200
            body = r.json()
            assert body["status"] == "cancelled"
            assert body["cancelled_by"] == "root"
            assert len(audits) == 1
            assert audits[0]["action"] == "response.actions.cancel"
    finally:
        app.dependency_overrides.pop(require_admin, None)
