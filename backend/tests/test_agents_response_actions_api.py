from __future__ import annotations

import os
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.core.db import get_db
from app.features.agents import api as agents_api
from app.features.agents.auth import AgentPrincipal, get_current_agent
from app.features.agents.models import AgentModel
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

    def with_for_update(self, *args, **kwargs):
        return self

    def first(self):
        return self._first

    def all(self):
        return list(self._all)


class _PendingDB:
    def __init__(self):
        self.agent = AgentModel(id=1, agent_id="agent-1", is_revoked=False)
        self.action = ResponseActionModel(
            id=101,
            action_type="collect_triage_bundle",
            agent_id="agent-1",
            status="pending",
            payload={},
            requested_by="admin",
            requested_at=datetime.utcnow() - timedelta(minutes=1),
            expires_at=datetime.utcnow() + timedelta(minutes=5),
        )

    def query(self, model):
        if model is AgentModel:
            return _FakeQuery(first_row=self.agent)
        if model is ResponseActionModel:
            return _FakeQuery(all_rows=[self.action])
        raise AssertionError(f"unexpected model query: {model}")

    def add(self, obj):
        return None

    def commit(self):
        return None

    def refresh(self, obj):
        return None

    def close(self):
        return None


class _ResultDB:
    def __init__(self):
        self.agent = AgentModel(id=1, agent_id="agent-1", is_revoked=False)
        self.action = ResponseActionModel(
            id=202,
            action_type="collect_triage_bundle",
            agent_id="agent-1",
            status="running",
            payload={},
            requested_by="admin",
            requested_at=datetime.utcnow() - timedelta(minutes=3),
        )
        self.result_row = None

    def query(self, model):
        if model is AgentModel:
            return _FakeQuery(first_row=self.agent)
        if model is ResponseActionModel:
            return _FakeQuery(first_row=self.action)
        if model is ResponseActionResultModel:
            return _FakeQuery(first_row=self.result_row)
        raise AssertionError(f"unexpected model query: {model}")

    def add(self, obj):
        if isinstance(obj, ResponseActionResultModel):
            self.result_row = obj
        return None

    def commit(self):
        return None

    def refresh(self, obj):
        return None

    def close(self):
        return None


def test_agent_pending_response_actions_mark_delivered(monkeypatch) -> None:
    fake_db = _PendingDB()
    audits = []
    monkeypatch.setattr(agents_api, "write_audit_event", lambda *args, **kwargs: audits.append(kwargs))
    app.dependency_overrides[get_db] = lambda: fake_db
    app.dependency_overrides[get_current_agent] = lambda: AgentPrincipal(id=1, agent_id="agent-1", auth_method="credential")
    try:
        with TestClient(app) as client:
            r = client.get("/agents/response-actions/pending")
            assert r.status_code == 200
            body = r.json()
            assert len(body) == 1
            assert body[0]["id"] == 101
            assert body[0]["status"] == "delivered"
            assert fake_db.action.status == "delivered"
            assert fake_db.action.delivered_at is not None
            assert len(audits) == 1
            assert audits[0]["action"] == "response.actions.delivered"
            assert audits[0]["resource_type"] == "response_action"
            assert audits[0]["resource_id"] == "101"
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_agent, None)


def test_agent_report_response_action_result_persists(monkeypatch) -> None:
    fake_db = _ResultDB()
    audits = []
    monkeypatch.setattr(agents_api, "write_audit_event", lambda *args, **kwargs: audits.append(kwargs))
    app.dependency_overrides[get_db] = lambda: fake_db
    app.dependency_overrides[get_current_agent] = lambda: AgentPrincipal(id=1, agent_id="agent-1", auth_method="credential")
    try:
        with TestClient(app) as client:
            r = client.post(
                "/agents/response-actions/results",
                json={
                    "response_action_id": 202,
                    "agent_id": "agent-1",
                    "status": "success",
                    "result_payload": {"schema_version": "v1"},
                    "started_at": "2026-03-29T15:00:00Z",
                    "finished_at": "2026-03-29T15:00:01Z",
                },
            )
            assert r.status_code == 201
            assert fake_db.result_row is not None
            assert fake_db.result_row.response_action_id == 202
            assert fake_db.result_row.agent_id == "agent-1"
            assert fake_db.result_row.status == "success"
            assert fake_db.action.status == "success"
            assert fake_db.action.started_at is not None
            assert fake_db.action.finished_at is not None
            assert len(audits) == 0
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_agent, None)


def test_agent_report_normalizes_zero_timestamps(monkeypatch) -> None:
    fake_db = _ResultDB()
    monkeypatch.setattr(agents_api, "write_audit_event", lambda *args, **kwargs: None)
    app.dependency_overrides[get_db] = lambda: fake_db
    app.dependency_overrides[get_current_agent] = lambda: AgentPrincipal(id=1, agent_id="agent-1", auth_method="credential")
    try:
        with TestClient(app) as client:
            r = client.post(
                "/agents/response-actions/results",
                json={
                    "response_action_id": 202,
                    "agent_id": "agent-1",
                    "status": "success",
                    "result_payload": {"schema_version": "v1"},
                    "started_at": "2026-03-29T15:00:00Z",
                    "finished_at": "0001-01-01T00:00:00Z",
                },
            )
            assert r.status_code == 201
            assert fake_db.result_row.finished_at is None
            assert fake_db.action.finished_at is not None
            assert fake_db.action.finished_at.year >= 2026
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_agent, None)


def test_agent_report_response_action_failure_emits_audit(monkeypatch) -> None:
    fake_db = _ResultDB()
    audits = []
    monkeypatch.setattr(agents_api, "write_audit_event", lambda *args, **kwargs: audits.append(kwargs))
    app.dependency_overrides[get_db] = lambda: fake_db
    app.dependency_overrides[get_current_agent] = lambda: AgentPrincipal(id=1, agent_id="agent-1", auth_method="credential")
    try:
        with TestClient(app) as client:
            r = client.post(
                "/agents/response-actions/results",
                json={
                    "response_action_id": 202,
                    "agent_id": "agent-1",
                    "status": "failed",
                    "error": "execution failed",
                },
            )
            assert r.status_code == 201
            assert fake_db.result_row is not None
            assert fake_db.result_row.status == "failed"
            assert fake_db.action.status == "failed"
            assert fake_db.action.last_error == "execution failed"
            assert len(audits) == 1
            assert audits[0]["action"] == "response.actions.failed"
            assert audits[0]["outcome"] == "failure"
            assert audits[0]["resource_type"] == "response_action"
            assert audits[0]["resource_id"] == "202"
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_agent, None)


def test_agent_report_response_action_running_sets_started(monkeypatch) -> None:
    fake_db = _ResultDB()
    fake_db.action.status = "delivered"
    app.dependency_overrides[get_db] = lambda: fake_db
    app.dependency_overrides[get_current_agent] = lambda: AgentPrincipal(id=1, agent_id="agent-1", auth_method="credential")
    try:
        with TestClient(app) as client:
            r = client.post(
                "/agents/response-actions/results",
                json={
                    "response_action_id": 202,
                    "agent_id": "agent-1",
                    "status": "running",
                    "started_at": "2026-03-29T15:00:00Z",
                },
            )
            assert r.status_code == 201
            assert fake_db.action.status == "running"
            assert fake_db.action.started_at is not None
            assert fake_db.action.finished_at is None
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_agent, None)
