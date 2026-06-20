from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from datetime import datetime
from types import SimpleNamespace

import app.features.response.agent_actions as mod
from app.features.agents.auth import AgentPrincipal
from app.features.response.schemas import AgentResponseActionResultIn


class _FakeRepo:
    def __init__(self, *, agent_row, pending=None, action=None, latest=None):
        self._agent_row = agent_row
        self._pending = list(pending or [])
        self._action = action
        self._latest = latest
        self.saved_actions = []
        self.saved_results = []
        self.commits = 0

    def get_agent_by_id(self, db, row_id):
        return self._agent_row

    def list_pending_actions_for_agent(self, db, *, agent_id, limit, for_update):
        return self._pending

    def save_response_action(self, db, row):
        self.saved_actions.append(row)
        return row

    save_action = save_response_action

    def get_response_action(self, db, response_action_id, *, for_update=False):
        return self._action

    def get_action(self, db, *, action_id, for_update=False):
        return self._action

    def get_latest_response_action_result(self, db, *, response_action_id, agent_id):
        return self._latest

    def get_latest_result_for_agent(self, db, *, action_id, agent_id):
        return self._latest

    def save_response_action_result(self, db, row):
        self.saved_results.append(row)
        return row

    save_result = save_response_action_result

    def commit(self, db):
        self.commits += 1

    def refresh(self, db, row):
        pass


def _agent():
    return AgentPrincipal(id=1, agent_id="agent-x", auth_method="cert", credential_id=1)


def _patch(monkeypatch, repo):
    published = []
    monkeypatch.setattr(mod, "repository", repo)
    monkeypatch.setattr(mod, "publish_response_action_lifecycle", lambda **kw: published.append(kw))
    return published


def test_list_pending_actions_marks_delivered_and_publishes(monkeypatch):
    pending = SimpleNamespace(
        id=10, status="pending", action_type="isolate", agent_id="agent-x",
        expires_at=None, finished_at=None, last_error=None, delivered_at=None, requested_by="admin",
    )
    repo = _FakeRepo(agent_row=SimpleNamespace(is_revoked=False), pending=[pending])
    published = _patch(monkeypatch, repo)

    out = mod.list_pending_actions(object(), request=None, agent=_agent(), audit_writer=lambda *a, **k: None)

    assert [r.id for r in out] == [10]
    assert pending.status == "delivered"
    assert pending.delivered_at is not None
    assert published == [{"action": pending, "lifecycle_event": "delivered"}]
    assert repo.commits == 1


def test_list_pending_actions_expires_and_publishes(monkeypatch):
    expired = SimpleNamespace(
        id=11, status="pending", action_type="isolate", agent_id="agent-x",
        expires_at=datetime(2000, 1, 1), finished_at=None, last_error=None, delivered_at=None, requested_by="admin",
    )
    repo = _FakeRepo(agent_row=SimpleNamespace(is_revoked=False), pending=[expired])
    published = _patch(monkeypatch, repo)

    out = mod.list_pending_actions(object(), request=None, agent=_agent(), audit_writer=lambda *a, **k: None)

    assert out == []
    assert expired.status == "expired"
    assert published == [{"action": expired, "lifecycle_event": "expired"}]


def test_report_action_result_success_publishes_completed(monkeypatch):
    action = SimpleNamespace(
        id=10, status="delivered", action_type="isolate", agent_id="agent-x",
        delivered_at=datetime(2024, 1, 1), started_at=None, finished_at=None, last_error=None,
    )
    latest = SimpleNamespace(status=None, result_payload=None, error=None, started_at=None, finished_at=None)
    repo = _FakeRepo(agent_row=SimpleNamespace(is_revoked=False), action=action, latest=latest)
    published = _patch(monkeypatch, repo)

    payload = AgentResponseActionResultIn(response_action_id=10, agent_id="agent-x", status="success", result_payload={})
    res = mod.report_action_result(object(), payload=payload, request=None, agent=_agent(), audit_writer=lambda *a, **k: None)

    assert res == {"status": "success"}
    assert action.status == "success"
    assert len(published) == 1
    assert published[0]["action"] is action
    assert published[0]["lifecycle_event"] == "completed"
    assert published[0]["result"] is latest


def test_report_action_result_failed_publishes_failed_and_audits(monkeypatch):
    action = SimpleNamespace(
        id=12, status="delivered", action_type="isolate", agent_id="agent-x",
        delivered_at=datetime(2024, 1, 1), started_at=None, finished_at=None, last_error=None,
    )
    latest = SimpleNamespace(status=None, result_payload=None, error=None, started_at=None, finished_at=None)
    repo = _FakeRepo(agent_row=SimpleNamespace(is_revoked=False), action=action, latest=latest)
    published = _patch(monkeypatch, repo)
    audits = []

    payload = AgentResponseActionResultIn(response_action_id=12, agent_id="agent-x", status="failed", error="boom")
    res = mod.report_action_result(
        object(), payload=payload, request=None, agent=_agent(), audit_writer=lambda *a, **k: audits.append(k)
    )

    assert res == {"status": "failed"}
    assert action.status == "failed"
    assert action.last_error == "boom"
    assert published[0]["lifecycle_event"] == "failed"
    assert len(audits) == 1
