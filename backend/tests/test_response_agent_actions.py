from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

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


def _managed_agent(*action_types):
    return SimpleNamespace(
        is_revoked=False,
        agent_metadata={"profile": "managed"},
        metrics={"capabilities": {"response_action_types": list(action_types)}},
    )


def test_list_pending_actions_marks_delivered_and_publishes(monkeypatch):
    pending = SimpleNamespace(
        id=10, status="pending", action_type="collect_triage_bundle", agent_id="agent-x",
        expires_at=None, finished_at=None, last_error=None, delivered_at=None, requested_by="admin",
    )
    repo = _FakeRepo(agent_row=_managed_agent("collect_triage_bundle"), pending=[pending])
    published = _patch(monkeypatch, repo)

    out = mod.list_pending_actions(object(), request=None, agent=_agent(), audit_writer=lambda *a, **k: None)

    assert [r.id for r in out] == [10]
    assert pending.status == "delivered"
    assert pending.delivered_at is not None
    assert published == [{"action": pending, "lifecycle_event": "delivered"}]
    assert repo.commits == 1


def test_list_pending_actions_fails_action_after_capability_is_removed(monkeypatch):
    pending = SimpleNamespace(
        id=12,
        status="pending",
        action_type="run_shell_command",
        agent_id="agent-x",
        expires_at=None,
        finished_at=None,
        last_error=None,
        delivered_at=None,
        requested_by="admin",
    )
    repo = _FakeRepo(agent_row=_managed_agent("kill_process"), pending=[pending])
    published = _patch(monkeypatch, repo)

    out = mod.list_pending_actions(object(), request=None, agent=_agent(), audit_writer=lambda *a, **k: None)

    assert out == []
    assert pending.status == "failed"
    assert pending.last_error == "agent capability unavailable: unsupported_action"
    assert published == [{"action": pending, "lifecycle_event": "failed"}]


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


def test_terminal_result_retry_is_idempotent(monkeypatch):
    started_at = datetime(2026, 7, 30, 12, 0, 0)
    finished_at = datetime(2026, 7, 30, 12, 0, 1)
    action = SimpleNamespace(
        id=14,
        status="success",
        action_type="collect_triage_bundle",
        agent_id="agent-x",
        delivered_at=started_at,
        started_at=started_at,
        finished_at=finished_at,
        last_error=None,
    )
    latest = SimpleNamespace(
        status="success",
        result_payload={"bundle": "ready"},
        error=None,
        started_at=started_at,
        finished_at=finished_at,
    )
    repo = _FakeRepo(agent_row=SimpleNamespace(is_revoked=False), action=action, latest=latest)
    published = _patch(monkeypatch, repo)
    payload = AgentResponseActionResultIn(
        response_action_id=14,
        agent_id="agent-x",
        status="success",
        result_payload={"bundle": "ready"},
        started_at=started_at,
        finished_at=finished_at,
    )

    result = mod.report_action_result(
        object(),
        payload=payload,
        request=None,
        agent=_agent(),
        audit_writer=lambda *args, **kwargs: None,
    )

    assert result == {"status": "success", "duplicate": True}
    assert repo.saved_actions == []
    assert repo.saved_results == []
    assert repo.commits == 0
    assert published == []


def test_terminal_result_conflict_is_rejected(monkeypatch):
    action = SimpleNamespace(
        id=15,
        status="success",
        action_type="collect_triage_bundle",
        agent_id="agent-x",
        delivered_at=None,
        started_at=None,
        finished_at=None,
        last_error=None,
    )
    latest = SimpleNamespace(
        status="success",
        result_payload={"bundle": "ready"},
        error=None,
        started_at=None,
        finished_at=None,
    )
    repo = _FakeRepo(agent_row=SimpleNamespace(is_revoked=False), action=action, latest=latest)
    _patch(monkeypatch, repo)
    payload = AgentResponseActionResultIn(
        response_action_id=15,
        agent_id="agent-x",
        status="failed",
        error="late failure",
    )

    with pytest.raises(HTTPException) as exc:
        mod.report_action_result(
            object(),
            payload=payload,
            request=None,
            agent=_agent(),
            audit_writer=lambda *args, **kwargs: None,
        )

    assert exc.value.status_code == 409
    assert action.status == "success"
    assert repo.commits == 0
