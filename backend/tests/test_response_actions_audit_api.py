from __future__ import annotations

import os
from datetime import datetime

from fastapi.testclient import TestClient

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core.portal_auth import PortalPrincipal, require_admin
from app.features.response import api as response_api
from app.main import app
from app.features.agents.models import AgentModel
from app.features.response.models import ResponseActionModel


class _FakeQuery:
    def __init__(self, first_row=None):
        self._first = first_row

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._first


class _FakeDB:
    def __init__(self):
        self.agent = AgentModel(id=1, agent_id="agent-1", is_revoked=False)
        self.created = None

    def query(self, model):
        if model is AgentModel:
            return _FakeQuery(first_row=self.agent)
        raise AssertionError(f"unexpected model query: {model}")

    def add(self, obj):
        if isinstance(obj, ResponseActionModel):
            self.created = obj
        return None

    def flush(self):
        if self.created is not None and not self.created.id:
            now = datetime.utcnow()
            self.created.id = 301
            self.created.created_at = now
            self.created.updated_at = now
        return None

    def commit(self):
        return None

    def refresh(self, obj):
        return None

    def close(self):
        return None


def test_response_action_create_emits_request_audit(monkeypatch) -> None:
    fake_db = _FakeDB()
    monkeypatch.setattr(response_api, "SessionLocal", lambda: fake_db)
    audits = []
    monkeypatch.setattr(response_api, "write_audit_event", lambda *args, **kwargs: audits.append(kwargs))
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=9, username="root", role="admin")
    try:
        with TestClient(app) as client:
            r = client.post(
                "/response/actions",
                json={
                    "action_type": "collect_triage_bundle",
                    "agent_id": "agent-1",
                    "payload": {
                        "collectors": {"runtime": True, "host": True},
                        "limits": {"max_processes": 100},
                        "redaction": {"mask_secrets": True},
                    },
                },
            )
            assert r.status_code == 201
            assert len(audits) == 1
            assert audits[0]["action"] == "response.actions.create"
            assert audits[0]["resource_type"] == "response_action"
            assert audits[0]["resource_id"] == "301"
            assert audits[0]["context"]["payload_size"] == 3
            assert sorted(audits[0]["context"]["payload_keys"]) == ["collectors", "limits", "redaction"]
            assert "payload" not in audits[0]["context"]
    finally:
        app.dependency_overrides.pop(require_admin, None)
