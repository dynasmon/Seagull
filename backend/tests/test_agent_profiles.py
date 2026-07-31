from __future__ import annotations

import os
from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

from app.features.agents import profiles
from app.features.agents import service as agents_service
from app.features.agents.schemas import AgentHeartbeatIn
from app.features.response import agent_actions
from app.features.response import service as response_service
from app.features.response.schemas import BatchDispatchIn, ResponseActionCreateIn


class TestProfileRules:
    def test_normalize_known_values(self):
        assert profiles.normalize("Sensor") == "sensor"
        assert profiles.normalize(" managed ") == "managed"
        assert profiles.normalize("root") == ""
        assert profiles.normalize(None) == ""

    def test_unknown_metadata_falls_back_to_managed(self):
        assert profiles.of({}) == profiles.MANAGED
        assert profiles.of(None) == profiles.MANAGED
        assert profiles.of({"profile": "nonsense"}) == profiles.MANAGED
        assert profiles.of({"profile": "sensor"}) == profiles.SENSOR

    def test_sensor_cannot_run_response_actions(self):
        assert profiles.allows_response_actions("sensor") is False
        assert profiles.allows_response_actions("managed") is True
        assert profiles.allows_response_actions(None) is True

    def test_reported_profile_can_downgrade_but_not_escalate(self):
        assert profiles.resolve_reported("managed", "sensor") == "sensor"
        assert profiles.resolve_reported("sensor", "managed") == "sensor"
        assert profiles.resolve_reported("sensor", None) == "sensor"
        assert profiles.resolve_reported("managed", "garbage") == "managed"

    def test_response_action_requires_reported_capability(self):
        agent_row = SimpleNamespace(agent_metadata={"profile": "managed"}, metrics={})
        assert profiles.response_action_support(agent_row, action_type="kill_process") == (
            False,
            "capabilities_not_reported",
        )
        agent_row.metrics = {
            "capabilities": {
                "response_action_types": ["kill_process", "run_shell_command"],
                "shell_exec": False,
            }
        }
        assert profiles.response_action_support(agent_row, action_type="kill_process") == (True, "")
        assert profiles.response_action_support(agent_row, action_type="quarantine_file") == (
            False,
            "unsupported_action",
        )
        assert profiles.response_action_support(agent_row, action_type="run_shell_command") == (
            False,
            "local_policy_denied",
        )


class TestResponseActionDispatchGuard:
    def test_single_dispatch_rejects_sensor_agent(self, monkeypatch):
        agent_row = SimpleNamespace(agent_id="agent-sensor", is_revoked=False, agent_metadata={"profile": "sensor"})
        monkeypatch.setattr(response_service.repository, "get_agent", lambda db, agent_id: agent_row)

        with pytest.raises(HTTPException) as exc:
            response_service.create_response_action(
                object(),
                payload=ResponseActionCreateIn(action_type="kill_process", agent_id="agent-sensor", payload={"target": {"pid": 10}, "dry_run": True}),
                request=SimpleNamespace(client=None, headers={}),
                admin=SimpleNamespace(id=1, username="admin"),
                audit_writer=lambda db, **kw: None,
            )
        assert exc.value.status_code == 409
        assert "sensor" in str(exc.value.detail)

    def test_single_dispatch_allows_managed_agent(self, monkeypatch):
        agent_row = SimpleNamespace(
            agent_id="agent-managed",
            is_revoked=False,
            agent_metadata={"profile": "managed"},
            metrics={"capabilities": {"response_action_types": ["kill_process"]}},
        )
        created = {}
        monkeypatch.setattr(response_service.repository, "get_agent", lambda db, agent_id: agent_row)
        monkeypatch.setattr(response_service.repository, "flush", lambda db: None)
        monkeypatch.setattr(response_service.repository, "commit", lambda db: None)
        monkeypatch.setattr(response_service.repository, "refresh", lambda db, row: None)
        monkeypatch.setattr(response_service, "publish_response_action_lifecycle", lambda **kw: None)

        def _create_action(db, **kwargs):
            created.update(kwargs)
            return SimpleNamespace(id=5, payload=kwargs.get("payload") or {}, expires_at=None, **{
                k: v for k, v in kwargs.items() if k in ("action_type", "agent_id", "status", "requested_by")
            })

        monkeypatch.setattr(response_service.repository, "create_action", _create_action)

        row = response_service.create_response_action(
            object(),
            payload=ResponseActionCreateIn(action_type="kill_process", agent_id="agent-managed", payload={"target": {"pid": 10}, "dry_run": True}),
            request=SimpleNamespace(client=None, headers={}),
            admin=SimpleNamespace(id=1, username="admin"),
            audit_writer=lambda db, **kw: None,
        )
        assert row.id == 5
        assert created["agent_id"] == "agent-managed"

    def test_batch_dispatch_skips_sensor_agents(self, monkeypatch):
        agents = {
            "agent-sensor": SimpleNamespace(agent_id="agent-sensor", is_revoked=False, agent_metadata={"profile": "sensor"}),
            "agent-managed": SimpleNamespace(
                agent_id="agent-managed",
                is_revoked=False,
                agent_metadata={"profile": "managed"},
                metrics={"capabilities": {"response_action_types": ["kill_process"]}},
            ),
        }
        monkeypatch.setattr(response_service.repository, "get_agent", lambda db, agent_id: agents.get(agent_id))
        monkeypatch.setattr(response_service.repository, "flush", lambda db: None)
        monkeypatch.setattr(response_service.repository, "commit", lambda db: None)
        monkeypatch.setattr(response_service.repository, "refresh", lambda db, row: None)
        monkeypatch.setattr(response_service, "publish_response_action_lifecycle", lambda **kw: None)
        monkeypatch.setattr(
            response_service.repository,
            "create_action",
            lambda db, **kwargs: SimpleNamespace(id=9, agent_id=kwargs["agent_id"]),
        )

        out = response_service.create_response_action_batch(
            object(),
            payload=BatchDispatchIn(
                action_type="kill_process",
                agent_ids=["agent-sensor", "agent-managed"],
                payload={"target": {"pid": 10}, "dry_run": True},
            ),
            request=SimpleNamespace(client=None, headers={}),
            admin=SimpleNamespace(id=1, username="admin"),
            audit_writer=lambda db, **kw: None,
        )
        assert out["skipped"] == [{"agent_id": "agent-sensor", "reason": "sensor_profile"}]
        assert [item["agent_id"] for item in out["queued"]] == ["agent-managed"]


class TestAgentActionPolling:
    def test_sensor_agent_receives_no_actions(self, monkeypatch):
        agent_row = SimpleNamespace(agent_id="agent-sensor", is_revoked=False, agent_metadata={"profile": "sensor"})
        monkeypatch.setattr(agent_actions.repository, "get_agent_by_id", lambda db, agent_pk: agent_row)

        def _must_not_run(*args, **kwargs):
            raise AssertionError("sensor agents must not read the pending action queue")

        monkeypatch.setattr(agent_actions.repository, "list_pending_actions_for_agent", _must_not_run)

        out = agent_actions.list_pending_actions(
            object(),
            request=SimpleNamespace(client=None, headers={}),
            agent=SimpleNamespace(id=3, agent_id="agent-sensor", auth_method="mtls", credential_id=None),
            audit_writer=lambda db, **kw: None,
        )
        assert out == []


class TestHeartbeatProfile:
    def _agent_row(self, metadata):
        return SimpleNamespace(
            agent_id="agent-x",
            is_revoked=False,
            agent_metadata=dict(metadata),
            metrics={},
            last_seen_at=None,
        )

    def _run_heartbeat(self, monkeypatch, row, profile):
        monkeypatch.setattr(agents_service.repository, "get_agent_by_id", lambda db, agent_pk: row)
        monkeypatch.setattr(agents_service.repository, "save_agent", lambda db, saved: None)
        monkeypatch.setattr(agents_service.repository, "commit", lambda db: None)
        monkeypatch.setattr(agents_service, "_publish_agent_heartbeat_realtime", lambda **kw: None)
        agents_service.heartbeat(
            object(),
            payload=AgentHeartbeatIn(status="ok", profile=profile),
            agent=SimpleNamespace(id=1, agent_id="agent-x", auth_method="mtls", credential_id=None),
        )

    def test_heartbeat_downgrade_is_applied(self, monkeypatch):
        row = self._agent_row({"profile": "managed"})
        self._run_heartbeat(monkeypatch, row, "sensor")
        assert row.agent_metadata["profile"] == "sensor"
        assert row.metrics["profile"] == "sensor"

    def test_heartbeat_cannot_escalate_profile(self, monkeypatch):
        row = self._agent_row({"profile": "sensor"})
        self._run_heartbeat(monkeypatch, row, "managed")
        assert row.agent_metadata["profile"] == "sensor"
        assert row.metrics["profile"] == "sensor"


class TestAdminProfileUpdate:
    def test_invalid_profile_is_rejected(self, monkeypatch):
        from app.features.agents.schemas import AgentUpdateIn

        row = SimpleNamespace(
            agent_id="agent-x",
            display_name=None,
            description=None,
            tags=[],
            agent_metadata={"profile": "sensor"},
        )
        monkeypatch.setattr(agents_service.repository, "get_agent_by_agent_id", lambda db, agent_id: row)

        with pytest.raises(HTTPException) as exc:
            agents_service.update_agent(
                object(),
                agent_id="agent-x",
                payload=AgentUpdateIn(metadata={"profile": "root"}),
                request=SimpleNamespace(client=None, headers={}),
                admin=SimpleNamespace(id=1, username="admin"),
                audit_writer=lambda db, **kw: None,
            )
        assert exc.value.status_code == 422

    def test_admin_can_promote_agent_to_managed(self, monkeypatch):
        from app.features.agents.schemas import AgentUpdateIn

        row = SimpleNamespace(
            agent_id="agent-x",
            display_name=None,
            description=None,
            tags=[],
            agent_metadata={"profile": "sensor"},
            config={},
            metrics={},
            created_at=datetime(2026, 1, 1),
            last_seen_at=None,
            is_revoked=False,
        )
        monkeypatch.setattr(agents_service.repository, "get_agent_by_agent_id", lambda db, agent_id: row)
        monkeypatch.setattr(agents_service.repository, "save_agent", lambda db, saved: None)
        monkeypatch.setattr(agents_service.repository, "commit", lambda db: None)
        monkeypatch.setattr(agents_service.repository, "refresh", lambda db, saved: None)

        agents_service.update_agent(
            object(),
            agent_id="agent-x",
            payload=AgentUpdateIn(metadata={"profile": "Managed"}),
            request=SimpleNamespace(client=None, headers={}),
            admin=SimpleNamespace(id=1, username="admin"),
            audit_writer=lambda db, **kw: None,
        )
        assert row.agent_metadata["profile"] == "managed"
