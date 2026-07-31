from __future__ import annotations

from types import SimpleNamespace

from app.core.config import settings
from app.features.agents import configuration
from app.features.agents import service as agents_service
from app.features.agents.auth import AgentPrincipal
from app.features.agents.schemas import AgentConfigUpdateIn


def test_default_configuration_starts_at_revision_one(monkeypatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_DEFAULT_AGENT_CONFIG_JSON", '{"modules":{"fim":{"enabled":true}}}')
    value = settings.default_agent_config()
    assert value["revision"] == 1
    assert value["modules"]["fim"]["enabled"] is True


def test_invalid_default_revision_is_replaced(monkeypatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_DEFAULT_AGENT_CONFIG_JSON", '{"revision":0}')
    assert settings.default_agent_config() == {"revision": 1}


def test_replacement_revision_is_server_controlled() -> None:
    value = configuration.replace(
        {"revision": 7, "modules": {"fim": {"enabled": True}}},
        {"revision": 999, "modules": {"fim": {"enabled": False}}},
    )
    assert value["revision"] == 8
    assert value["modules"]["fim"]["enabled"] is False


def test_set_config_increments_revision(monkeypatch) -> None:
    row = SimpleNamespace(agent_id="agent-1", is_revoked=False, config={"revision": 4})
    saved = []
    commits = []
    monkeypatch.setattr(agents_service.repository, "get_agent_by_agent_id", lambda db, agent_id: row)
    monkeypatch.setattr(agents_service.repository, "save_agent", lambda db, value: saved.append(value))
    monkeypatch.setattr(agents_service.repository, "commit", lambda db: commits.append(True))

    agents_service.set_config(
        object(),
        agent_id="agent-1",
        payload=AgentConfigUpdateIn(config={"revision": 400, "modules": {"fim": {"enabled": True}}}),
        request=None,
        admin=SimpleNamespace(id=1, username="admin"),
        audit_writer=lambda *args, **kwargs: None,
    )

    assert row.config["revision"] == 5
    assert row.config["modules"]["fim"]["enabled"] is True
    assert saved == [row]
    assert commits == [True]


def test_get_config_migrates_legacy_revision(monkeypatch) -> None:
    row = SimpleNamespace(id=1, agent_id="agent-1", is_revoked=False, config={"modules": {}})
    commits = []
    monkeypatch.setattr(agents_service.repository, "get_agent_by_id", lambda db, row_id: row)
    monkeypatch.setattr(agents_service.repository, "save_agent", lambda db, value: None)
    monkeypatch.setattr(agents_service.repository, "commit", lambda db: commits.append(True))

    value = agents_service.get_config(
        object(),
        agent=AgentPrincipal(id=1, agent_id="agent-1", auth_method="credential"),
    )

    assert value["revision"] == 1
    assert row.config["revision"] == 1
    assert commits == [True]
