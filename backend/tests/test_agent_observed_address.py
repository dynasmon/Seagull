from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

from app.features.agents import service as agents_service
from app.features.agents.schemas import AgentHeartbeatIn


def _request(host: str | None) -> SimpleNamespace:
    return SimpleNamespace(client=SimpleNamespace(host=host) if host is not None else None, headers={})


def test_client_address_normalizes_the_connecting_peer():
    assert agents_service.client_address(_request("203.0.113.44")) == "203.0.113.44"
    assert agents_service.client_address(_request("2001:db8::1%eth0")) == "2001:db8::1"


def test_client_address_rejects_anything_that_is_not_an_address():
    assert agents_service.client_address(None) is None
    assert agents_service.client_address(_request(None)) is None
    assert agents_service.client_address(_request("")) is None
    assert agents_service.client_address(_request("edge.internal")) is None


def test_heartbeat_records_the_address_the_agent_connects_from(monkeypatch):
    row = SimpleNamespace(
        id=1,
        agent_id="agent-core-1",
        is_revoked=False,
        last_seen_at=None,
        observed_address=None,
        observed_address_at=None,
        agent_metadata={"profile": "managed"},
        metrics={},
    )
    monkeypatch.setattr(agents_service.repository, "get_agent_by_id", lambda db, agent_pk: row)
    monkeypatch.setattr(agents_service.repository, "save_agent", lambda db, saved: None)
    monkeypatch.setattr(agents_service.repository, "commit", lambda db: None)
    monkeypatch.setattr(agents_service, "_publish_agent_heartbeat_realtime", lambda **kw: None)

    agents_service.heartbeat(
        object(),
        payload=AgentHeartbeatIn(status="ok"),
        agent=SimpleNamespace(id=1, agent_id="agent-core-1", auth_method="mtls", credential_id=None),
        request=_request("203.0.113.44"),
    )

    assert row.observed_address == "203.0.113.44"
    assert row.observed_address_at == row.last_seen_at


def test_heartbeat_keeps_the_last_known_address_when_the_peer_is_unknown(monkeypatch):
    row = SimpleNamespace(
        id=1,
        agent_id="agent-core-1",
        is_revoked=False,
        last_seen_at=None,
        observed_address="203.0.113.44",
        observed_address_at=None,
        agent_metadata={"profile": "managed"},
        metrics={},
    )
    monkeypatch.setattr(agents_service.repository, "get_agent_by_id", lambda db, agent_pk: row)
    monkeypatch.setattr(agents_service.repository, "save_agent", lambda db, saved: None)
    monkeypatch.setattr(agents_service.repository, "commit", lambda db: None)
    monkeypatch.setattr(agents_service, "_publish_agent_heartbeat_realtime", lambda **kw: None)

    agents_service.heartbeat(
        object(),
        payload=AgentHeartbeatIn(status="ok"),
        agent=SimpleNamespace(id=1, agent_id="agent-core-1", auth_method="mtls", credential_id=None),
        request=_request(None),
    )

    assert row.observed_address == "203.0.113.44"
