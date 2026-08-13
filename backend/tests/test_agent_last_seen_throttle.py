from __future__ import annotations

import os
from datetime import datetime, timedelta
from types import SimpleNamespace

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

import pytest
from starlette.requests import Request

from app.core.config import settings
from app.features.agents import auth as agents_auth
from app.features.agents.models import AgentModel

RAW_CREDENTIAL = "agc.agent-1.a-very-long-and-secret-value"
SALT = "salt-value"


class _FakeRedis:
    def __init__(self, *, fail: bool = False):
        self.keys: dict[str, int] = {}
        self.fail = fail

    def set(self, key, value, nx=False, ex=None):
        if self.fail:
            raise RuntimeError("redis is down")
        if nx and key in self.keys:
            return None
        self.keys[key] = int(ex or 0)
        return True


class _FakeQuery:
    def __init__(self, rows: list):
        self._rows = rows

    def filter(self, *args, **kwargs) -> "_FakeQuery":
        return self

    def first(self):
        return self._rows[0] if self._rows else None

    def all(self) -> list:
        return list(self._rows)


class _FakeSession:
    def __init__(self, agent, credentials: list):
        self._agent = agent
        self._credentials = credentials
        self.commits = 0

    def query(self, model):
        if model is AgentModel:
            return _FakeQuery([self._agent])
        return _FakeQuery(self._credentials)

    def add(self, row) -> None:
        return None

    def commit(self) -> None:
        self.commits += 1

    def close(self) -> None:
        return None


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/ingest/events",
            "headers": [
                (b"x-agent-id", b"agent-1"),
                (b"x-agent-credential", RAW_CREDENTIAL.encode("utf-8")),
            ],
            "client": ("127.0.0.1", 51234),
            "query_string": b"",
            "scheme": "http",
        }
    )


@pytest.fixture()
def authenticate(monkeypatch: pytest.MonkeyPatch):
    agent = SimpleNamespace(id=1, agent_id="agent-1", is_revoked=False, last_seen_at=None)
    credential = SimpleNamespace(
        id=7,
        agent_id="agent-1",
        credential_salt=SALT,
        credential_hash=agents_auth.hash_agent_credential(RAW_CREDENTIAL, SALT),
        expires_at=datetime.utcnow() + timedelta(hours=1),
        max_uses=100_000,
        used_uses=0,
        last_used_at=None,
        revoked_at=None,
    )
    session = _FakeSession(agent, [credential])
    monkeypatch.setattr(agents_auth, "SessionLocal", lambda: session)

    def run():
        agents_auth.get_current_agent(_request())
        return agent, session

    return run


def test_the_first_request_writes_last_seen_and_the_rest_do_not(authenticate, monkeypatch: pytest.MonkeyPatch):
    redis = _FakeRedis()
    monkeypatch.setattr(settings, "SEAGULL_AGENT_LAST_SEEN_THROTTLE_SECONDS", 60)
    monkeypatch.setattr(agents_auth, "get_redis", lambda: redis)

    for _ in range(10):
        agent, session = authenticate()

    assert agent.last_seen_at is not None
    assert session.commits == 1


def test_each_window_gets_one_write(authenticate, monkeypatch: pytest.MonkeyPatch):
    redis = _FakeRedis()
    monkeypatch.setattr(settings, "SEAGULL_AGENT_LAST_SEEN_THROTTLE_SECONDS", 60)
    monkeypatch.setattr(agents_auth, "get_redis", lambda: redis)

    authenticate()
    authenticate()
    redis.keys.clear()
    _agent, session = authenticate()

    assert session.commits == 2


def test_a_zero_window_writes_on_every_request(authenticate, monkeypatch: pytest.MonkeyPatch):
    redis = _FakeRedis()
    monkeypatch.setattr(settings, "SEAGULL_AGENT_LAST_SEEN_THROTTLE_SECONDS", 0)
    monkeypatch.setattr(agents_auth, "get_redis", lambda: redis)

    for _ in range(3):
        _agent, session = authenticate()

    assert session.commits == 3


def test_authentication_survives_an_unreachable_redis(authenticate, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "SEAGULL_AGENT_LAST_SEEN_THROTTLE_SECONDS", 60)
    monkeypatch.setattr(agents_auth, "get_redis", lambda: None)

    agent, session = authenticate()

    assert agent.last_seen_at is None
    assert session.commits == 0


def test_authentication_survives_a_failing_redis(authenticate, monkeypatch: pytest.MonkeyPatch):
    redis = _FakeRedis(fail=True)
    monkeypatch.setattr(settings, "SEAGULL_AGENT_LAST_SEEN_THROTTLE_SECONDS", 60)
    monkeypatch.setattr(agents_auth, "get_redis", lambda: redis)

    agent, session = authenticate()

    assert agent.last_seen_at is None
    assert session.commits == 0
