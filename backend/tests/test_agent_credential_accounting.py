from __future__ import annotations

import os
from datetime import datetime, timedelta
from types import SimpleNamespace

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.features.agents import auth as agents_auth
from app.features.agents import service as agents_service
from app.features.agents.models import AgentModel

RAW_CREDENTIAL = "agc.agent-1.a-very-long-and-secret-value"
SALT = "salt-value"


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
            return _FakeQuery([self._agent] if self._agent is not None else [])
        return _FakeQuery(self._credentials)

    def add(self, row) -> None:
        return None

    def commit(self) -> None:
        self.commits += 1

    def close(self) -> None:
        return None


def _credential(*, used_uses: int = 0, max_uses: int = 100_000, expires_in: int = 3600):
    return SimpleNamespace(
        id=7,
        agent_id="agent-1",
        credential_salt=SALT,
        credential_hash=agents_auth.hash_agent_credential(RAW_CREDENTIAL, SALT),
        expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
        max_uses=max_uses,
        used_uses=used_uses,
        last_used_at=None,
        revoked_at=None,
    )


@pytest.fixture()
def authenticate(monkeypatch: pytest.MonkeyPatch):
    def run(credential, *, agent=None):
        agent_row = agent if agent is not None else SimpleNamespace(id=1, agent_id="agent-1", is_revoked=False, last_seen_at=None)
        session = _FakeSession(agent_row, [credential] if credential is not None else [])
        monkeypatch.setattr(agents_auth, "SessionLocal", lambda: session)
        return agents_auth.get_current_agent(_request()), session

    return run


def test_authenticating_does_not_spend_a_credential_use(authenticate):
    credential = _credential(used_uses=0)

    for _ in range(5):
        principal, _session = authenticate(credential)

    assert principal.agent_id == "agent-1"
    assert principal.credential_id == 7
    assert credential.used_uses == 0


def test_a_credential_at_its_use_ceiling_still_authenticates(authenticate):
    credential = _credential(used_uses=100_000, max_uses=100_000)

    principal, _session = authenticate(credential)

    assert principal.auth_method == "credential"
    assert credential.used_uses == 100_000


def test_an_expired_credential_is_refused(authenticate):
    credential = _credential(expires_in=-1)

    with pytest.raises(HTTPException) as exc:
        authenticate(credential)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Agent credential expired"


def test_a_revoked_agent_is_refused(authenticate):
    revoked = SimpleNamespace(id=1, agent_id="agent-1", is_revoked=True, last_seen_at=None)

    with pytest.raises(HTTPException) as exc:
        authenticate(_credential(), agent=revoked)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Unknown or revoked agent"


def test_an_unmatched_credential_is_refused(authenticate):
    other = _credential()
    other.credential_hash = agents_auth.hash_agent_credential("agc.agent-1.something-else", SALT)

    with pytest.raises(HTTPException) as exc:
        authenticate(other)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid agent credential"


def test_rotating_spends_one_redemption(monkeypatch: pytest.MonkeyPatch):
    credential = _credential(used_uses=3)
    saved: list = []
    monkeypatch.setattr(agents_service.repository, "get_credential_by_id", lambda db, cid: credential if cid == 7 else None)
    monkeypatch.setattr(agents_service.repository, "save_credential", lambda db, row: saved.append(row) or row)
    redeemed_at = datetime.utcnow()

    agents_service._spend_credential_redemption(object(), credential_id=7, redeemed_at=redeemed_at)

    assert credential.used_uses == 4
    assert credential.last_used_at == redeemed_at
    assert saved == [credential]


def test_rotating_without_a_credential_spends_nothing(monkeypatch: pytest.MonkeyPatch):
    saved: list = []
    monkeypatch.setattr(agents_service.repository, "get_credential_by_id", lambda db, cid: None)
    monkeypatch.setattr(agents_service.repository, "save_credential", lambda db, row: saved.append(row) or row)

    agents_service._spend_credential_redemption(object(), credential_id=None, redeemed_at=datetime.utcnow())

    assert saved == []
