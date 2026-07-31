from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.features.agents import enrollment_replay
from app.features.agents import service as agents_service
from app.features.agents.auth import generate_bootstrap_token, hash_agent_credential
from app.features.agents.schemas import AgentCredentialOut, AgentEnrollIn, AgentEnrollOut


def _transaction(hostname: str = "endpoint-1") -> AgentEnrollIn:
    return AgentEnrollIn(
        enrollment_id="11111111-1111-4111-8111-111111111111",
        agent_id="agent-1",
        hostname=hostname,
        protocol_version=1,
    )


def _response() -> AgentEnrollOut:
    return AgentEnrollOut(
        agent_id="agent-1",
        config={"revision": 1},
        credential=AgentCredentialOut(
            credential="agc.agent-1.encrypted",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            max_uses=100,
            renewal_token="abt.agent-1.renewal",
            renewal_token_expires_at=datetime.utcnow() + timedelta(days=30),
        ),
    )


def _token():
    raw, salt, token_hash = generate_bootstrap_token("agent-1")
    token = SimpleNamespace(
        id=7,
        agent_id="agent-1",
        token_salt=salt,
        token_hash=token_hash,
        token_type="enrollment",
        token_metadata={},
        expires_at=datetime.utcnow() + timedelta(hours=1),
        max_uses=1,
        used_uses=1,
        last_used_at=datetime.utcnow(),
        revoked_at=datetime.utcnow(),
        revoked_reason="consumed",
    )
    return raw, token


def _active_credential(token_id: int):
    salt = "credential-salt"
    raw = _response().credential.credential
    return SimpleNamespace(
        issued_from_bootstrap_token_id=token_id,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        used_uses=0,
        max_uses=100,
        credential_salt=salt,
        credential_hash=hash_agent_credential(raw, salt),
    )


def test_replay_cache_encrypts_credentials_and_restores_exact_response() -> None:
    raw, token = _token()
    payload = _transaction()
    response = _response()

    enrollment_replay.store(token, payload, raw, response)

    serialized = str(token.token_metadata)
    assert response.credential.credential not in serialized
    assert response.credential.renewal_token not in serialized
    restored = enrollment_replay.load(token, payload, raw)
    assert restored is not None
    assert restored.model_dump(mode="json") == response.model_dump(mode="json")


def test_replay_cache_rejects_transaction_payload_mismatch() -> None:
    raw, token = _token()
    enrollment_replay.store(token, _transaction(), raw, _response())

    with pytest.raises(HTTPException) as exc:
        enrollment_replay.load(token, _transaction(hostname="changed"), raw)

    assert exc.value.status_code == 409


def test_consumed_token_authorizes_only_its_exact_cached_transaction(monkeypatch) -> None:
    raw, token = _token()
    payload = _transaction()
    response = _response()
    enrollment_replay.store(token, payload, raw, response)
    monkeypatch.setattr(
        agents_service.repository,
        "list_bootstrap_tokens_for_update",
        lambda db, agent_id: [token],
    )
    monkeypatch.setattr(
        agents_service.repository,
        "list_active_credentials",
        lambda db, agent_id: [_active_credential(token.id)],
    )

    matched, replay = agents_service._authorize_enrollment_token(object(), payload, raw)

    assert matched is token
    assert replay is not None
    assert replay.credential.credential == response.credential.credential
    assert token.used_uses == 1


def test_consumed_token_does_not_replay_a_superseded_identity(monkeypatch) -> None:
    raw, token = _token()
    payload = _transaction()
    enrollment_replay.store(token, payload, raw, _response())
    monkeypatch.setattr(
        agents_service.repository,
        "list_bootstrap_tokens_for_update",
        lambda db, agent_id: [token],
    )
    monkeypatch.setattr(
        agents_service.repository,
        "list_active_credentials",
        lambda db, agent_id: [],
    )

    with pytest.raises(HTTPException) as exc:
        agents_service._authorize_enrollment_token(object(), payload, raw)

    assert exc.value.status_code == 409


def test_manually_revoked_token_cannot_replay_cached_response(monkeypatch) -> None:
    raw, token = _token()
    payload = _transaction()
    enrollment_replay.store(token, payload, raw, _response())
    token.revoked_reason = "operator_revoked"
    monkeypatch.setattr(
        agents_service.repository,
        "list_bootstrap_tokens_for_update",
        lambda db, agent_id: [token],
    )

    with pytest.raises(HTTPException) as exc:
        agents_service._authorize_enrollment_token(object(), payload, raw)

    assert exc.value.status_code == 401
