from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from typing import Any, Dict, Iterator, List

import pytest
from fastapi.testclient import TestClient

from app.core.api.body_limit import PAYLOAD_TOO_LARGE_DETAIL, policy_from_settings
from app.core.db import get_db
from app.features.agents.auth import AgentPrincipal, get_current_agent
from app.features.events import storage_contract as contract
from app.features.ingest import api as ingest_api
from app.main import app

_AGENT_ID = "agent-a"


class _FakeDB:
    def close(self) -> None:
        return None


def _event(**overrides: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "agent_id": _AGENT_ID,
        "event_type": "flow",
        "schema_version": 1,
        "timestamp": "2026-08-11T12:00:00+00:00",
        "src_ip": "203.0.113.4",
        "dst_ip": "198.51.100.9",
        "src_port": 40100,
        "dst_port": 443,
        "proto": "tcp",
        "bytes": 512,
        "extra": {},
    }
    payload.update(overrides)
    return payload


@pytest.fixture()
def admitted(monkeypatch: pytest.MonkeyPatch) -> Iterator[List[List[Any]]]:
    accepted: List[List[Any]] = []

    def _ingest(db: Any, *, events: List[Any], agent: AgentPrincipal) -> Dict[str, Any]:
        accepted.append(events)
        return {"accepted": True, "durable": True, "received": len(events), "enqueued": 1}

    monkeypatch.setattr(ingest_api, "ingest_events", _ingest)
    app.dependency_overrides[get_current_agent] = lambda: AgentPrincipal(
        id=1,
        agent_id=_AGENT_ID,
        auth_method="mtls",
    )
    app.dependency_overrides[get_db] = lambda: _FakeDB()
    try:
        yield accepted
    finally:
        app.dependency_overrides.pop(get_current_agent, None)
        app.dependency_overrides.pop(get_db, None)


def test_a_batch_within_the_contract_is_accepted(admitted: List[List[Any]]) -> None:
    with TestClient(app) as client:
        response = client.post("/ingest/events", json=[_event(), _event(event_type="ssh_auth")])

    assert response.status_code == 200
    assert response.json()["durable"] is True
    assert len(admitted[0]) == 2


@pytest.mark.parametrize(
    "event",
    [
        _event(event_type="e" * (contract.EVENT_TYPE_MAX_CHARS + 1)),
        _event(agent_id="a" * (contract.AGENT_ID_MAX_CHARS + 1)),
        _event(src_ip="dns.example.test"),
        _event(dst_port=contract.PORT_MAX + 1),
        _event(proto="p" * (contract.PROTO_MAX_CHARS + 1)),
        _event(extra={"note": "n" * (contract.EXTRA_MAX_TEXT_CHARS + 1)}),
    ],
)
def test_a_poison_event_is_refused_before_the_batch_is_called_durable(
    admitted: List[List[Any]],
    event: Dict[str, Any],
) -> None:
    with TestClient(app) as client:
        response = client.post("/ingest/events", json=[_event(), event])

    assert response.status_code == 422
    assert admitted == []


def test_the_reason_names_the_offending_event_and_field(admitted: List[List[Any]]) -> None:
    with TestClient(app) as client:
        response = client.post("/ingest/events", json=[_event(), _event(src_ip="10.0.0.256")])

    assert response.status_code == 422
    location = response.json()["detail"][0]["loc"]
    assert location[1] == 1
    assert location[2] == "src_ip"


def test_a_body_over_the_route_ceiling_never_reaches_the_route() -> None:
    oversized = b"x" * (policy_from_settings().default.max_bytes + 1)

    with TestClient(app) as client:
        response = client.post("/auth/login", content=oversized, headers={"content-type": "application/json"})

    assert response.status_code == 413
    assert response.json()["detail"] == PAYLOAD_TOO_LARGE_DETAIL


def test_a_chunked_body_over_the_ceiling_is_answered_as_too_large_not_as_a_parse_error() -> None:
    limit = policy_from_settings().default.max_bytes

    def _chunks() -> Iterator[bytes]:
        chunk = b"x" * 65536
        for _ in range((limit // len(chunk)) + 2):
            yield chunk

    with TestClient(app) as client:
        response = client.post("/auth/login", content=_chunks(), headers={"content-type": "application/json"})

    assert response.status_code == 413
    assert response.json()["detail"] == PAYLOAD_TOO_LARGE_DETAIL
