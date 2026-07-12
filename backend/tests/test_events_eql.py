from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest
from fastapi import HTTPException

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite:///./test.db")

from app.features.events import api as events_api
from app.features.events import service
from app.features.events.domain.eql import eql_sequences_from_response, normalize_eql_query
from app.features.events.domain.hunt_dialects import HuntQueryError, translate_es_query_error
from app.features.events.schemas import EqlHuntRequest, EqlHuntResponse, QueryProvenanceMeta

SEQUENCE_QUERY = (
    'sequence by agent_id with maxspan=5m '
    '[ ssh_auth where ssh_action == "failed_password" ] '
    '[ user_created where true ]'
)


@pytest.fixture(autouse=True)
def _reset_hunt_breaker() -> None:
    service._hunt_breaker.reset()


class _FakeApiError(Exception):
    def __init__(self, message: str, *, status_code: int, body: Dict[str, Any]) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class _FakeEqlNamespace:
    def __init__(self, owner: "_FakeEs") -> None:
        self._owner = owner

    def search(self, **kwargs: Any) -> Dict[str, Any]:
        self._owner.search_calls.append(kwargs)
        if self._owner.error is not None:
            raise self._owner.error
        return self._owner.response

    def delete(self, **kwargs: Any) -> None:
        self._owner.delete_calls.append(kwargs)


class _FakeEs:
    def __init__(self, response: Optional[Dict[str, Any]] = None, error: Optional[Exception] = None) -> None:
        self.response = response or {"hits": {}}
        self.error = error
        self.search_calls: List[Dict[str, Any]] = []
        self.delete_calls: List[Dict[str, Any]] = []
        self.eql = _FakeEqlNamespace(self)

    def options(self, **_kwargs: Any) -> "_FakeEs":
        return self


def _es_event(event_id: int, ts: str, event_type: str = "ssh_auth") -> Dict[str, Any]:
    return {
        "_id": str(event_id),
        "_source": {
            "id": event_id,
            "agent_id": "agent-a",
            "event_type": event_type,
            "schema_version": 1,
            "timestamp": ts,
            "src_ip": "203.0.113.9",
            "dst_ip": "192.0.2.7",
            "src_port": 51000,
            "dst_port": 22,
            "proto": "tcp",
            "bytes": 64,
            "extra": {},
        },
    }


def _sequence_response() -> Dict[str, Any]:
    return {
        "is_partial": False,
        "is_running": False,
        "timed_out": False,
        "hits": {
            "total": {"value": 1},
            "sequences": [
                {
                    "join_keys": ["agent-a"],
                    "events": [
                        _es_event(11, "2026-07-12T10:00:00Z"),
                        _es_event(12, "2026-07-12T10:03:00Z", event_type="user_created"),
                    ],
                }
            ],
        },
    }


def _use_fake_es(monkeypatch: pytest.MonkeyPatch, fake: _FakeEs) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_es_client_or_none", lambda: fake)


def _capture_counters(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        service,
        "incr_counter",
        lambda name, value=1.0, **labels: calls.append((name, labels)),
    )
    return calls


def test_eql_sequence_query_returns_ordered_events(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeEs(response=_sequence_response())
    _use_fake_es(monkeypatch, fake)
    counters = _capture_counters(monkeypatch)

    out = service.hunt_events_eql(query=SEQUENCE_QUERY, since_minutes=60)

    assert out.total == 1
    assert len(out.sequences) == 1
    sequence = out.sequences[0]
    assert sequence.join_keys == ["agent-a"]
    assert [event.id for event in sequence.events] == [11, 12]
    assert sequence.events[1].event_type == "user_created"
    assert out.meta.source == "elasticsearch"
    assert out.meta.fallback_chain == ["elasticsearch"]
    assert ("hunt_query_dialect_total", {"dialect": "eql"}) in counters


def test_eql_search_request_carries_seagull_schema_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeEs(response=_sequence_response())
    _use_fake_es(monkeypatch, fake)

    service.hunt_events_eql(query=SEQUENCE_QUERY, since_minutes=90)

    call = fake.search_calls[0]
    assert call["event_category_field"] == "event_type"
    assert call["timestamp_field"] == "timestamp"
    assert call["keep_on_completion"] is False
    assert call["wait_for_completion_timeout"] == "5000ms"
    assert call["size"] == 50
    filters = call["filter"]["bool"]["filter"]
    gte_values = [f["range"]["timestamp"]["gte"] for f in filters if "range" in f and "gte" in f["range"]["timestamp"]]
    assert len(gte_values) == 1
    started = datetime.fromisoformat(gte_values[0])
    assert datetime.now(timezone.utc) - started <= timedelta(minutes=91)


def test_eql_window_defaults_to_24_hours(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeEs(response=_sequence_response())
    _use_fake_es(monkeypatch, fake)

    out = service.hunt_events_eql(query=SEQUENCE_QUERY)

    window = out.meta.query_window_end - out.meta.query_window_start
    assert timedelta(minutes=1439) <= window <= timedelta(minutes=1441)


def test_eql_size_is_capped_by_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeEs(response=_sequence_response())
    _use_fake_es(monkeypatch, fake)

    service.hunt_events_eql(query=SEQUENCE_QUERY, size=200)
    assert fake.search_calls[0]["size"] == 50

    service.hunt_events_eql(query=SEQUENCE_QUERY, size=7)
    assert fake.search_calls[1]["size"] == 7


def test_eql_plain_event_query_maps_to_single_event_sequences() -> None:
    response = {
        "hits": {
            "total": {"value": 2},
            "events": [
                _es_event(21, "2026-07-12T09:00:00Z"),
                _es_event(22, "2026-07-12T09:01:00Z"),
            ],
        }
    }

    sequences, total = eql_sequences_from_response(response)

    assert total == 2
    assert [seq.events[0].id for seq in sequences] == [21, 22]
    assert all(seq.join_keys == [] for seq in sequences)


def test_eql_parse_error_translates_to_400_with_location(monkeypatch: pytest.MonkeyPatch) -> None:
    error = _FakeApiError(
        "parsing_exception",
        status_code=400,
        body={
            "error": {
                "root_cause": [
                    {"type": "parsing_exception", "reason": "line 1:14: mismatched input 'wehre'"}
                ]
            }
        },
    )
    fake = _FakeEs(error=error)
    _use_fake_es(monkeypatch, fake)
    counters = _capture_counters(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events_eql(query="any wehre true", since_minutes=60)

    assert exc.value.status_code == 400
    assert "line 1, column 14" in str(exc.value.detail)
    assert service._hunt_breaker.state("elasticsearch").state == "closed"
    assert ("hunt_query_error_total", {"dialect": "eql", "reason": "syntax"}) in counters


def test_eql_unknown_field_translates_to_400(monkeypatch: pytest.MonkeyPatch) -> None:
    error = _FakeApiError(
        "verification_exception",
        status_code=400,
        body={
            "error": {
                "root_cause": [
                    {
                        "type": "verification_exception",
                        "reason": "Found 1 problem\nline 1:12: Unknown column [sshaction]",
                    }
                ]
            }
        },
    )
    fake = _FakeEs(error=error)
    _use_fake_es(monkeypatch, fake)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events_eql(query='any where sshaction == "x"', since_minutes=60)

    assert exc.value.status_code == 400
    assert "Unknown field 'sshaction'" in str(exc.value.detail)


def test_eql_timed_out_response_surfaces_504(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeEs(response={"timed_out": True, "hits": {}})
    _use_fake_es(monkeypatch, fake)
    counters = _capture_counters(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events_eql(query=SEQUENCE_QUERY, since_minutes=60)

    assert exc.value.status_code == 504
    assert "timed out" in str(exc.value.detail)
    assert ("hunt_query_error_total", {"dialect": "eql", "reason": "timeout"}) in counters


def test_eql_partial_async_result_is_deleted_and_surfaces_504(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeEs(response={"id": "async-1", "is_running": True, "is_partial": True, "hits": {}})
    _use_fake_es(monkeypatch, fake)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events_eql(query=SEQUENCE_QUERY, since_minutes=60)

    assert exc.value.status_code == 504
    assert fake.delete_calls == [{"id": "async-1"}]


def test_eql_transport_timeout_surfaces_504(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeEs(error=TimeoutError("Connection timeout caused by read timeout"))
    _use_fake_es(monkeypatch, fake)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events_eql(query=SEQUENCE_QUERY, since_minutes=60)

    assert exc.value.status_code == 504


def test_eql_unavailable_elasticsearch_surfaces_503(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_es_client_or_none", lambda: None)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events_eql(query=SEQUENCE_QUERY, since_minutes=60)

    assert exc.value.status_code == 503


def test_eql_rejected_when_search_backend_is_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "postgres")

    with pytest.raises(HTTPException) as exc:
        service.hunt_events_eql(query=SEQUENCE_QUERY, since_minutes=60)

    assert exc.value.status_code == 503


def test_eql_open_circuit_rejects_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeEs(response=_sequence_response())
    _use_fake_es(monkeypatch, fake)
    monkeypatch.setattr(service._hunt_breaker, "allow", lambda _backend: False)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events_eql(query=SEQUENCE_QUERY, since_minutes=60)

    assert exc.value.status_code == 503
    assert "circuit" in str(exc.value.detail)
    assert fake.search_calls == []


def test_normalize_eql_query_rejects_blank_and_oversized_input() -> None:
    with pytest.raises(HuntQueryError) as blank:
        normalize_eql_query("   ")
    assert blank.value.reason == "syntax"

    with pytest.raises(HuntQueryError) as oversized:
        normalize_eql_query("x" * 3000)
    assert oversized.value.reason == "too_long"


def test_translate_es_query_error_maps_unavailable_backend() -> None:
    error = translate_es_query_error(ConnectionError("refused"), dialect="eql")
    assert error.reason == "es_unavailable"


def test_eql_endpoint_passes_request_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake(**kwargs: Any) -> EqlHuntResponse:
        captured.update(kwargs)
        return EqlHuntResponse(
            generated_at=datetime.now(timezone.utc),
            total=0,
            sequences=[],
            meta=QueryProvenanceMeta(source="elasticsearch"),
        )

    monkeypatch.setattr(events_api.events_service, "hunt_events_eql", _fake)

    payload = EqlHuntRequest(query=SEQUENCE_QUERY, since_minutes=120, agent_id="agent-a", size=5)
    events_api.hunt_events_eql_endpoint(payload)

    assert captured["query"] == SEQUENCE_QUERY
    assert captured["since_minutes"] == 120
    assert captured["agent_id"] == "agent-a"
    assert captured["size"] == 5
