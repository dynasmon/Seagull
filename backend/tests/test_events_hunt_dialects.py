from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import HTTPException

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite:///./test.db")

from app.features.events import service
from app.features.events.domain.hunt_dialects import HuntQueryError, resolve_hunt_dialect
from app.features.events.domain.routing import QuerySignals, decide_backend_chain
from app.features.events.schemas import NetEventDB


@pytest.fixture(autouse=True)
def _reset_hunt_breaker() -> None:
    service._hunt_breaker.reset()


def _evt(event_id: int = 101) -> NetEventDB:
    return NetEventDB(
        id=int(event_id),
        agent_id="agent-a",
        event_type="ssh_auth",
        schema_version=1,
        timestamp=datetime.now(timezone.utc),
        src_ip="203.0.113.8",
        dst_ip="192.0.2.10",
        src_port=54000,
        dst_port=22,
        proto="tcp",
        bytes=100,
        extra={"action": "failed_password"},
    )


def _capture_counters(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        service,
        "incr_counter",
        lambda name, value=1.0, **labels: calls.append((name, labels)),
    )
    return calls


def test_resolve_dialect_defaults_to_simple() -> None:
    assert resolve_hunt_dialect(search=None, search_dialect=None) == ("simple", None)
    assert resolve_hunt_dialect(search="a:b", search_dialect=None) == ("simple", "a:b")


def test_resolve_dialect_honors_prefixes_when_parameter_is_absent() -> None:
    assert resolve_hunt_dialect(search="kql: src_ip:203.0.113.9", search_dialect=None) == ("kql", "src_ip:203.0.113.9")
    assert resolve_hunt_dialect(search="EQL: sequence", search_dialect=None) == ("eql", "sequence")
    assert resolve_hunt_dialect(search="simple: needle", search_dialect=None) == ("simple", "needle")


def test_resolve_dialect_parameter_wins_over_prefix() -> None:
    dialect, text = resolve_hunt_dialect(search="kql: proto:tcp", search_dialect="simple")
    assert dialect == "simple"
    assert text == "kql: proto:tcp"

    dialect, text = resolve_hunt_dialect(search="kql: proto:tcp", search_dialect="kql")
    assert dialect == "kql"
    assert text == "proto:tcp"


def test_resolve_dialect_rejects_unknown_values() -> None:
    with pytest.raises(HuntQueryError) as exc:
        resolve_hunt_dialect(search="x", search_dialect="lucene")
    assert exc.value.reason == "unknown_dialect"


def test_route_decision_forces_elasticsearch_for_kql() -> None:
    decision = decide_backend_chain(
        QuerySignals(has_search=True, window_minutes=60, dialect="kql"),
        es_enabled=True,
        wide_window_minutes=240,
        many_clauses_threshold=5,
    )
    assert decision.chain == ("elasticsearch",)
    assert decision.reason == "kql"


def test_hunt_events_kql_executes_against_elasticsearch(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(601)
    seen: dict[str, Any] = {}

    def fake_kql_query(**kwargs: Any) -> tuple[list[NetEventDB], None, bool]:
        seen.update(kwargs)
        return [sample], None, False

    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_kql_hunt_query", fake_kql_query)
    counters = _capture_counters(monkeypatch)

    out = service.hunt_events(
        db=object(),
        page_size=25,
        search="ssh_action:failed_password and src_ip:203.0.113.0/24",
        search_dialect="kql",
        since_minutes=60,
    )

    assert out.meta.source == "elasticsearch"
    assert out.meta.fallback_chain == ["elasticsearch"]
    assert out.items[0].id == 601
    assert seen["timeout_seconds"] == pytest.approx(3.0)
    assert seen["terminate_after"] == 10000
    assert {"term": {"ssh_action": "failed_password"}} in seen["compiled_query"]["bool"]["filter"]
    assert ("hunt_query_dialect_total", {"dialect": "kql"}) in counters


def test_hunt_events_kql_prefix_activates_dialect(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(602)
    seen: dict[str, Any] = {}

    def fake_kql_query(**kwargs: Any) -> tuple[list[NetEventDB], None, bool]:
        seen.update(kwargs)
        return [sample], None, False

    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_kql_hunt_query", fake_kql_query)

    out = service.hunt_events(db=object(), page_size=10, search="kql: agent_id:edge-1", since_minutes=30)

    assert out.meta.source == "elasticsearch"
    assert seen["compiled_query"] == {"term": {"agent_id": "edge-1"}}


def test_hunt_events_kql_clamps_window_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_kql_hunt_query", lambda **_kwargs: ([_evt(603)], None, False))

    out = service.hunt_events(db=object(), page_size=10, search="proto:tcp", search_dialect="kql")

    assert out.meta.query_window_start is not None
    window = out.meta.query_window_end - out.meta.query_window_start
    assert timedelta(minutes=1439) <= window <= timedelta(minutes=1441)


def test_hunt_events_kql_respects_query_timestamp_range(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_kql_hunt_query", lambda **_kwargs: ([_evt(604)], None, False))

    out = service.hunt_events(
        db=object(),
        page_size=10,
        search='proto:tcp and timestamp >= "2026-07-01T00:00:00Z"',
        search_dialect="kql",
    )

    assert out.meta.query_window_start is None


def test_hunt_events_kql_syntax_error_returns_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    counters = _capture_counters(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(db=object(), page_size=10, search="ssh_action:", search_dialect="kql")

    assert exc.value.status_code == 400
    assert "syntax error" in str(exc.value.detail)
    assert ("hunt_query_error_total", {"dialect": "kql", "reason": "syntax"}) in counters


def test_hunt_events_kql_unknown_field_returns_400_with_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(db=object(), page_size=10, search="sshaction:x", search_dialect="kql")

    assert exc.value.status_code == 400
    assert "Unknown field 'sshaction'" in str(exc.value.detail)
    assert "agent_id" in str(exc.value.detail)


def test_hunt_events_kql_leading_wildcard_returns_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    counters = _capture_counters(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(db=object(), page_size=10, search="dns_qname:*evil*", search_dialect="kql")

    assert exc.value.status_code == 400
    assert ("hunt_query_error_total", {"dialect": "kql", "reason": "leading_wildcard"}) in counters


def test_hunt_events_eql_dialect_points_to_dedicated_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    counters = _capture_counters(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(db=object(), page_size=10, search="sequence", search_dialect="eql")

    assert exc.value.status_code == 400
    assert "/api/events/hunt/eql" in str(exc.value.detail)
    assert ("hunt_query_error_total", {"dialect": "eql", "reason": "eql_endpoint"}) in counters


def test_hunt_events_kql_does_not_fall_back_when_es_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    pg_calls: list[Any] = []
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(
        service,
        "_pg_hunt_query",
        lambda *args, **kwargs: pg_calls.append(kwargs) or ([_evt(605)], None, False),
    )

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(db=object(), page_size=10, search="proto:tcp", search_dialect="kql")

    assert exc.value.status_code == 503
    assert "KQL" in str(exc.value.detail)
    assert pg_calls == []


def test_hunt_events_kql_timeout_surfaces_504(monkeypatch: pytest.MonkeyPatch) -> None:
    pg_calls: list[Any] = []
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(
        service,
        "_es_kql_hunt_query",
        lambda **_kwargs: (_ for _ in ()).throw(
            HuntQueryError("KQL query timed out against Elasticsearch", reason="timeout")
        ),
    )
    monkeypatch.setattr(
        service,
        "_pg_hunt_query",
        lambda *args, **kwargs: pg_calls.append(kwargs) or ([_evt(606)], None, False),
    )
    counters = _capture_counters(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(db=object(), page_size=10, search="proto:tcp", search_dialect="kql")

    assert exc.value.status_code == 504
    assert "timed out" in str(exc.value.detail)
    assert pg_calls == []
    assert ("hunt_query_error_total", {"dialect": "kql", "reason": "timeout"}) in counters


def test_hunt_events_kql_rejected_query_does_not_penalize_breaker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(
        service,
        "_es_kql_hunt_query",
        lambda **_kwargs: (_ for _ in ()).throw(
            HuntQueryError("Elasticsearch rejected the KQL query: bad request", reason="rejected")
        ),
    )

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(db=object(), page_size=10, search="proto:tcp", search_dialect="kql")

    assert exc.value.status_code == 400
    assert service._hunt_breaker.state("elasticsearch").state == "closed"


def test_hunt_events_kql_requires_search_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(db=object(), page_size=10, search=None, search_dialect="kql")

    assert exc.value.status_code == 400


def test_hunt_events_kql_rejected_when_search_backend_is_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "postgres")

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(db=object(), page_size=10, search="proto:tcp", search_dialect="kql")

    assert exc.value.status_code == 503
    assert "Elasticsearch" in str(exc.value.detail)


def test_hunt_events_kql_clause_limit_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service.settings, "SEAGULL_HUNT_MAX_QUERY_CLAUSES", 2, raising=False)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(
            db=object(),
            page_size=10,
            search="proto:tcp and dst_port:22 and agent_id:edge-1",
            search_dialect="kql",
        )

    assert exc.value.status_code == 400
    assert "maximum of 2 clauses" in str(exc.value.detail)


def test_hunt_events_simple_dialect_keeps_fallback_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(607)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(service, "_pg_hunt_query", lambda *_args, **_kwargs: ([sample], None, False))

    out = service.hunt_events(
        db=object(),
        page_size=10,
        search="failed_password",
        search_dialect="simple",
        since_minutes=60,
    )

    assert out.meta.source == "postgres"
    assert out.meta.fallback_chain == ["elasticsearch", "postgres"]
    assert out.meta.degraded_reason == "elasticsearch_fallback:elasticsearch_unavailable"


def test_explain_hunt_route_reports_kql_dialect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")

    out = service.explain_hunt_route(search="ssh_action:accepted and dst_port >= 30000", search_dialect="kql")

    assert out.decision_backend == "elasticsearch"
    assert out.decision_reason == "kql"
    assert out.chain == ["elasticsearch"]
    assert out.signals.dialect == "kql"
    assert out.signals.has_search is True
    assert out.timeouts_seconds["elasticsearch"] == pytest.approx(3.0)


def test_explain_hunt_route_rejects_invalid_kql(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")

    with pytest.raises(HTTPException) as exc:
        service.explain_hunt_route(search="ssh_action:", search_dialect="kql")

    assert exc.value.status_code == 400


def test_hunt_field_catalog_exposes_mapping_and_runtime_fields() -> None:
    out = service.hunt_field_catalog()

    fields = {spec.name: spec.type for spec in out.fields}
    assert fields["agent_id"] == "keyword"
    assert fields["timestamp"] == "date"
    assert fields["dst_port"] == "integer"
    assert fields["dst_port_class"] == "keyword"
    assert fields["extra.*"] == "flattened"
