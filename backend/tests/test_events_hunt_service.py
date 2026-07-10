from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi import HTTPException

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite:///./test.db")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.features.events import service
from app.features.events.domain import queries as event_queries
from app.features.events.domain.routing import BackendCircuitBreaker, QuerySignals
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


def test_route_decision_prefers_elasticsearch_for_search() -> None:
    decision = service._route_decision(QuerySignals(has_search=True, window_minutes=60))
    assert decision.chain == ("elasticsearch", "postgres", "clickhouse")
    assert decision.reason == "fulltext"


def test_route_decision_prefers_clickhouse_for_wide_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service.settings, "SEAGULL_EVENTS_HUNT_CLICKHOUSE_MINUTES", 90, raising=False)
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    decision = service._route_decision(QuerySignals(window_minutes=120))
    assert decision.chain == ("clickhouse", "postgres", "elasticsearch")
    assert decision.reason == "wide_window"


def test_route_decision_prefers_postgres_for_narrow_indexed_filters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    decision = service._route_decision(QuerySignals(filter_clauses=3, window_minutes=30))
    assert decision.chain == ("postgres", "clickhouse", "elasticsearch")
    assert decision.reason == "default"


def test_hunt_events_falls_back_to_postgres_when_es_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(501)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(service, "_pg_hunt_query", lambda *_args, **_kwargs: ([sample], None, False))

    out = service.hunt_events(
        db=object(),
        page_size=50,
        cursor=None,
        agent_id="agent-a",
        event_type="ssh_auth",
        since_minutes=120,
        search="failed_password",
    )

    assert out.items and out.items[0].id == 501
    assert out.meta.source == "postgres"
    assert out.meta.fallback_chain == ["elasticsearch", "postgres"]
    assert out.meta.degraded_reason == "elasticsearch_fallback:elasticsearch_unavailable"
    assert out.meta.query_window_start is not None
    assert out.meta.query_window_end is not None


def test_hunt_events_uses_elasticsearch_for_search_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(777)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_hunt_query", lambda **_kwargs: ([sample], None, False))
    monkeypatch.setattr(service, "_pg_has_newer_event", lambda *_args, **_kwargs: False)

    out = service.hunt_events(
        db=object(),
        page_size=25,
        cursor=None,
        agent_id=None,
        event_type=None,
        since_minutes=60,
        search="203.0.113.8",
    )

    assert out.meta.source == "elasticsearch"
    assert out.meta.fallback_chain == ["elasticsearch"]
    assert out.meta.degraded_reason is None


def test_hunt_events_passes_search_timeout_to_elasticsearch(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(778)
    seen: dict[str, Any] = {}

    def fake_es_hunt_query(**kwargs: Any) -> tuple[list[NetEventDB], None, bool]:
        seen.update(kwargs)
        return [sample], None, False

    monkeypatch.setattr(service.settings, "SEAGULL_ROUTE_ES_SEARCH_TIMEOUT_SECONDS", 1.25, raising=False)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_hunt_query", fake_es_hunt_query)
    monkeypatch.setattr(service, "_pg_has_newer_event", lambda *_args, **_kwargs: False)

    out = service.hunt_events(db=object(), page_size=10, since_minutes=60, search="needle")

    assert out.meta.source == "elasticsearch"
    assert seen["timeout_seconds"] == 1.25


def test_hunt_events_falls_back_from_clickhouse_to_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(902)
    monkeypatch.setattr(service.settings, "SEAGULL_EVENTS_HUNT_CLICKHOUSE_MINUTES", 30, raising=False)
    monkeypatch.setattr(service, "_ch_client_or_none", lambda: None)
    monkeypatch.setattr(service, "_pg_hunt_query", lambda *_args, **_kwargs: ([sample], None, False))

    out = service.hunt_events(
        db=object(),
        page_size=30,
        cursor=None,
        agent_id=None,
        event_type=None,
        since_minutes=120,
    )

    assert out.meta.source == "postgres"
    assert out.meta.fallback_chain == ["clickhouse", "postgres"]
    assert out.meta.degraded_reason == "clickhouse_fallback:clickhouse_unavailable"


def test_hunt_events_falls_back_to_elasticsearch_after_pg_and_clickhouse_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(903)
    monkeypatch.setattr(service.settings, "SEAGULL_EVENTS_HUNT_CLICKHOUSE_MINUTES", 30, raising=False)
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_ch_client_or_none", lambda: object())
    monkeypatch.setattr(
        service,
        "_ch_hunt_query",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("ch_down")),
    )
    monkeypatch.setattr(
        service,
        "_pg_hunt_query",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("pg_down")),
    )
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_hunt_query", lambda **_kwargs: ([sample], None, False))
    monkeypatch.setattr(service, "_pg_has_newer_event", lambda *_args, **_kwargs: False)

    out = service.hunt_events(
        db=object(),
        page_size=30,
        cursor=None,
        agent_id=None,
        event_type=None,
        since_minutes=120,
    )

    assert out.meta.source == "elasticsearch"
    assert out.meta.fallback_chain == ["clickhouse", "postgres", "elasticsearch"]
    assert out.meta.degraded_reason is not None


def test_hunt_events_skips_backend_with_open_circuit(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(910)
    breaker = BackendCircuitBreaker(failure_threshold=1, window_seconds=30.0, cooldown_seconds=60.0)
    breaker.record_failure("elasticsearch")
    monkeypatch.setattr(service, "_hunt_breaker", breaker)
    monkeypatch.setattr(service, "_pg_hunt_query", lambda *_args, **_kwargs: ([sample], None, False))
    counters = _capture_counters(monkeypatch)

    out = service.hunt_events(db=object(), page_size=10, since_minutes=60, search="needle")

    assert out.meta.source == "postgres"
    assert "elasticsearch" not in out.meta.fallback_chain
    assert out.meta.degraded_reason == "elasticsearch_skipped:circuit_open"
    assert ("hunt_backend_chosen_total", {"backend": "postgres", "reason": "fallback"}) in counters
    assert (
        "hunt_backend_fallback_total",
        {"from_backend": "elasticsearch", "to_backend": "postgres", "reason": "circuit_open"},
    ) in counters


def test_hunt_events_returns_clear_error_when_all_circuits_open(monkeypatch: pytest.MonkeyPatch) -> None:
    breaker = BackendCircuitBreaker(failure_threshold=1, window_seconds=30.0, cooldown_seconds=60.0)
    for backend in ("elasticsearch", "clickhouse", "postgres"):
        breaker.record_failure(backend)
    monkeypatch.setattr(service, "_hunt_breaker", breaker)

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(db=object(), page_size=10, since_minutes=60, search="needle")

    assert exc.value.status_code == 503
    assert "circuit" in str(exc.value.detail)


def test_hunt_events_repeated_failures_open_circuit(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(911)
    breaker = BackendCircuitBreaker(failure_threshold=2, window_seconds=30.0, cooldown_seconds=60.0)
    monkeypatch.setattr(service, "_hunt_breaker", breaker)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(
        service,
        "_es_hunt_query",
        lambda **_kwargs: (_ for _ in ()).throw(TimeoutError("es read timed out")),
    )
    monkeypatch.setattr(service, "_pg_hunt_query", lambda *_args, **_kwargs: ([sample], None, False))
    counters = _capture_counters(monkeypatch)

    for _ in range(2):
        out = service.hunt_events(db=object(), page_size=10, since_minutes=60, search="needle")
        assert out.meta.source == "postgres"

    assert breaker.state("elasticsearch").state == "open"
    assert ("hunt_backend_circuit_open_total", {"backend": "elasticsearch"}) in counters

    out = service.hunt_events(db=object(), page_size=10, since_minutes=60, search="needle")
    assert out.meta.fallback_chain == ["postgres"]
    assert out.meta.degraded_reason == "elasticsearch_skipped:circuit_open"


def test_hunt_events_stale_es_falls_back_without_penalizing_breaker(monkeypatch: pytest.MonkeyPatch) -> None:
    es_sample = _evt(920)
    pg_sample = _evt(921)
    monkeypatch.setattr(service.settings, "SEAGULL_ROUTE_TRUST_ES", False, raising=False)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_hunt_query", lambda **_kwargs: ([es_sample], None, False))
    monkeypatch.setattr(service, "_pg_has_newer_event", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(service, "_pg_hunt_query", lambda *_args, **_kwargs: ([pg_sample], None, False))

    out = service.hunt_events(db=object(), page_size=10, since_minutes=60, search="needle")

    assert out.meta.source == "postgres"
    assert out.meta.degraded_reason == "elasticsearch_fallback:elasticsearch_stale"
    assert service._hunt_breaker.state("elasticsearch").state == "closed"


def test_hunt_events_trust_es_flag_skips_pg_freshness_check(monkeypatch: pytest.MonkeyPatch) -> None:
    es_sample = _evt(930)
    freshness_calls: list[Any] = []

    def fake_pg_has_newer_event(*args: Any, **kwargs: Any) -> bool:
        freshness_calls.append(kwargs)
        return True

    monkeypatch.setattr(service.settings, "SEAGULL_ROUTE_TRUST_ES", True, raising=False)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_hunt_query", lambda **_kwargs: ([es_sample], None, False))
    monkeypatch.setattr(service, "_pg_has_newer_event", fake_pg_has_newer_event)

    out = service.hunt_events(db=object(), page_size=10, since_minutes=60, search="needle")

    assert out.meta.source == "elasticsearch"
    assert out.meta.degraded_reason is None
    assert freshness_calls == []


def test_hunt_events_pg_failure_rolls_back_session(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(940)

    class _FakeSession:
        def __init__(self) -> None:
            self.rollbacks = 0

        def rollback(self) -> None:
            self.rollbacks += 1

    db = _FakeSession()
    monkeypatch.setattr(
        service,
        "_pg_hunt_query",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("canceling statement due to statement timeout")),
    )
    monkeypatch.setattr(service, "_ch_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_ch_hunt_query", lambda **_kwargs: ([sample], None, False))
    monkeypatch.setattr(service, "_pg_has_newer_event", lambda *_args, **_kwargs: False)

    out = service.hunt_events(db=db, page_size=10, since_minutes=30)

    assert out.meta.source == "clickhouse"
    assert out.meta.degraded_reason == "postgres_fallback:timeout"
    assert db.rollbacks == 1


def test_hunt_events_rejects_invalid_time_range() -> None:
    with pytest.raises(HTTPException) as exc:
        service.hunt_events(
            db=object(),
            page_size=10,
            start_ts_iso="2026-04-06T10:00:00Z",
            end_ts_iso="2026-04-06T09:00:00Z",
        )
    assert exc.value.status_code == 422


def test_hunt_events_rejects_blank_search() -> None:
    with pytest.raises(HTTPException) as exc:
        service.hunt_events(
            db=object(),
            page_size=10,
            search="   ",
        )
    assert exc.value.status_code == 422


def test_hunt_events_returns_503_when_all_candidates_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(service, "_ch_client_or_none", lambda: None)
    monkeypatch.setattr(
        service,
        "_pg_hunt_query",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("pg_down")),
    )

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(
            db=object(),
            page_size=10,
            search="needle",
            since_minutes=30,
        )
    assert exc.value.status_code == 503


def test_explain_hunt_route_reports_decision_without_executing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service.settings, "SEAGULL_ROUTE_ES_SEARCH_TIMEOUT_SECONDS", 2.0, raising=False)

    out = service.explain_hunt_route(search="ssh brute *", since_minutes=60, agent_id="agent-a")

    assert out.decision_backend == "elasticsearch"
    assert out.decision_reason == "fulltext"
    assert out.chain == ["elasticsearch", "postgres", "clickhouse"]
    assert out.attempt_plan == out.chain
    assert out.signals.has_search is True
    assert out.signals.has_wildcard is True
    assert out.timeouts_seconds["elasticsearch"] == 2.0
    assert out.circuit["elasticsearch"].state == "closed"
    assert out.trust_es is False


def test_explain_hunt_route_reflects_open_circuit(monkeypatch: pytest.MonkeyPatch) -> None:
    breaker = BackendCircuitBreaker(failure_threshold=1, window_seconds=30.0, cooldown_seconds=60.0)
    breaker.record_failure("elasticsearch")
    monkeypatch.setattr(service, "_hunt_breaker", breaker)

    out = service.explain_hunt_route(search="needle", since_minutes=60)

    assert out.chain[0] == "elasticsearch"
    assert out.attempt_plan[0] == "postgres"
    assert "elasticsearch" not in out.attempt_plan
    assert out.circuit["elasticsearch"].state == "open"


def test_explain_hunt_route_aggregate_simulation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")

    out = service.explain_hunt_route(since_minutes=30, aggregate=True)

    assert out.decision_backend == "clickhouse"
    assert out.decision_reason == "aggregate"
    assert out.timeouts_seconds["clickhouse"] == pytest.approx(3.0)


def test_hunt_backend_timeouts_by_query_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service.settings, "SEAGULL_EVENTS_HUNT_CLICKHOUSE_MINUTES", 240, raising=False)
    search_signals = QuerySignals(has_search=True, window_minutes=60)
    term_signals = QuerySignals(window_minutes=60)
    aggregate_signals = QuerySignals(aggregate=True)
    wide_scan_signals = QuerySignals(window_minutes=1440)

    assert service._hunt_backend_timeout_seconds("elasticsearch", search_signals) == pytest.approx(2.0)
    assert service._hunt_backend_timeout_seconds("elasticsearch", term_signals) == pytest.approx(0.5)
    assert service._hunt_backend_timeout_seconds("clickhouse", aggregate_signals) == pytest.approx(3.0)
    assert service._hunt_backend_timeout_seconds("clickhouse", wide_scan_signals) == pytest.approx(3.0)
    assert service._hunt_backend_timeout_seconds("clickhouse", term_signals) == pytest.approx(0.5)
    assert service._hunt_backend_timeout_seconds("postgres", search_signals) == pytest.approx(0.5)


def test_ch_timeout_settings_supports_fractional_seconds() -> None:
    assert event_queries._ch_timeout_settings(0.5) == {"max_execution_time": 0.5}
    assert event_queries._ch_timeout_settings(None) == {}
    assert event_queries._ch_timeout_settings(0) == {}


def test_es_with_request_timeout_uses_options_when_available() -> None:
    class _FakeEs:
        def __init__(self) -> None:
            self.request_timeout: float | None = None

        def options(self, *, request_timeout: float) -> "_FakeEs":
            clone = _FakeEs()
            clone.request_timeout = request_timeout
            return clone

    scoped = event_queries._es_with_request_timeout(_FakeEs(), 2.0)
    assert scoped.request_timeout == 2.0

    bare = object()
    assert event_queries._es_with_request_timeout(bare, 2.0) is bare


def test_pg_statement_timeout_is_noop_outside_postgres() -> None:
    engine = create_engine("sqlite://")
    session_factory = sessionmaker(bind=engine)
    with session_factory() as session:
        event_queries._pg_apply_statement_timeout(session, 0.5)
