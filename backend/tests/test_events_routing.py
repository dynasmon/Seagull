from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite:///./test.db")

from app.features.events.domain.routing import (
    BackendCircuitBreaker,
    QuerySignals,
    RouteDecision,
    classify_backend_failure,
    decide_backend_chain,
    failure_counts_toward_breaker,
)


class _FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = float(now)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


def _decide(
    signals: QuerySignals,
    *,
    es_enabled: bool = True,
    wide_window_minutes: int = 240,
    many_clauses_threshold: int = 5,
) -> RouteDecision:
    return decide_backend_chain(
        signals,
        es_enabled=es_enabled,
        wide_window_minutes=wide_window_minutes,
        many_clauses_threshold=many_clauses_threshold,
    )


def _breaker(threshold: int = 3, window: float = 10.0, cooldown: float = 5.0) -> tuple[BackendCircuitBreaker, _FakeClock]:
    clock = _FakeClock()
    breaker = BackendCircuitBreaker(
        failure_threshold=threshold,
        window_seconds=window,
        cooldown_seconds=cooldown,
        clock=clock,
    )
    return breaker, clock


def test_decide_fulltext_search_puts_elasticsearch_first() -> None:
    decision = _decide(QuerySignals(has_search=True, window_minutes=60))
    assert decision.chain == ("elasticsearch", "postgres", "clickhouse")
    assert decision.reason == "fulltext"


def test_decide_fulltext_search_on_wide_window_falls_back_to_clickhouse_before_postgres() -> None:
    decision = _decide(QuerySignals(has_search=True, window_minutes=1440))
    assert decision.chain == ("elasticsearch", "clickhouse", "postgres")
    assert decision.reason == "fulltext"


def test_decide_wildcard_search_puts_elasticsearch_first() -> None:
    decision = _decide(QuerySignals(has_wildcard=True, window_minutes=30))
    assert decision.chain[0] == "elasticsearch"
    assert decision.reason == "fulltext"


def test_decide_many_filter_clauses_puts_elasticsearch_first() -> None:
    decision = _decide(QuerySignals(filter_clauses=5, window_minutes=30))
    assert decision.chain[0] == "elasticsearch"
    assert decision.reason == "filters"


def test_decide_aggregate_puts_clickhouse_first() -> None:
    decision = _decide(QuerySignals(aggregate=True, window_minutes=30))
    assert decision.chain == ("clickhouse", "postgres", "elasticsearch")
    assert decision.reason == "aggregate"


def test_decide_wide_window_without_search_puts_clickhouse_first() -> None:
    decision = _decide(QuerySignals(window_minutes=720))
    assert decision.chain == ("clickhouse", "postgres", "elasticsearch")
    assert decision.reason == "wide_window"


def test_decide_narrow_window_with_indexed_equality_filters_puts_postgres_first() -> None:
    decision = _decide(QuerySignals(filter_clauses=3, window_minutes=30))
    assert decision.chain == ("postgres", "clickhouse", "elasticsearch")
    assert decision.reason == "default"


def test_decide_transactional_join_puts_postgres_first_even_with_search() -> None:
    decision = _decide(QuerySignals(has_search=True, transactional_join=True, window_minutes=1440))
    assert decision.chain == ("postgres", "clickhouse", "elasticsearch")
    assert decision.reason == "transactional"


def test_decide_search_beats_aggregate_and_wide_window() -> None:
    decision = _decide(QuerySignals(has_search=True, aggregate=True, window_minutes=1440))
    assert decision.chain[0] == "elasticsearch"
    assert decision.reason == "fulltext"


def test_decide_removes_elasticsearch_when_disabled() -> None:
    decision = _decide(QuerySignals(has_search=True, window_minutes=1440), es_enabled=False)
    assert decision.chain == ("clickhouse", "postgres")
    assert "elasticsearch" not in decision.chain


def test_decide_respects_wide_window_threshold_floor() -> None:
    narrow = _decide(QuerySignals(window_minutes=10), wide_window_minutes=1)
    assert narrow.chain[0] == "postgres"
    wide = _decide(QuerySignals(window_minutes=20), wide_window_minutes=1)
    assert wide.chain[0] == "clickhouse"


def test_decide_every_chain_keeps_all_enabled_backends() -> None:
    for signals in (
        QuerySignals(has_search=True, window_minutes=60),
        QuerySignals(aggregate=True),
        QuerySignals(window_minutes=100000),
        QuerySignals(),
    ):
        decision = _decide(signals)
        assert sorted(decision.chain) == ["clickhouse", "elasticsearch", "postgres"]


def test_breaker_stays_closed_below_threshold() -> None:
    breaker, _clock = _breaker(threshold=3)
    assert breaker.record_failure("elasticsearch") is False
    assert breaker.record_failure("elasticsearch") is False
    assert breaker.allow("elasticsearch") is True
    assert breaker.state("elasticsearch").state == "closed"


def test_breaker_opens_at_threshold_and_blocks() -> None:
    breaker, _clock = _breaker(threshold=3, cooldown=5.0)
    breaker.record_failure("elasticsearch")
    breaker.record_failure("elasticsearch")
    assert breaker.record_failure("elasticsearch") is True
    assert breaker.allow("elasticsearch") is False
    state = breaker.state("elasticsearch")
    assert state.state == "open"
    assert 0.0 < state.open_remaining_seconds <= 5.0


def test_breaker_failures_decay_outside_window() -> None:
    breaker, clock = _breaker(threshold=3, window=10.0)
    breaker.record_failure("clickhouse")
    breaker.record_failure("clickhouse")
    clock.advance(11.0)
    assert breaker.record_failure("clickhouse") is False
    assert breaker.allow("clickhouse") is True


def test_breaker_half_open_allows_single_probe() -> None:
    breaker, clock = _breaker(threshold=1, cooldown=5.0)
    assert breaker.record_failure("elasticsearch") is True
    clock.advance(5.1)
    assert breaker.state("elasticsearch").state == "half_open"
    assert breaker.allow("elasticsearch") is True
    assert breaker.allow("elasticsearch") is False


def test_breaker_probe_success_closes_circuit() -> None:
    breaker, clock = _breaker(threshold=1, cooldown=5.0)
    breaker.record_failure("elasticsearch")
    clock.advance(5.1)
    assert breaker.allow("elasticsearch") is True
    breaker.record_success("elasticsearch")
    assert breaker.state("elasticsearch").state == "closed"
    assert breaker.allow("elasticsearch") is True
    assert breaker.allow("elasticsearch") is True


def test_breaker_probe_failure_reopens_circuit() -> None:
    breaker, clock = _breaker(threshold=1, cooldown=5.0)
    breaker.record_failure("elasticsearch")
    clock.advance(5.1)
    assert breaker.allow("elasticsearch") is True
    assert breaker.record_failure("elasticsearch") is True
    assert breaker.allow("elasticsearch") is False
    assert breaker.state("elasticsearch").state == "open"


def test_breaker_isolates_backends() -> None:
    breaker, _clock = _breaker(threshold=1)
    breaker.record_failure("elasticsearch")
    assert breaker.allow("elasticsearch") is False
    assert breaker.allow("clickhouse") is True
    assert breaker.allow("postgres") is True


def test_breaker_success_resets_failure_history() -> None:
    breaker, _clock = _breaker(threshold=2)
    breaker.record_failure("postgres")
    breaker.record_success("postgres")
    assert breaker.record_failure("postgres") is False
    assert breaker.allow("postgres") is True


def test_classify_timeout_exceptions() -> None:
    assert classify_backend_failure(TimeoutError("read timed out")) == "timeout"
    assert classify_backend_failure(RuntimeError("Code: 159. DB::Exception: TIMEOUT_EXCEEDED")) == "timeout"
    assert (
        classify_backend_failure(RuntimeError("canceling statement due to statement timeout"))
        == "timeout"
    )


def test_classify_lookup_error_keeps_reason() -> None:
    assert classify_backend_failure(LookupError("elasticsearch_stale")) == "elasticsearch_stale"
    assert classify_backend_failure(LookupError("clickhouse_unavailable")) == "clickhouse_unavailable"
    assert classify_backend_failure(LookupError("")) == "lookup_error"


def test_classify_generic_exception_uses_type_name() -> None:
    assert classify_backend_failure(ValueError("boom")) == "ValueError"


def test_staleness_does_not_count_toward_breaker() -> None:
    assert failure_counts_toward_breaker("elasticsearch_stale") is False
    assert failure_counts_toward_breaker("clickhouse_stale") is False
    assert failure_counts_toward_breaker("timeout") is True
    assert failure_counts_toward_breaker("elasticsearch_unavailable") is True
    assert failure_counts_toward_breaker("RuntimeError") is True
