from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Set

import pytest

from app.workers.sinks import reconciler
from app.workers.sinks.config import ReconcilerConfig

MINUTE = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)


def _config(**overrides: Any) -> ReconcilerConfig:
    base = {
        "enabled": True,
        "clickhouse_enabled": True,
        "search_enabled": True,
        "interval_seconds": 300.0,
        "lookback_minutes": 60,
        "settle_seconds": 120,
        "repair_enabled": True,
        "repair_max_events": 100,
        "search_index_pattern": "seagull-events-*",
    }
    base.update(overrides)
    return ReconcilerConfig(**base)


class _EsStub:
    def __init__(self, responses: List[Dict[str, Any]]) -> None:
        self.responses = responses
        self.bodies: List[Dict[str, Any]] = []

    def search(self, *, index: str, body: Dict[str, Any], **_kwargs: Any) -> Dict[str, Any]:
        self.bodies.append(dict(body))
        return self.responses[min(len(self.bodies) - 1, len(self.responses) - 1)]


@pytest.fixture()
def repairs(monkeypatch) -> List[Dict[str, Any]]:
    captured: List[Dict[str, Any]] = []

    def _enqueue_repair(*, sink: str, event_ids) -> int:
        captured.append({"sink": sink, "event_ids": list(event_ids)})
        return len(event_ids)

    monkeypatch.setattr(reconciler, "enqueue_repair", _enqueue_repair)
    return captured


def test_window_ends_before_the_settle_horizon() -> None:
    cfg = _config(lookback_minutes=30, settle_seconds=120)
    window = reconciler.reconcile_window(cfg, now=datetime(2026, 8, 10, 12, 5, 30, tzinfo=timezone.utc))
    assert window.end == datetime(2026, 8, 10, 12, 3, tzinfo=timezone.utc)
    assert window.start == datetime(2026, 8, 10, 11, 33, tzinfo=timezone.utc)


def test_only_minutes_short_of_the_hot_store_are_drilled() -> None:
    expected = {MINUTE: 10, MINUTE + timedelta(minutes=1): 10, MINUTE + timedelta(minutes=2): 10}
    present = {MINUTE: 10, MINUTE + timedelta(minutes=1): 7, MINUTE + timedelta(minutes=2): 12}
    assert reconciler._diverging_minutes(expected, present) == [MINUTE + timedelta(minutes=1)]


def test_missing_events_are_counted_and_repaired(monkeypatch, repairs: List[Dict[str, Any]]) -> None:
    monkeypatch.setattr(reconciler, "postgres_event_ids", lambda _minute: {1, 2, 3, 4})

    divergence = reconciler.reconcile_sink(
        sink="clickhouse",
        expected={MINUTE: 4},
        present={MINUTE: 2},
        present_ids=lambda _minute: {1, 2},
        cfg=_config(),
    )

    assert divergence.expected == 4
    assert divergence.missing == 2
    assert divergence.repaired == 2
    assert divergence.ratio == 0.5
    assert repairs == [{"sink": "clickhouse", "event_ids": [3, 4]}]


def test_extra_documents_never_hide_a_missing_event(monkeypatch, repairs: List[Dict[str, Any]]) -> None:
    monkeypatch.setattr(reconciler, "postgres_event_ids", lambda _minute: {1, 2, 3})

    divergence = reconciler.reconcile_sink(
        sink="search",
        expected={MINUTE: 3},
        present={MINUTE: 2},
        present_ids=lambda _minute: {1, 2, 99},
        cfg=_config(),
    )

    assert divergence.missing == 1
    assert repairs == [{"sink": "search", "event_ids": [3]}]


def test_repair_budget_bounds_the_work(monkeypatch, repairs: List[Dict[str, Any]]) -> None:
    monkeypatch.setattr(reconciler, "postgres_event_ids", lambda _minute: set(range(1, 51)))

    divergence = reconciler.reconcile_sink(
        sink="clickhouse",
        expected={MINUTE: 50},
        present={MINUTE: 0},
        present_ids=lambda _minute: set(),
        cfg=_config(repair_max_events=10),
    )

    assert divergence.missing == 50
    assert divergence.repaired == 10
    assert repairs[0]["event_ids"] == list(range(1, 11))


def test_repair_can_be_reported_without_being_applied(monkeypatch, repairs: List[Dict[str, Any]]) -> None:
    monkeypatch.setattr(reconciler, "postgres_event_ids", lambda _minute: {1, 2, 3})

    divergence = reconciler.reconcile_sink(
        sink="clickhouse",
        expected={MINUTE: 3},
        present={MINUTE: 0},
        present_ids=lambda _minute: set(),
        cfg=_config(repair_enabled=False),
    )

    assert divergence.missing == 3
    assert divergence.repaired == 0
    assert repairs == []


def test_a_pass_reports_every_enabled_sink(monkeypatch, repairs: List[Dict[str, Any]]) -> None:
    monkeypatch.setattr(reconciler, "postgres_minute_counts", lambda _window: {MINUTE: 2})
    monkeypatch.setattr(reconciler, "postgres_event_ids", lambda _minute: {1, 2})
    monkeypatch.setattr(reconciler, "get_clickhouse_client", lambda: object())
    monkeypatch.setattr(reconciler, "clickhouse_minute_counts", lambda _client, _window: {MINUTE: 1})
    monkeypatch.setattr(reconciler, "clickhouse_event_ids", lambda _client, _minute: {1})
    monkeypatch.setattr(reconciler, "search_minute_counts", lambda _es, _pattern, _window: {MINUTE: 2})
    monkeypatch.setattr(reconciler, "search_event_ids", lambda _es, _pattern, _minute: {1, 2})

    pass_runner = reconciler.ProjectionReconciler(_config())
    pass_runner.search_client = lambda: object()

    results = pass_runner.run_once()

    assert [(result.sink, result.missing) for result in results] == [("clickhouse", 1), ("search", 0)]
    assert repairs == [{"sink": "clickhouse", "event_ids": [2]}]


def test_an_unreachable_projection_does_not_abort_the_other(monkeypatch, repairs: List[Dict[str, Any]]) -> None:
    monkeypatch.setattr(reconciler, "postgres_minute_counts", lambda _window: {MINUTE: 2})
    monkeypatch.setattr(reconciler, "postgres_event_ids", lambda _minute: {1, 2})
    monkeypatch.setattr(reconciler, "get_clickhouse_client", lambda: object())
    monkeypatch.setattr(reconciler, "clickhouse_minute_counts", lambda _client, _window: {MINUTE: 1})
    monkeypatch.setattr(reconciler, "clickhouse_event_ids", lambda _client, _minute: {1})

    def _unreachable(*_args: Any, **_kwargs: Any):
        raise ConnectionError("no route to elasticsearch")

    monkeypatch.setattr(reconciler, "search_minute_counts", _unreachable)

    pass_runner = reconciler.ProjectionReconciler(_config())
    pass_runner.search_client = lambda: object()

    results = pass_runner.run_once()

    assert [(result.sink, result.missing) for result in results] == [("clickhouse", 1)]
    assert repairs == [{"sink": "clickhouse", "event_ids": [2]}]


def test_an_unreachable_search_client_is_rebuilt_next_pass(monkeypatch) -> None:
    monkeypatch.setattr(reconciler, "postgres_minute_counts", lambda _window: {})

    def _unreachable(*_args: Any, **_kwargs: Any):
        raise ConnectionError("no route to elasticsearch")

    monkeypatch.setattr(reconciler, "search_minute_counts", _unreachable)

    pass_runner = reconciler.ProjectionReconciler(_config(clickhouse_enabled=False))
    pass_runner._search = object()

    assert pass_runner.run_once() == []
    assert pass_runner._search is None


def test_a_disabled_sink_is_not_reconciled(monkeypatch, repairs: List[Dict[str, Any]]) -> None:
    monkeypatch.setattr(reconciler, "postgres_minute_counts", lambda _window: {MINUTE: 2})
    monkeypatch.setattr(reconciler, "postgres_event_ids", lambda _minute: {1, 2})
    monkeypatch.setattr(reconciler, "search_minute_counts", lambda _es, _pattern, _window: {MINUTE: 0})
    monkeypatch.setattr(reconciler, "search_event_ids", lambda _es, _pattern, _minute: set())

    pass_runner = reconciler.ProjectionReconciler(_config(clickhouse_enabled=False))
    pass_runner.search_client = lambda: object()

    assert pass_runner.sinks() == ["search"]
    assert [result.sink for result in pass_runner.run_once()] == ["search"]


def test_search_counts_are_bucketed_per_minute() -> None:
    es = _EsStub(
        [
            {
                "aggregations": {
                    "per_minute": {
                        "buckets": [
                            {"key": int(MINUTE.timestamp() * 1000), "doc_count": 5},
                            {"key": int((MINUTE + timedelta(minutes=1)).timestamp() * 1000), "doc_count": 9},
                        ]
                    }
                }
            }
        ]
    )

    counts = reconciler.search_minute_counts(
        es, "seagull-events-*", reconciler.Window(start=MINUTE, end=MINUTE + timedelta(minutes=2))
    )

    assert counts == {MINUTE: 5, MINUTE + timedelta(minutes=1): 9}
    assert {"exists": {"field": "id"}} in es.bodies[0]["query"]["bool"]["filter"]


def test_search_ids_paginate_until_the_last_page() -> None:
    first_page = {"hits": {"hits": [{"_id": str(i), "sort": [i]} for i in range(reconciler._ID_PAGE_SIZE)]}}
    last_page = {"hits": {"hits": [{"_id": "999999", "sort": [999999]}]}}
    es = _EsStub([first_page, last_page])

    found: Set[int] = reconciler.search_event_ids(es, "seagull-events-*", MINUTE)

    assert len(found) == reconciler._ID_PAGE_SIZE + 1
    assert 999999 in found
    assert es.bodies[1]["search_after"] == [reconciler._ID_PAGE_SIZE - 1]
