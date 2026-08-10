from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest

from app.shared.outbox.store import REASON_MAX_ATTEMPTS, REASON_REJECTED, OutboxBatch
from app.workers.sinks.config import DispatcherConfig
from app.workers.sinks.delivery import DeliveryResult
from app.workers.sinks.dispatcher import OutboxDispatcher


def _config(**overrides: Any) -> DispatcherConfig:
    base = {
        "clickhouse_enabled": True,
        "warm_enabled": True,
        "search_enabled": True,
        "claim_batches": 4,
        "lease_seconds": 60.0,
        "max_attempts": 3,
        "retry_backoff_seconds": 1.0,
        "retry_backoff_max_seconds": 30.0,
        "idle_sleep_seconds": 0.01,
        "stats_interval_seconds": 3600.0,
        "dead_letter_retention_days": 7,
        "clickhouse_reconnect_seconds": 5.0,
        "warm_index_prefix": "seagull-events-warm",
        "warm_ilm_enabled": False,
        "warm_ilm_policy": "seagull-warm-delete-30d",
        "warm_ilm_delete_after_days": 30,
    }
    base.update(overrides)
    return DispatcherConfig(**base)


def _event(event_id: int) -> Dict[str, Any]:
    return {
        "agent_id": "agent-1",
        "event_type": "dns",
        "timestamp": datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc),
        "extra": {"app_proto": "dns"},
        "pg_event_id": event_id,
    }


class _FakeStore:
    def __init__(self) -> None:
        self.completed: List[int] = []
        self.rescheduled: List[Dict[str, Any]] = []
        self.dead: List[Dict[str, Any]] = []

    def complete(self, _conn: Any, *, batch_ids: List[int]) -> None:
        self.completed.extend(batch_ids)

    def reschedule(self, _conn: Any, *, batch_id: int, events: List[Dict[str, Any]], available_at, error: str) -> None:
        self.rescheduled.append(
            {"batch_id": batch_id, "events": list(events), "available_at": available_at, "error": error}
        )

    def dead_letter(self, _conn: Any, *, batch: OutboxBatch, events, reason: str, error: str, now=None) -> None:
        self.dead.append({"batch_id": batch.id, "events": list(events), "reason": reason, "error": error})


class _RecordingDelivery:
    def __init__(self, sink: str, result: DeliveryResult) -> None:
        self.sink = sink
        self.result = result
        self.calls: List[int] = []

    def deliver(self, events: List[Dict[str, Any]], *, batch_id: int) -> DeliveryResult:
        self.calls.append(batch_id)
        return self.result


@pytest.fixture()
def fake_store(monkeypatch) -> _FakeStore:
    from app.workers.sinks import dispatcher as dispatcher_module

    replacement = _FakeStore()
    monkeypatch.setattr(dispatcher_module.store, "complete", replacement.complete)
    monkeypatch.setattr(dispatcher_module.store, "reschedule", replacement.reschedule)
    monkeypatch.setattr(dispatcher_module.store, "dead_letter", replacement.dead_letter)

    class _NullConnection:
        def __enter__(self) -> "_NullConnection":
            return self

        def __exit__(self, *_exc: Any) -> bool:
            return False

    monkeypatch.setattr(dispatcher_module.engine, "begin", lambda: _NullConnection())
    return replacement


def _batch(*, batch_id: int = 1, attempts: int = 1, events: int = 2) -> OutboxBatch:
    return OutboxBatch(
        id=batch_id,
        sink="clickhouse",
        events=[_event(i) for i in range(events)],
        attempts=attempts,
        enqueued_at=datetime.now(timezone.utc) - timedelta(seconds=5),
    )


def test_fully_delivered_batch_is_removed(fake_store: _FakeStore) -> None:
    batch = _batch()
    delivery = _RecordingDelivery("clickhouse", DeliveryResult(delivered=2))
    dispatcher = OutboxDispatcher(delivery=delivery, cfg=_config())

    dispatcher._settle(batch, delivery.result)

    assert fake_store.completed == [batch.id]
    assert fake_store.rescheduled == []
    assert fake_store.dead == []


def test_transient_failure_keeps_only_failed_events(fake_store: _FakeStore) -> None:
    batch = _batch(events=3)
    failed = batch.events[1:]
    delivery = _RecordingDelivery("clickhouse", DeliveryResult(delivered=1, retry=failed, error="503:unavailable"))
    dispatcher = OutboxDispatcher(delivery=delivery, cfg=_config())

    dispatcher._settle(batch, delivery.result)

    assert fake_store.completed == []
    assert len(fake_store.rescheduled) == 1
    assert fake_store.rescheduled[0]["events"] == failed
    assert fake_store.rescheduled[0]["error"] == "503:unavailable"
    assert fake_store.dead == []


def test_permanent_failure_goes_to_dead_letter_and_batch_is_removed(fake_store: _FakeStore) -> None:
    batch = _batch(events=2)
    rejected = batch.events[:1]
    delivery = _RecordingDelivery("clickhouse", DeliveryResult(delivered=1, dead=rejected, error="400:mapper_parsing"))
    dispatcher = OutboxDispatcher(delivery=delivery, cfg=_config())

    dispatcher._settle(batch, delivery.result)

    assert fake_store.completed == [batch.id]
    assert [entry["reason"] for entry in fake_store.dead] == [REASON_REJECTED]
    assert fake_store.dead[0]["events"] == rejected


def test_exhausted_attempts_dead_letter_the_remainder(fake_store: _FakeStore) -> None:
    batch = _batch(attempts=3, events=2)
    delivery = _RecordingDelivery("clickhouse", DeliveryResult(retry=batch.events, error="timeout"))
    dispatcher = OutboxDispatcher(delivery=delivery, cfg=_config(max_attempts=3))

    dispatcher._settle(batch, delivery.result)

    assert fake_store.completed == [batch.id]
    assert fake_store.rescheduled == []
    assert [entry["reason"] for entry in fake_store.dead] == [REASON_MAX_ATTEMPTS]
    assert fake_store.dead[0]["events"] == batch.events


def test_retry_delay_grows_with_attempts(fake_store: _FakeStore) -> None:
    cfg = _config(retry_backoff_seconds=2.0, retry_backoff_max_seconds=8.0)
    dispatcher = OutboxDispatcher(delivery=_RecordingDelivery("clickhouse", DeliveryResult()), cfg=cfg)
    batch = _batch(attempts=2, events=1)

    dispatcher._settle(batch, DeliveryResult(retry=batch.events, error="timeout"))

    delay = fake_store.rescheduled[0]["available_at"] - datetime.now(timezone.utc)
    assert timedelta(seconds=3) < delay <= timedelta(seconds=4)
