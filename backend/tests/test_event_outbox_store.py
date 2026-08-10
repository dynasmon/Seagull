from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite+pysqlite:///:memory:")

import pytest
from sqlalchemy import create_engine

from app.core.db import Base
from app.shared.outbox import store
from app.shared.outbox.models import SINK_CLICKHOUSE, SINK_WARM, EventOutboxDeadLetterModel, EventOutboxModel

NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def connection():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[EventOutboxModel.__table__, EventOutboxDeadLetterModel.__table__],
    )
    with engine.begin() as conn:
        yield conn
    engine.dispose()


def _events(count: int, *, first_id: int = 1):
    return [
        {
            "agent_id": "agent-1",
            "event_type": "dns",
            "timestamp": NOW,
            "extra": {"app_proto": "dns"},
            "pg_event_id": first_id + offset,
        }
        for offset in range(count)
    ]


def test_enqueue_splits_events_into_bounded_batches(connection) -> None:
    written = store.enqueue(connection, sink=SINK_CLICKHOUSE, events=_events(5), chunk_size=2, now=NOW)

    assert written == 3
    depth = store.depth(connection, sink=SINK_CLICKHOUSE, now=NOW)
    assert depth.batches == 3
    assert depth.events == 5


def test_enqueue_is_scoped_per_sink(connection) -> None:
    store.enqueue(connection, sink=SINK_CLICKHOUSE, events=_events(2), chunk_size=10, now=NOW)
    store.enqueue(connection, sink=SINK_WARM, events=_events(3), chunk_size=10, now=NOW)

    assert store.depth(connection, sink=SINK_CLICKHOUSE, now=NOW).events == 2
    assert store.depth(connection, sink=SINK_WARM, now=NOW).events == 3
    assert store.claim(connection, sink=SINK_WARM, limit=10, lease_seconds=60, now=NOW)[0].events[0]["pg_event_id"] == 1


def test_claim_returns_decoded_events_and_counts_the_attempt(connection) -> None:
    store.enqueue(connection, sink=SINK_CLICKHOUSE, events=_events(2), chunk_size=10, now=NOW)

    batches = store.claim(connection, sink=SINK_CLICKHOUSE, limit=10, lease_seconds=60, now=NOW)

    assert len(batches) == 1
    assert batches[0].attempts == 1
    assert batches[0].events[0]["timestamp"] == NOW
    assert batches[0].events[0]["extra"] == {"app_proto": "dns"}


def test_leased_batches_are_not_claimed_again_until_the_lease_expires(connection) -> None:
    store.enqueue(connection, sink=SINK_CLICKHOUSE, events=_events(1), chunk_size=10, now=NOW)
    store.claim(connection, sink=SINK_CLICKHOUSE, limit=10, lease_seconds=60, now=NOW)

    assert store.claim(connection, sink=SINK_CLICKHOUSE, limit=10, lease_seconds=60, now=NOW) == []

    reclaimed = store.claim(
        connection, sink=SINK_CLICKHOUSE, limit=10, lease_seconds=60, now=NOW + timedelta(seconds=61)
    )
    assert len(reclaimed) == 1
    assert reclaimed[0].attempts == 2


def test_complete_removes_the_batch(connection) -> None:
    store.enqueue(connection, sink=SINK_CLICKHOUSE, events=_events(1), chunk_size=10, now=NOW)
    batch = store.claim(connection, sink=SINK_CLICKHOUSE, limit=10, lease_seconds=60, now=NOW)[0]

    store.complete(connection, batch_ids=[batch.id])

    assert store.depth(connection, sink=SINK_CLICKHOUSE, now=NOW).batches == 0


def test_reschedule_narrows_the_batch_to_the_failed_events(connection) -> None:
    store.enqueue(connection, sink=SINK_CLICKHOUSE, events=_events(3), chunk_size=10, now=NOW)
    batch = store.claim(connection, sink=SINK_CLICKHOUSE, limit=10, lease_seconds=60, now=NOW)[0]

    store.reschedule(
        connection,
        batch_id=batch.id,
        events=batch.events[2:],
        available_at=NOW + timedelta(seconds=5),
        error="503:unavailable",
    )

    assert store.depth(connection, sink=SINK_CLICKHOUSE, now=NOW).events == 1
    retried = store.claim(
        connection, sink=SINK_CLICKHOUSE, limit=10, lease_seconds=60, now=NOW + timedelta(seconds=6)
    )
    assert [event["pg_event_id"] for event in retried[0].events] == [3]


def test_dead_letter_preserves_the_events_and_the_reason(connection) -> None:
    store.enqueue(connection, sink=SINK_CLICKHOUSE, events=_events(2), chunk_size=10, now=NOW)
    batch = store.claim(connection, sink=SINK_CLICKHOUSE, limit=10, lease_seconds=60, now=NOW)[0]

    store.dead_letter(
        connection,
        batch=batch,
        events=batch.events,
        reason=store.REASON_MAX_ATTEMPTS,
        error="timeout",
        now=NOW,
    )
    store.complete(connection, batch_ids=[batch.id])

    assert store.dead_letter_depth(connection, sink=SINK_CLICKHOUSE) == 2
    assert store.depth(connection, sink=SINK_CLICKHOUSE, now=NOW).batches == 0


def test_dead_letters_are_purged_by_age(connection) -> None:
    store.enqueue(connection, sink=SINK_CLICKHOUSE, events=_events(1), chunk_size=10, now=NOW)
    batch = store.claim(connection, sink=SINK_CLICKHOUSE, limit=10, lease_seconds=60, now=NOW)[0]
    store.dead_letter(
        connection, batch=batch, events=batch.events, reason=store.REASON_REJECTED, error="", now=NOW
    )

    assert store.purge_dead_letter(connection, older_than=NOW - timedelta(days=1)) == 0
    assert store.purge_dead_letter(connection, older_than=NOW + timedelta(days=1)) == 1
    assert store.dead_letter_depth(connection, sink=SINK_CLICKHOUSE) == 0


def test_depth_reports_the_age_of_the_oldest_batch(connection) -> None:
    store.enqueue(connection, sink=SINK_CLICKHOUSE, events=_events(1), chunk_size=10, now=NOW)

    depth = store.depth(connection, sink=SINK_CLICKHOUSE, now=NOW + timedelta(seconds=90))

    assert depth.oldest_age_seconds == pytest.approx(90.0, abs=1.0)
