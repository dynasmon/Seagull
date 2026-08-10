from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Sequence

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.engine import Connection

from app.shared.indexing.identity import normalized_event_timestamp
from app.shared.outbox.models import EventOutboxDeadLetterModel, EventOutboxModel

REASON_MAX_ATTEMPTS = "max_attempts"
REASON_REJECTED = "rejected"


@dataclass(frozen=True)
class OutboxBatch:
    id: int
    sink: str
    events: List[Dict[str, Any]]
    attempts: int
    enqueued_at: datetime


@dataclass(frozen=True)
class OutboxDepth:
    batches: int
    events: int
    oldest_age_seconds: float


def _encode_event(event: Dict[str, Any]) -> Dict[str, Any]:
    encoded = dict(event)
    timestamp = encoded.get("timestamp")
    if isinstance(timestamp, datetime):
        encoded["timestamp"] = timestamp.isoformat()
    extra = encoded.get("extra")
    if not isinstance(extra, dict):
        encoded["extra"] = {}
    return encoded


def _decode_event(event: Dict[str, Any]) -> Dict[str, Any]:
    decoded = dict(event)
    decoded["timestamp"] = normalized_event_timestamp(decoded.get("timestamp"))
    extra = decoded.get("extra")
    if not isinstance(extra, dict):
        decoded["extra"] = {}
    return decoded


def encode_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [_encode_event(event) for event in events]


def decode_events(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, list):
        return []
    return [_decode_event(event) for event in payload if isinstance(event, dict)]


def _chunks(events: Sequence[Dict[str, Any]], size: int) -> Iterable[Sequence[Dict[str, Any]]]:
    step = max(1, int(size))
    for start in range(0, len(events), step):
        yield events[start : start + step]


def enqueue(
    conn: Connection,
    *,
    sink: str,
    events: Sequence[Dict[str, Any]],
    chunk_size: int,
    now: datetime | None = None,
) -> int:
    if not events:
        return 0
    available_at = now or datetime.now(timezone.utc)
    rows = [
        {
            "sink": sink,
            "payload": encode_events(chunk),
            "event_count": len(chunk),
            "attempts": 0,
            "available_at": available_at,
            "created_at": available_at,
        }
        for chunk in _chunks(events, chunk_size)
    ]
    conn.execute(insert(EventOutboxModel), rows)
    return len(rows)


def claim(
    conn: Connection,
    *,
    sink: str,
    limit: int,
    lease_seconds: float,
    now: datetime | None = None,
) -> List[OutboxBatch]:
    claimed_at = now or datetime.now(timezone.utc)
    due = (
        select(EventOutboxModel.id)
        .where(EventOutboxModel.sink == sink, EventOutboxModel.available_at <= claimed_at)
        .order_by(EventOutboxModel.available_at.asc(), EventOutboxModel.id.asc())
        .limit(max(1, int(limit)))
        .with_for_update(skip_locked=True)
    )
    rows = conn.execute(
        update(EventOutboxModel)
        .where(EventOutboxModel.id.in_(due.scalar_subquery()))
        .values(
            attempts=EventOutboxModel.attempts + 1,
            available_at=claimed_at + timedelta(seconds=max(1.0, float(lease_seconds))),
        )
        .returning(
            EventOutboxModel.id,
            EventOutboxModel.sink,
            EventOutboxModel.payload,
            EventOutboxModel.attempts,
            EventOutboxModel.created_at,
        )
    ).mappings().all()

    batches = [
        OutboxBatch(
            id=int(row["id"]),
            sink=str(row["sink"]),
            events=decode_events(row["payload"]),
            attempts=int(row["attempts"] or 0),
            enqueued_at=row["created_at"],
        )
        for row in rows
    ]
    batches.sort(key=lambda batch: batch.id)
    return batches


def complete(conn: Connection, *, batch_ids: Sequence[int]) -> None:
    if not batch_ids:
        return
    conn.execute(delete(EventOutboxModel).where(EventOutboxModel.id.in_(list(batch_ids))))


def reschedule(
    conn: Connection,
    *,
    batch_id: int,
    events: Sequence[Dict[str, Any]],
    available_at: datetime,
    error: str,
) -> None:
    conn.execute(
        update(EventOutboxModel)
        .where(EventOutboxModel.id == int(batch_id))
        .values(
            payload=encode_events(events),
            event_count=len(events),
            available_at=available_at,
            last_error=(error or "")[:500] or None,
        )
    )


def dead_letter(
    conn: Connection,
    *,
    batch: OutboxBatch,
    events: Sequence[Dict[str, Any]],
    reason: str,
    error: str,
    now: datetime | None = None,
) -> None:
    if not events:
        return
    conn.execute(
        insert(EventOutboxDeadLetterModel).values(
            sink=batch.sink,
            payload=encode_events(events),
            event_count=len(events),
            attempts=int(batch.attempts),
            reason=str(reason)[:64],
            error=(error or "")[:500] or None,
            enqueued_at=batch.enqueued_at,
            failed_at=now or datetime.now(timezone.utc),
        )
    )


def depth(conn: Connection, *, sink: str, now: datetime | None = None) -> OutboxDepth:
    row = conn.execute(
        select(
            func.count(EventOutboxModel.id),
            func.coalesce(func.sum(EventOutboxModel.event_count), 0),
            func.min(EventOutboxModel.created_at),
        ).where(EventOutboxModel.sink == sink)
    ).first()
    if row is None:
        return OutboxDepth(batches=0, events=0, oldest_age_seconds=0.0)

    oldest = row[2]
    if oldest is None:
        age = 0.0
    else:
        reference = now or datetime.now(timezone.utc)
        if oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=timezone.utc)
        age = max(0.0, (reference - oldest).total_seconds())
    return OutboxDepth(batches=int(row[0] or 0), events=int(row[1] or 0), oldest_age_seconds=age)


def dead_letter_depth(conn: Connection, *, sink: str) -> int:
    total = conn.execute(
        select(func.coalesce(func.sum(EventOutboxDeadLetterModel.event_count), 0)).where(
            EventOutboxDeadLetterModel.sink == sink
        )
    ).scalar()
    return int(total or 0)


def purge_dead_letter(conn: Connection, *, older_than: datetime) -> int:
    result = conn.execute(
        delete(EventOutboxDeadLetterModel).where(EventOutboxDeadLetterModel.failed_at < older_than)
    )
    return int(result.rowcount or 0)
