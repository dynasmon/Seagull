from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.core.cache import get_redis
from app.core.observability import incr_counter
from app.features.ingest.control.queue_keys import backlog_events_key, deadletter_key, queue_key

DEADLETTER_MAX_MESSAGES = 200
DEADLETTER_TTL_SECONDS = 7 * 86400
DEADLETTER_PAGE_MAX = 25


@dataclass(frozen=True)
class DeadLetterMessage:
    position: int
    agent_id: str
    received: int
    retries: int
    received_at: Optional[str]
    mode: str
    storm_reason: str
    hot_events: int
    analytics_events: int
    warm_events: int
    rollups: int
    payload_bytes: int
    readable: bool


@dataclass(frozen=True)
class DeadLetterPage:
    messages: int
    offset: int
    limit: int
    items: List[DeadLetterMessage]


@dataclass(frozen=True)
class RedriveOutcome:
    requeued_messages: int
    requeued_events: int
    skipped_messages: int
    remaining_messages: int


@dataclass(frozen=True)
class PurgeOutcome:
    purged_messages: int
    remaining_messages: int


class DeadLetterUnavailable(RuntimeError):
    pass


def push(client: Any, payload: Any) -> None:
    if client is None:
        return
    key = deadletter_key()
    try:
        pipe = client.pipeline()
        pipe.rpush(key, payload)
        pipe.ltrim(key, -DEADLETTER_MAX_MESSAGES, -1)
        pipe.expire(key, DEADLETTER_TTL_SECONDS)
        pipe.execute()
    except Exception:
        return


def depth(client: Any = None) -> int:
    target = client or get_redis()
    if target is None:
        return 0
    try:
        return max(0, int(target.llen(deadletter_key()) or 0))
    except Exception:
        return 0


def page(*, offset: int = 0, limit: int = DEADLETTER_PAGE_MAX) -> DeadLetterPage:
    start = max(0, int(offset))
    size = max(1, min(int(limit), DEADLETTER_PAGE_MAX))

    client = _require_client()
    try:
        total = max(0, int(client.llen(deadletter_key()) or 0))
        raw_messages = client.lrange(deadletter_key(), start, start + size - 1) or []
    except Exception as exc:
        raise DeadLetterUnavailable("dead letter list is unreadable") from exc

    items = [_summarize(position=start + index, raw=raw) for index, raw in enumerate(raw_messages)]
    return DeadLetterPage(messages=total, offset=start, limit=size, items=items)


def redrive(*, limit: int) -> RedriveOutcome:
    budget = max(1, min(int(limit), DEADLETTER_MAX_MESSAGES))

    client = _require_client()
    requeued_messages = 0
    requeued_events = 0
    skipped_messages = 0

    for _ in range(min(budget, depth(client))):
        try:
            raw = client.lpop(deadletter_key())
        except Exception:
            break
        if not raw:
            break

        message = _decode(raw)
        if message is None:
            skipped_messages += 1
            _restore(client, raw)
            continue

        message.pop("_retry_count", None)
        received = max(0, _as_int(message.get("received")))
        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False)

        try:
            pipe = client.pipeline()
            pipe.lpush(queue_key(), payload)
            if received > 0:
                pipe.incrby(backlog_events_key(), received)
            pipe.execute()
        except Exception:
            _restore(client, raw)
            break

        requeued_messages += 1
        requeued_events += received

    if requeued_messages:
        incr_counter("ingest_deadletter_redriven_messages_total", value=float(requeued_messages))

    return RedriveOutcome(
        requeued_messages=requeued_messages,
        requeued_events=requeued_events,
        skipped_messages=skipped_messages,
        remaining_messages=depth(client),
    )


def purge(*, limit: Optional[int] = None) -> PurgeOutcome:
    client = _require_client()
    before = depth(client)
    if limit is None:
        try:
            client.delete(deadletter_key())
        except Exception:
            return PurgeOutcome(purged_messages=0, remaining_messages=before)
        purged = before
    else:
        budget = max(1, min(int(limit), DEADLETTER_MAX_MESSAGES))
        purged = 0
        for _ in range(budget):
            try:
                raw = client.lpop(deadletter_key())
            except Exception:
                break
            if not raw:
                break
            purged += 1

    if purged:
        incr_counter("ingest_deadletter_purged_messages_total", value=float(purged))

    return PurgeOutcome(purged_messages=purged, remaining_messages=depth(client))


def _require_client() -> Any:
    client = get_redis()
    if client is None:
        raise DeadLetterUnavailable("redis is unavailable")
    return client


def _restore(client: Any, raw: Any) -> None:
    try:
        client.rpush(deadletter_key(), raw)
    except Exception:
        return


def _decode(raw: Any) -> Optional[Dict[str, Any]]:
    try:
        message = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return message if isinstance(message, dict) else None


def _summarize(*, position: int, raw: Any) -> DeadLetterMessage:
    payload_bytes = len(raw.encode("utf-8")) if isinstance(raw, str) else len(raw or b"")
    message = _decode(raw)
    if message is None:
        return DeadLetterMessage(
            position=position,
            agent_id="",
            received=0,
            retries=0,
            received_at=None,
            mode="",
            storm_reason="",
            hot_events=0,
            analytics_events=0,
            warm_events=0,
            rollups=0,
            payload_bytes=payload_bytes,
            readable=False,
        )

    return DeadLetterMessage(
        position=position,
        agent_id=str(message.get("agent_id") or "")[:64],
        received=max(0, _as_int(message.get("received"))),
        retries=max(0, _as_int(message.get("_retry_count"))),
        received_at=_as_text(message.get("received_at")),
        mode=str(message.get("mode") or "")[:32],
        storm_reason=str(message.get("storm_reason") or "")[:64],
        hot_events=_count(message.get("hot_events")),
        analytics_events=_count(message.get("analytics_events")),
        warm_events=_count(message.get("warm_events")),
        rollups=_count(message.get("rollups")),
        payload_bytes=payload_bytes,
        readable=True,
    )


def _count(value: Any) -> int:
    return len(value) if isinstance(value, (list, tuple)) else 0


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _as_text(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text[:64] or None
