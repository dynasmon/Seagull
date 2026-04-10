from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from app.core.observability import log_event
from app.core.redis_client import get_redis


logger = logging.getLogger("netwatch.api.realtime")

PORTAL_REALTIME_TOPICS = ("overview", "alerts", "agents")
PORTAL_REALTIME_STREAM_KEY = "netwatch:portal:realtime:v3:stream"
PORTAL_REALTIME_CURSOR_KEY = "netwatch:portal:realtime:v3:cursor"


@dataclass(frozen=True)
class PortalRealtimeStreamEntry:
    stream_id: str
    cursor: int
    message: str


def _replay_max_events() -> int:
    raw = str(os.getenv("NETWATCH_REALTIME_REPLAY_MAX_EVENTS", "512") or "512").strip()
    try:
        parsed = int(raw, 10)
    except Exception:
        parsed = 512
    return max(64, min(parsed, 5000))


PORTAL_REALTIME_REPLAY_MAX_EVENTS = _replay_max_events()


def portal_realtime_topics() -> tuple[str, ...]:
    return PORTAL_REALTIME_TOPICS


def _normalize_topic(topic: str | None) -> str:
    raw = str(topic or "").strip().lower()
    if raw in PORTAL_REALTIME_TOPICS:
        return raw
    return "overview"


def portal_realtime_stream_key() -> str:
    return PORTAL_REALTIME_STREAM_KEY


def _cursor_to_int(value: Any) -> int:
    try:
        out = int(str(value or "").strip(), 10)
    except Exception:
        return 0
    if out < 0:
        return 0
    return out


def _parse_message_json(raw_message: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw_message)
    except Exception as exc:
        raise ValueError("message must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("message must be a JSON object")
    return parsed


def _entry_from_stream_row(stream_id: Any, fields: Any) -> PortalRealtimeStreamEntry | None:
    entry_id = str(stream_id or "").strip()
    if not entry_id:
        return None
    if not isinstance(fields, dict):
        return None

    message_raw = fields.get("envelope")
    if not isinstance(message_raw, str) or not message_raw.strip():
        return None

    cursor_raw = fields.get("cursor")
    cursor = _cursor_to_int(cursor_raw)
    if cursor <= 0:
        return None

    return PortalRealtimeStreamEntry(
        stream_id=entry_id,
        cursor=cursor,
        message=message_raw.strip(),
    )


def load_portal_realtime_replay(
    redis_client: Any,
    *,
    max_events: int = 200,
) -> list[PortalRealtimeStreamEntry]:
    if redis_client is None:
        return []

    limit = max(1, int(max_events or 1))
    key = portal_realtime_stream_key()
    try:
        rows = redis_client.xrevrange(key, max="+", min="-", count=limit) or []
    except Exception:
        try:
            rows = redis_client.xrange(key, min="-", max="+", count=limit) or []
        except Exception:
            return []

    out: list[PortalRealtimeStreamEntry] = []
    for row in rows:
        if not isinstance(row, (tuple, list)) or len(row) != 2:
            continue
        entry = _entry_from_stream_row(row[0], row[1])
        if entry is not None:
            out.append(entry)
    out.sort(key=lambda item: item.cursor)
    return out


def read_portal_realtime_stream(
    redis_client: Any,
    *,
    last_stream_id: str,
    block_ms: int = 1000,
    count: int = 100,
) -> list[PortalRealtimeStreamEntry]:
    if redis_client is None:
        return []

    stream_id = str(last_stream_id or "").strip() or "$"
    key = portal_realtime_stream_key()
    try:
        result = redis_client.xread(streams={key: stream_id}, count=max(1, int(count or 1)), block=max(0, int(block_ms or 0)))
    except Exception:
        return []

    out: list[PortalRealtimeStreamEntry] = []
    for stream_row in result or []:
        if not isinstance(stream_row, (tuple, list)) or len(stream_row) != 2:
            continue
        entries = stream_row[1]
        if not isinstance(entries, list):
            continue
        for entry_row in entries:
            if not isinstance(entry_row, (tuple, list)) or len(entry_row) != 2:
                continue
            entry = _entry_from_stream_row(entry_row[0], entry_row[1])
            if entry is not None:
                out.append(entry)
    return out


def publish_portal_realtime_message(message: str, *, topic: str | None = None) -> bool:
    if not isinstance(message, str) or not message.strip():
        raise ValueError("message must be a non-empty string")

    redis_client = get_redis(decode_responses=True)
    if redis_client is None:
        return False

    payload = _parse_message_json(message)
    event_topic = _normalize_topic(str(payload.get("topic") or topic or "overview"))

    try:
        cursor = int(redis_client.incr(PORTAL_REALTIME_CURSOR_KEY))
        payload["cursor"] = str(cursor)
        payload["topic"] = event_topic
        message_out = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False)

        redis_client.xadd(
            portal_realtime_stream_key(),
            {
                "cursor": str(cursor),
                "topic": event_topic,
                "envelope": message_out,
            },
            maxlen=PORTAL_REALTIME_REPLAY_MAX_EVENTS,
            approximate=True,
        )
        return True
    except Exception as exc:
        log_event(
            logger,
            "warning",
            "realtime_publish_failed",
            stream=portal_realtime_stream_key(),
            error_type=type(exc).__name__,
            error=str(exc),
        )
        return False
