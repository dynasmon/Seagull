from __future__ import annotations

import json
import logging
import os
from typing import Any

from app.core.observability import log_event
from app.core.redis_client import get_redis


logger = logging.getLogger("netwatch.api.realtime")

PORTAL_REALTIME_TOPICS = ("overview", "alerts", "agents")
PORTAL_REALTIME_CHANNEL_PREFIX = "netwatch:portal:realtime:v2:topic"
PORTAL_REALTIME_REPLAY_PREFIX = "netwatch:portal:realtime:v2:replay"
PORTAL_REALTIME_CURSOR_KEY = "netwatch:portal:realtime:v2:cursor"


def _replay_max_events() -> int:
    raw = str(os.getenv("NETWATCH_REALTIME_REPLAY_MAX_EVENTS", "256") or "256").strip()
    try:
        parsed = int(raw, 10)
    except Exception:
        parsed = 256
    return max(32, parsed)


PORTAL_REALTIME_REPLAY_MAX_EVENTS = _replay_max_events()


def portal_realtime_topics() -> tuple[str, ...]:
    return PORTAL_REALTIME_TOPICS


def _normalize_topic(topic: str | None) -> str:
    raw = str(topic or "").strip().lower()
    if raw in PORTAL_REALTIME_TOPICS:
        return raw
    return "overview"


def portal_realtime_channel(topic: str = "overview") -> str:
    normalized = _normalize_topic(topic)
    return f"{PORTAL_REALTIME_CHANNEL_PREFIX}:{normalized}"


def portal_realtime_replay_key(topic: str = "overview") -> str:
    normalized = _normalize_topic(topic)
    return f"{PORTAL_REALTIME_REPLAY_PREFIX}:{normalized}"


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


def load_portal_realtime_replay(redis_client: Any, *, topic: str, max_events: int = 200) -> list[str]:
    if redis_client is None:
        return []

    limit = max(1, int(max_events or 1))
    key = portal_realtime_replay_key(topic)
    try:
        rows = redis_client.lrange(key, -limit, -1) or []
    except Exception:
        return []

    out: list[str] = []
    for row in rows:
        if isinstance(row, str):
            text = row.strip()
        else:
            text = str(row or "").strip()
        if text:
            out.append(text)
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
        cursor = _cursor_to_int(payload.get("cursor"))
        if cursor <= 0:
            cursor = int(redis_client.incr(PORTAL_REALTIME_CURSOR_KEY))
        payload["cursor"] = str(cursor)
        payload["topic"] = event_topic
        message_out = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False)

        replay_key = portal_realtime_replay_key(event_topic)
        channel = portal_realtime_channel(event_topic)

        pipe = redis_client.pipeline()
        pipe.rpush(replay_key, message_out)
        pipe.ltrim(replay_key, -PORTAL_REALTIME_REPLAY_MAX_EVENTS, -1)
        pipe.publish(channel, message_out)
        pipe.execute()
        return True
    except Exception as exc:
        log_event(
            logger,
            "warning",
            "realtime_publish_failed",
            channel=portal_realtime_channel(event_topic),
            error_type=type(exc).__name__,
            error=str(exc),
        )
        return False
