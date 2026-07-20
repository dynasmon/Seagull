from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Iterable

from redis.exceptions import TimeoutError as RedisTimeoutError

from app.core.cache import get_redis
from app.core.config.env_secrets import getenv_compat
from app.core.observability import incr_counter, log_event

logger = logging.getLogger("seagull.api.realtime")

PORTAL_REALTIME_TOPICS = (
    "overview",
    "alerts",
    "agents",
    "exposure",
    "investigations",
    "workflows",
    "events",
    "ddos",
    "inventory",
    "vulnerabilities",
    "network_topology",
    "threat_map",
)
PORTAL_REALTIME_STREAM_KEY = "seagull:portal:realtime:v3:stream"
PORTAL_REALTIME_CURSOR_KEY = "seagull:portal:realtime:v3:cursor"

PORTAL_REALTIME_STREAM_PARTITIONS = ("critical", "control", "stream")
PORTAL_REALTIME_DEFAULT_STREAM_PARTITION = "control"

TOPIC_STREAM_PARTITION: dict[str, str] = {
    "overview": "control",
    "alerts": "critical",
    "agents": "control",
    "exposure": "control",
    "investigations": "control",
    "workflows": "control",
    "events": "stream",
    "ddos": "stream",
    "inventory": "control",
    "vulnerabilities": "control",
    "network_topology": "control",
    "threat_map": "control",
}

_UNMAPPED_PORTAL_REALTIME_TOPICS = tuple(
    topic for topic in PORTAL_REALTIME_TOPICS if topic not in TOPIC_STREAM_PARTITION
)
if _UNMAPPED_PORTAL_REALTIME_TOPICS:
    raise RuntimeError(
        f"portal realtime topics missing stream partition mapping: {_UNMAPPED_PORTAL_REALTIME_TOPICS}"
    )

_UNKNOWN_PORTAL_REALTIME_PARTITIONS = tuple(
    sorted({p for p in TOPIC_STREAM_PARTITION.values() if p not in PORTAL_REALTIME_STREAM_PARTITIONS})
)
if _UNKNOWN_PORTAL_REALTIME_PARTITIONS:
    raise RuntimeError(
        f"portal realtime topics mapped to unknown stream partitions: {_UNKNOWN_PORTAL_REALTIME_PARTITIONS}"
    )


class PortalRealtimeStreamUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class PortalRealtimeStreamEntry:
    stream_id: str
    cursor: int
    message: str


@dataclass(frozen=True)
class PortalRealtimeReplayWindow:
    entries: tuple[PortalRealtimeStreamEntry, ...]
    earliest_cursor: int
    latest_cursor: int


def _replay_max_events() -> int:
    raw = str(getenv_compat("SEAGULL_REALTIME_REPLAY_MAX_EVENTS", "512") or "512").strip()
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


def portal_realtime_partition_stream_key(partition: str) -> str:
    name = str(partition or "").strip().lower()
    if name not in PORTAL_REALTIME_STREAM_PARTITIONS:
        name = PORTAL_REALTIME_DEFAULT_STREAM_PARTITION
    return f"{PORTAL_REALTIME_STREAM_KEY}:{name}"


def partition_for_topic(topic: str) -> str:
    return TOPIC_STREAM_PARTITION.get(_normalize_topic(topic), PORTAL_REALTIME_DEFAULT_STREAM_PARTITION)


def partitions_for_topics(topics: Iterable[str]) -> set[str]:
    return {partition_for_topic(topic) for topic in topics or ()}


def _normalize_partitions(partitions: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for partition in partitions or ():
        name = str(partition or "").strip().lower()
        if name in PORTAL_REALTIME_STREAM_PARTITIONS and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _bounded_partition_maxlen(name: str, default: int, low: int, high: int) -> int:
    raw = str(getenv_compat(name, str(default)) or str(default)).strip()
    try:
        parsed = int(raw, 10)
    except Exception:
        parsed = default
    return max(low, min(parsed, high))


def _partition_maxlen(partition: str) -> int:
    name = str(partition or "").strip().lower()
    if name == "critical":
        return _bounded_partition_maxlen("SEAGULL_REALTIME_STREAM_MAXLEN_CRITICAL", 256, 64, 2000)
    if name == "stream":
        return _bounded_partition_maxlen("SEAGULL_REALTIME_STREAM_MAXLEN_STREAM", 2048, 256, 10000)
    if name == "control":
        return _bounded_partition_maxlen("SEAGULL_REALTIME_STREAM_MAXLEN_CONTROL", 512, 64, 5000)
    return PORTAL_REALTIME_REPLAY_MAX_EVENTS


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


def _load_partition_entries(redis_client: Any, key: str, limit: int) -> list[PortalRealtimeStreamEntry]:
    try:
        rows = redis_client.xrevrange(key, max="+", min="-", count=limit) or []
    except Exception:
        try:
            all_rows = redis_client.xrange(key, min="-", max="+") or []
            rows = all_rows[-limit:]
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


def _read_partition_windows(
    redis_client: Any, partitions: list[str], limit: int
) -> dict[str, list[PortalRealtimeStreamEntry]]:
    out: dict[str, list[PortalRealtimeStreamEntry]] = {}
    for partition in partitions:
        key = portal_realtime_partition_stream_key(partition)
        out[key] = _load_partition_entries(redis_client, key, limit)
    return out


def _window_from_partition_windows(
    per_partition: dict[str, list[PortalRealtimeStreamEntry]],
) -> PortalRealtimeReplayWindow:
    merged: list[PortalRealtimeStreamEntry] = []
    for entries in per_partition.values():
        merged.extend(entries)
    if not merged:
        return PortalRealtimeReplayWindow(entries=(), earliest_cursor=0, latest_cursor=0)
    merged.sort(key=lambda item: item.cursor)
    return PortalRealtimeReplayWindow(
        entries=tuple(merged),
        earliest_cursor=merged[0].cursor,
        latest_cursor=merged[-1].cursor,
    )


def load_portal_realtime_replay(
    redis_client: Any,
    *,
    partitions: Iterable[str],
    max_events: int = 200,
) -> list[PortalRealtimeStreamEntry]:
    if redis_client is None:
        return []

    limit = max(1, int(max_events or 1))
    per_partition = _read_partition_windows(redis_client, _normalize_partitions(partitions), limit)

    merged: list[PortalRealtimeStreamEntry] = []
    for entries in per_partition.values():
        merged.extend(entries)
    merged.sort(key=lambda item: item.cursor)
    return merged


def load_portal_realtime_replay_window(
    redis_client: Any,
    *,
    partitions: Iterable[str],
    max_events: int = 200,
) -> PortalRealtimeReplayWindow:
    if redis_client is None:
        return PortalRealtimeReplayWindow(entries=(), earliest_cursor=0, latest_cursor=0)

    limit = max(1, int(max_events or 1))
    per_partition = _read_partition_windows(redis_client, _normalize_partitions(partitions), limit)
    return _window_from_partition_windows(per_partition)


def load_portal_realtime_replay_state(
    redis_client: Any,
    *,
    partitions: Iterable[str],
    max_events: int = 200,
) -> tuple[PortalRealtimeReplayWindow, dict[str, str]]:
    normalized = _normalize_partitions(partitions)
    seek_ids: dict[str, str] = {portal_realtime_partition_stream_key(p): "0" for p in normalized}

    if redis_client is None:
        return PortalRealtimeReplayWindow(entries=(), earliest_cursor=0, latest_cursor=0), seek_ids

    limit = max(1, int(max_events or 1))
    per_partition = _read_partition_windows(redis_client, normalized, limit)
    for key, entries in per_partition.items():
        if entries:
            seek_ids[key] = entries[-1].stream_id
    return _window_from_partition_windows(per_partition), seek_ids


def read_portal_realtime_stream(
    redis_client: Any,
    *,
    streams: dict[str, str],
    block_ms: int = 1000,
    count: int = 100,
    raise_on_error: bool = False,
) -> tuple[list[PortalRealtimeStreamEntry], dict[str, str]]:
    if redis_client is None or not streams:
        if raise_on_error and redis_client is None:
            raise PortalRealtimeStreamUnavailable("realtime backplane unavailable")
        return [], {}

    requested = {str(key): (str(value or "").strip() or "$") for key, value in streams.items()}
    try:
        result = redis_client.xread(streams=requested, count=max(1, int(count or 1)), block=max(0, int(block_ms or 0)))
    except RedisTimeoutError:
        return [], {}
    except Exception as exc:
        if raise_on_error:
            raise PortalRealtimeStreamUnavailable(str(exc)) from exc
        return [], {}

    out: list[PortalRealtimeStreamEntry] = []
    seek_ids: dict[str, str] = {}
    for stream_row in result or []:
        if not isinstance(stream_row, (tuple, list)) or len(stream_row) != 2:
            continue
        stream_key = str(stream_row[0])
        entries = stream_row[1]
        if not isinstance(entries, list):
            continue
        last_id = ""
        for entry_row in entries:
            if not isinstance(entry_row, (tuple, list)) or len(entry_row) != 2:
                continue
            row_id = str(entry_row[0] or "").strip()
            if row_id:
                last_id = row_id
            entry = _entry_from_stream_row(entry_row[0], entry_row[1])
            if entry is not None:
                out.append(entry)
        if last_id:
            seek_ids[stream_key] = last_id
    out.sort(key=lambda item: item.cursor)
    return out, seek_ids


def publish_portal_realtime_message(message: str, *, topic: str | None = None) -> bool:
    if not isinstance(message, str) or not message.strip():
        raise ValueError("message must be a non-empty string")

    redis_client = get_redis(decode_responses=True)
    if redis_client is None:
        incr_counter("realtime_publish_dropped_total", reason="redis_unavailable")
        return False

    payload = _parse_message_json(message)
    event_topic = _normalize_topic(str(payload.get("topic") or topic or "overview"))
    partition = partition_for_topic(event_topic)
    stream_key = portal_realtime_partition_stream_key(partition)

    try:
        cursor = int(redis_client.incr(PORTAL_REALTIME_CURSOR_KEY))
        payload["cursor"] = str(cursor)
        payload["topic"] = event_topic
        message_out = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False)

        redis_client.xadd(
            stream_key,
            {
                "cursor": str(cursor),
                "topic": event_topic,
                "envelope": message_out,
            },
            maxlen=_partition_maxlen(partition),
            approximate=True,
        )
        incr_counter("realtime_publish_topic_total", topic=event_topic)
        return True
    except Exception as exc:
        incr_counter("realtime_publish_dropped_total", reason=type(exc).__name__)
        log_event(
            logger,
            "warning",
            "realtime_publish_failed",
            stream=stream_key,
            error_type=type(exc).__name__,
            error=str(exc),
        )
        return False
