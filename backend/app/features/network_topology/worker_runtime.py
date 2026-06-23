from __future__ import annotations

from datetime import datetime
from typing import Any

from app.core.cache import get_redis
from app.core.realtime import (
    load_portal_realtime_replay,
    partitions_for_topics,
    portal_realtime_partition_stream_key,
    read_portal_realtime_stream,
)
from app.features.network_topology.realtime import publish_topology_invalidate
from app.features.realtime.service import parse_realtime_envelope

_SIGNAL_DRAIN_COUNT = 256
_SIGNAL_DRAIN_BLOCK_MS = 100
_SIGNAL_CURSOR_KEY_PREFIX = "seagull:network_topology:signal_stream_cursor"
_SIGNAL_TOPICS = ("alerts", "exposure", "inventory", "network_topology")


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def map_event_to_invalidate_kwargs(envelope) -> dict[str, Any] | None:
    event_type = str(getattr(envelope, "type", "") or "")
    payload = getattr(envelope, "payload", None)
    if not isinstance(payload, dict):
        payload = {}

    if event_type == "exposure.summary.updated":
        return {
            "reason": "exposure_graph_updated",
            "source": "exposure",
            "projected_at": _parse_iso(payload.get("updated_at")),
        }
    if event_type == "ui.inventory.invalidate":
        return {
            "reason": "inventory_snapshot_ingested",
            "source": "inventory",
            "agent_id": payload.get("agent_id"),
        }
    if event_type == "ui.alerts.delta.patch":
        action = str(payload.get("action") or "").strip().lower()
        alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
        return {
            "reason": "alert_created" if action == "upsert" else "alert_updated",
            "source": "alerts",
            "alert_id": _safe_int(alert.get("id")),
            "high_priority": True,
        }
    if event_type == "ingest.event_batch.ingested":
        return {
            "reason": str(payload.get("reason") or "event_batch_ingested"),
            "source": str(payload.get("source") or "ingest"),
            "agent_id": payload.get("agent_id"),
            "batch_size": payload.get("batch_size"),
            "event_types": payload.get("event_types"),
            "degraded": bool(payload.get("degraded")),
            "sampled": bool(payload.get("sampled")),
            "high_priority": bool(payload.get("high_priority")),
        }
    return None


def _signal_partitions() -> list[str]:
    return sorted(partitions_for_topics(_SIGNAL_TOPICS))


def _signal_cursor_key(partition: str) -> str:
    return f"{_SIGNAL_CURSOR_KEY_PREFIX}:{partition}"


def _load_persisted_cursor(redis_client, partition: str) -> str:
    try:
        raw = redis_client.get(_signal_cursor_key(partition))
    except Exception:
        return ""
    return str(raw or "").strip()


def _persist_cursor(redis_client, partition: str, stream_id: str) -> None:
    value = str(stream_id or "").strip()
    if not value:
        return
    try:
        redis_client.set(_signal_cursor_key(partition), value)
    except Exception:
        return


def _baseline_cursor(redis_client, partition: str) -> str:
    replay = load_portal_realtime_replay(redis_client, partitions=[partition], max_events=1)
    return replay[-1].stream_id if replay else "0"


def drain_topology_signals(state) -> int:
    redis_client = get_redis(decode_responses=True)
    if redis_client is None:
        return 0

    partitions = _signal_partitions()
    key_for_partition = {partition: portal_realtime_partition_stream_key(partition) for partition in partitions}
    partition_for_key = {key: partition for partition, key in key_for_partition.items()}

    cursors = dict(getattr(state, "last_signal_stream_ids", None) or {})

    missing: list[str] = []
    for partition in partitions:
        current = str(cursors.get(partition) or "").strip()
        if not current:
            current = _load_persisted_cursor(redis_client, partition)
        if current:
            cursors[partition] = current
        else:
            missing.append(partition)

    if missing:
        for partition in missing:
            baseline = _baseline_cursor(redis_client, partition)
            cursors[partition] = baseline
            _persist_cursor(redis_client, partition, baseline)
        state.last_signal_stream_ids = {partition: cursors[partition] for partition in partitions}
        return 0

    state.last_signal_stream_ids = {partition: cursors[partition] for partition in partitions}

    entries, advanced = read_portal_realtime_stream(
        redis_client,
        streams={key_for_partition[partition]: cursors[partition] for partition in partitions},
        block_ms=_SIGNAL_DRAIN_BLOCK_MS,
        count=_SIGNAL_DRAIN_COUNT,
    )
    if not entries:
        return 0

    reacted = 0
    for entry in entries:
        envelope = parse_realtime_envelope(entry.message)
        if envelope is None:
            continue
        kwargs = map_event_to_invalidate_kwargs(envelope)
        if kwargs is not None:
            publish_topology_invalidate(**kwargs)
            reacted += 1

    for stream_key, stream_id in advanced.items():
        partition = partition_for_key.get(stream_key)
        if partition is None:
            continue
        cursors[partition] = stream_id
        _persist_cursor(redis_client, partition, stream_id)

    state.last_signal_stream_ids = {partition: cursors[partition] for partition in partitions}
    return reacted
