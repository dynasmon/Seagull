from __future__ import annotations

from datetime import datetime
from typing import Any

from app.core.cache import get_redis
from app.core.realtime import load_portal_realtime_replay, read_portal_realtime_stream
from app.features.network_topology.realtime import publish_topology_invalidate
from app.features.realtime.service import parse_realtime_envelope

_SIGNAL_DRAIN_COUNT = 256
_SIGNAL_DRAIN_BLOCK_MS = 100


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


def drain_topology_signals(state) -> int:
    redis_client = get_redis(decode_responses=True)
    if redis_client is None:
        return 0

    last_id = str(getattr(state, "last_signal_stream_id", "") or "")
    if not last_id:
        replay = load_portal_realtime_replay(redis_client, max_events=1)
        state.last_signal_stream_id = replay[-1].stream_id if replay else "0"
        return 0

    entries = read_portal_realtime_stream(
        redis_client,
        last_stream_id=last_id,
        block_ms=_SIGNAL_DRAIN_BLOCK_MS,
        count=_SIGNAL_DRAIN_COUNT,
    )
    if not entries:
        return 0

    reacted = 0
    for entry in entries:
        last_id = entry.stream_id
        envelope = parse_realtime_envelope(entry.message)
        if envelope is None:
            continue
        kwargs = map_event_to_invalidate_kwargs(envelope)
        if kwargs is not None:
            publish_topology_invalidate(**kwargs)
            reacted += 1

    state.last_signal_stream_id = last_id
    return reacted
