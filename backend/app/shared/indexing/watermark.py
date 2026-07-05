from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.cache import get_redis

_WATERMARK_KEY = "seagull:analytics:ch_watermark"
_WATERMARK_TTL_SECONDS = 86400
_PROTO_INTEL_FLOOR_KEY = "seagull:analytics:proto_intel_floor"
_PROTO_INTEL_RANGE_KEY = "seagull:analytics:proto_intel_range"


def _coerce_utc(ts: Any) -> Optional[datetime]:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str) and ts.strip():
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def write_clickhouse_watermark(*, max_pg_event_id: int, max_ts: Any) -> None:
    r = get_redis()
    if r is None:
        return
    ts = _coerce_utc(max_ts)
    if ts is None:
        return
    new_id = int(max_pg_event_id or 0)
    try:
        existing = read_clickhouse_watermark()
        if existing is not None:
            cur_ts = existing.get("max_ts")
            if isinstance(cur_ts, datetime) and cur_ts >= ts and existing.get("max_pg_event_id", 0) >= new_id:
                payload = {
                    "max_pg_event_id": int(existing.get("max_pg_event_id", 0) or 0),
                    "max_ts": cur_ts.isoformat(),
                    "updated_at": time.time(),
                }
                r.setex(_WATERMARK_KEY, _WATERMARK_TTL_SECONDS, json.dumps(payload, separators=(",", ":")))
                return
            new_id = max(new_id, int(existing.get("max_pg_event_id", 0) or 0))
            if isinstance(cur_ts, datetime):
                ts = max(ts, cur_ts)
        payload = {
            "max_pg_event_id": new_id,
            "max_ts": ts.isoformat(),
            "updated_at": time.time(),
        }
        r.setex(_WATERMARK_KEY, _WATERMARK_TTL_SECONDS, json.dumps(payload, separators=(",", ":")))
    except Exception:
        return


def read_clickhouse_watermark() -> Optional[dict[str, Any]]:
    r = get_redis()
    if r is None:
        return None
    try:
        raw = r.get(_WATERMARK_KEY)
        if not raw:
            return None
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None
        return {
            "max_pg_event_id": int(data.get("max_pg_event_id", 0) or 0),
            "max_ts": _coerce_utc(data.get("max_ts")),
            "updated_at": float(data.get("updated_at", 0.0) or 0.0),
        }
    except Exception:
        return None


def clickhouse_watermark_lag_seconds(*, now: Optional[datetime] = None) -> Optional[float]:
    wm = read_clickhouse_watermark()
    if wm is None:
        return None
    max_ts = wm.get("max_ts")
    if not isinstance(max_ts, datetime):
        return None
    ref = now or datetime.now(timezone.utc)
    return max(0.0, (ref - max_ts).total_seconds())


def write_proto_intel_materialization_floor(*, floor_ts: Any) -> None:
    r = get_redis()
    if r is None:
        return
    ts = _coerce_utc(floor_ts)
    if ts is None:
        return
    try:
        payload = {"floor_ts": ts.isoformat(), "updated_at": time.time()}
        r.set(_PROTO_INTEL_FLOOR_KEY, json.dumps(payload, separators=(",", ":")))
    except Exception:
        return


def read_proto_intel_materialization_floor() -> Optional[datetime]:
    r = get_redis()
    if r is None:
        return None
    try:
        raw = r.get(_PROTO_INTEL_FLOOR_KEY)
        if not raw:
            return None
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None
        return _coerce_utc(data.get("floor_ts"))
    except Exception:
        return None


def pin_proto_intel_materialization_range(
    *, start_ts: Any, boundary_ts: Any, chunk_hours: int | None = None
) -> Optional[dict[str, Any]]:
    start = _coerce_utc(start_ts)
    boundary = _coerce_utc(boundary_ts)
    if start is None or boundary is None:
        return None
    fallback = {
        "start": start,
        "boundary": boundary,
        "gen": "0",
        "chunk_hours": int(chunk_hours) if chunk_hours else None,
    }
    r = get_redis()
    if r is None:
        return fallback
    try:
        payload = {
            "start_ts": start.isoformat(),
            "boundary_ts": boundary.isoformat(),
            # Generation goes into insert_deduplication_token so a rebuild after
            # TRUNCATE never collides with the dedup log of a previous fill.
            "gen": str(int(time.time())),
            "chunk_hours": int(chunk_hours) if chunk_hours else None,
            "updated_at": time.time(),
        }
        r.set(_PROTO_INTEL_RANGE_KEY, json.dumps(payload, separators=(",", ":")), nx=True)
    except Exception:
        return fallback
    return read_proto_intel_materialization_range() or fallback


def read_proto_intel_materialization_range() -> Optional[dict[str, Any]]:
    r = get_redis()
    if r is None:
        return None
    try:
        raw = r.get(_PROTO_INTEL_RANGE_KEY)
        if not raw:
            return None
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None
        start = _coerce_utc(data.get("start_ts"))
        boundary = _coerce_utc(data.get("boundary_ts"))
        if start is None or boundary is None:
            return None
        chunk_hours = data.get("chunk_hours")
        return {
            "start": start,
            "boundary": boundary,
            # Legacy pins (pre-generation) read back as gen "0".
            "gen": str(data.get("gen") or "0"),
            "chunk_hours": int(chunk_hours) if chunk_hours else None,
        }
    except Exception:
        return None


def clear_proto_intel_materialization_state() -> None:
    r = get_redis()
    if r is None:
        return
    try:
        r.delete(_PROTO_INTEL_FLOOR_KEY, _PROTO_INTEL_RANGE_KEY)
    except Exception:
        return
