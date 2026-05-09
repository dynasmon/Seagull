from __future__ import annotations

import json
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.core.cache import get_redis
from app.core.config import settings


def _feed_key(agent_id: str | None = None) -> str:
    if agent_id:
        return f"seagull:recent_feed:v1:agent:{agent_id}"
    return "seagull:recent_feed:v1:global"


def _feed_last_ts_key(agent_id: str | None = None) -> str:
    if agent_id:
        return f"seagull:recent_feed:v1:last_ts:agent:{agent_id}"
    return "seagull:recent_feed:v1:last_ts:global"


def _feed_rate_key(ts_s: int) -> str:
    return f"seagull:recent_feed:v1:rows:{int(ts_s)}"


def _feed_drop_key(ts_s: int) -> str:
    return f"seagull:recent_feed:v1:dropped:{int(ts_s)}"


def _to_ts(dt: Any) -> Optional[datetime]:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if isinstance(dt, str) and dt.strip():
        try:
            if dt.endswith("Z"):
                dt = dt[:-1] + "+00:00"
            parsed = datetime.fromisoformat(dt)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None
    return None


def _compact_extra(extra: Any) -> Dict[str, Any]:
    if not isinstance(extra, dict):
        return {}

    keep_keys = {
        "action",
        "attack",
        "bps",
        "confidence",
        "distributed",
        "http_rps",
        "ip_context",
        "packets",
        "port_distinct",
        "port_entropy_norm",
        "port_top",
        "port_top_share",
        "pps",
        "requests",
        "severity",
        "src_entropy_norm",
        "tcp_syn_ratio",
        "tls_handshake_rps",
        "top_src",
        "unique_src_ips",
        "username",
        "vector",
        "window_seconds",
    }

    out: Dict[str, Any] = {}
    for key in keep_keys:
        if key not in extra:
            continue
        value = extra.get(key)
        if key == "top_src":
            if isinstance(value, list):
                trimmed = []
                for item in value[:10]:
                    if not isinstance(item, dict):
                        continue
                    trimmed.append(
                        {
                            "ip": item.get("ip") or item.get("src_ip") or item.get("address"),
                            "count": item.get("count"),
                        }
                    )
                out[key] = trimmed
            continue
        out[key] = value
    return out


def _event_id(row: Dict[str, Any]) -> int:
    raw = "|".join(
        [
            str(row.get("agent_id") or ""),
            str(row.get("event_type") or ""),
            str(row.get("timestamp") or ""),
            str(row.get("src_ip") or ""),
            str(row.get("dst_ip") or ""),
            str(row.get("src_port") or 0),
            str(row.get("dst_port") or 0),
            str(row.get("proto") or ""),
        ]
    )
    return int(zlib.crc32(raw.encode("utf-8")) & 0xFFFFFFFF)


def push_recent_events(rows: List[Dict[str, Any]]) -> int:
    r = get_redis()
    if r is None or not rows:
        return 0

    max_global = max(100, int(getattr(settings, "SEAGULL_INGEST_RECENT_FEED_MAX_EVENTS", 5000) or 5000))
    max_agent = max(50, int(getattr(settings, "SEAGULL_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS", 1000) or 1000))
    lookback_s = max(60, int(getattr(settings, "SEAGULL_INGEST_RECENT_FEED_LOOKBACK_SECONDS", 900) or 900))
    max_push = max(1, int(getattr(settings, "SEAGULL_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL", 512) or 512))
    original_n = len(rows)
    rows = list(rows[:max_push])

    pipe = r.pipeline()
    pushed = 0
    max_ts_global: datetime | None = None
    max_ts_by_agent: Dict[str, datetime] = {}
    for row in rows:
        ts = _to_ts(row.get("timestamp"))
        if ts is None:
            continue
        payload = {
            "id": int(row.get("id") or 0) or _event_id(row),
            "timestamp": ts.isoformat(),
            "agent_id": str(row.get("agent_id") or ""),
            "event_type": str(row.get("event_type") or ""),
            "src_ip": row.get("src_ip"),
            "dst_ip": row.get("dst_ip"),
            "src_port": row.get("src_port"),
            "dst_port": row.get("dst_port"),
            "proto": row.get("proto"),
            "bytes": row.get("bytes"),
            "schema_version": int(row.get("schema_version") or 1),
            "extra": _compact_extra(row.get("extra") or {}),
        }
        raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str)
        pipe.lpush(_feed_key(None), raw)
        pipe.ltrim(_feed_key(None), 0, max_global - 1)
        agent_id = payload["agent_id"]
        if agent_id:
            pipe.lpush(_feed_key(agent_id), raw)
            pipe.ltrim(_feed_key(agent_id), 0, max_agent - 1)
            prev_agent_ts = max_ts_by_agent.get(agent_id)
            if prev_agent_ts is None or ts > prev_agent_ts:
                max_ts_by_agent[agent_id] = ts
        if max_ts_global is None or ts > max_ts_global:
            max_ts_global = ts
        pushed += 1

    if pushed <= 0:
        return 0

    ts_s = int(datetime.now(timezone.utc).timestamp())
    rate_key = _feed_rate_key(ts_s)
    dropped_key = _feed_drop_key(ts_s)
    pipe.incrby(rate_key, int(pushed))
    pipe.expire(rate_key, 30)
    dropped_n = max(0, int(original_n) - int(pushed))
    if dropped_n > 0:
        pipe.incrby(dropped_key, int(dropped_n))
        pipe.expire(dropped_key, 30)
    if max_ts_global is not None:
        pipe.setex(_feed_last_ts_key(None), max(120, lookback_s * 2), max_ts_global.isoformat())
    for aid, ts in max_ts_by_agent.items():
        pipe.setex(_feed_last_ts_key(aid), max(120, lookback_s * 2), ts.isoformat())

    try:
        pipe.execute()
    except Exception:
        return 0
    return pushed


def fetch_recent_events(*, limit: int, agent_id: str | None = None, event_type: str | None = None) -> List[Dict[str, Any]]:
    r = get_redis()
    if r is None:
        return []

    fetch_n = max(int(limit) * 4, 100)
    fetch_n = min(fetch_n, 2000)
    try:
        rows = r.lrange(_feed_key(agent_id), 0, fetch_n - 1) or []
    except Exception:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=max(60, int(getattr(settings, "SEAGULL_INGEST_RECENT_FEED_LOOKBACK_SECONDS", 900) or 900))
    )
    out: List[Dict[str, Any]] = []
    seen: set[int] = set()
    for raw in rows:
        try:
            item = json.loads(raw)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        ts = _to_ts(item.get("timestamp"))
        if ts is None or ts < cutoff:
            continue
        if event_type and str(item.get("event_type") or "") != str(event_type):
            continue
        row_id = int(item.get("id") or 0)
        if row_id in seen:
            continue
        seen.add(row_id)
        out.append(item)
        if len(out) >= int(limit):
            break
    return out


def fetch_event_by_id(*, event_id: int, agent_id: str | None = None) -> Dict[str, Any] | None:
    r = get_redis()
    if r is None:
        return None

    scan_n = (
        max(50, int(getattr(settings, "SEAGULL_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS", 1000) or 1000))
        if agent_id
        else max(100, int(getattr(settings, "SEAGULL_INGEST_RECENT_FEED_MAX_EVENTS", 5000) or 5000))
    )
    scan_n = min(scan_n, 10000)

    try:
        rows = r.lrange(_feed_key(agent_id), 0, scan_n - 1) or []
    except Exception:
        return None

    target_id = int(event_id)
    for raw in rows:
        try:
            item = json.loads(raw)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        try:
            row_id = int(item.get("id") or 0)
        except Exception:
            continue
        if row_id == target_id:
            return item
    return None


def recent_feed_health(*, agent_id: str | None = None) -> Dict[str, Any]:
    r = get_redis()
    if r is None:
        return {
            "last_event_ts": None,
            "freshness_seconds": None,
            "events_last_second": 0,
            "dropped_last_second": 0,
        }

    last_ts_iso = None
    freshness_seconds = None
    events_last_second = 0
    dropped_last_second = 0

    try:
        last_ts_iso = r.get(_feed_last_ts_key(agent_id)) or r.get(_feed_last_ts_key(None))
    except Exception:
        last_ts_iso = None
    try:
        now_s = int(datetime.now(timezone.utc).timestamp())
        prev_s = max(0, now_s - 1)
        events_last_second = int(r.get(_feed_rate_key(prev_s)) or 0)
        dropped_last_second = int(r.get(_feed_drop_key(prev_s)) or 0)
        if events_last_second <= 0 and dropped_last_second <= 0:
            events_last_second = int(r.get(_feed_rate_key(now_s)) or 0)
            dropped_last_second = int(r.get(_feed_drop_key(now_s)) or 0)
    except Exception:
        events_last_second = 0
        dropped_last_second = 0

    ts = _to_ts(last_ts_iso)
    if ts is not None:
        freshness_seconds = max(0, int((datetime.now(timezone.utc) - ts).total_seconds()))
        last_ts_iso = ts.isoformat()

    return {
        "last_event_ts": last_ts_iso,
        "freshness_seconds": freshness_seconds,
        "events_last_second": int(max(0, events_last_second)),
        "dropped_last_second": int(max(0, dropped_last_second)),
    }
