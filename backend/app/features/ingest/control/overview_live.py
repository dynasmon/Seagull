from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.cache import get_redis
from app.core.observability import incr_counter, log_event
from app.features.ingest.control.queue_keys import (
    _as_float,
    _as_int,
    _env_int,
    _overview_live_dropped_key,
    _overview_live_key,
    _safe_text,
)

logger = logging.getLogger("seagull.ingest.control")

MIN_EVENT_TYPES_PER_SECOND = 4


def max_event_types_per_second() -> int:
    return max(
        MIN_EVENT_TYPES_PER_SECOND,
        _env_int("SEAGULL_OVERVIEW_LIVE_MAX_EVENT_TYPES_PER_SECOND", 16),
    )


def record_overview_live_telemetry(
    *,
    ingest_received: int,
    processed_events: int = 0,
    bytes_sum: int = 0,
    event_type_counts: Optional[Dict[str, int]] = None,
    severity_counts: Optional[Dict[str, int]] = None,
    ddos_packets_estimated: int = 0,
    ddos_samples: int = 0,
    ddos_peak_pps: float = 0.0,
    ddos_peak_bps: float = 0.0,
    ddos_peak_syn_ratio: float = 0.0,
    ddos_peak_flow_rps: float = 0.0,
    dropped_event_type_counts: int = 0,
    bucket_ts: Optional[datetime] = None,
) -> bool:

    r = get_redis()
    if r is None:
        incr_counter("overview_live_write_failed_total", reason="redis_unavailable")
        return False

    ts_s = int((bucket_ts or datetime.now(timezone.utc)).timestamp())
    key = _overview_live_key(ts_s)
    retention_s = max(60, _env_int("SEAGULL_OVERVIEW_LIVE_RETENTION_SECONDS", 1800))
    max_event_types = max_event_types_per_second()

    try:
        pipe = r.pipeline()
        pipe.hincrby(key, "ingest_received", max(0, int(ingest_received)))
        pipe.hincrby(key, "processed_events", max(0, int(processed_events)))
        pipe.hincrby(key, "bytes_sum", max(0, int(bytes_sum)))
        pipe.hincrby(key, "ddos_packets_estimated", max(0, int(ddos_packets_estimated)))
        pipe.hincrby(key, "ddos_samples", max(0, int(ddos_samples)))
        pipe.hincrby(key, "dropped_event_type_counts", max(0, int(dropped_event_type_counts)))

        if ddos_peak_pps > 0:
            pipe.hset(key, "ddos_peak_pps", f"{max(0.0, float(ddos_peak_pps)):.6f}")
        if ddos_peak_bps > 0:
            pipe.hset(key, "ddos_peak_bps", f"{max(0.0, float(ddos_peak_bps)):.6f}")
        if ddos_peak_syn_ratio > 0:
            pipe.hset(key, "ddos_peak_syn_ratio", f"{max(0.0, float(ddos_peak_syn_ratio)):.6f}")
        if ddos_peak_flow_rps > 0:
            pipe.hset(key, "ddos_peak_flow_rps", f"{max(0.0, float(ddos_peak_flow_rps)):.6f}")

        sev = {str(k or "").strip().lower(): int(v or 0) for k, v in (severity_counts or {}).items()}
        for key_name in ("critical", "high", "medium", "low", "unknown"):
            count = max(0, int(sev.get(key_name, 0)))
            if count > 0:
                pipe.hincrby(key, f"sev:{key_name}", count)

        evt_items = sorted(
            (
                (str(k or "").strip().lower(), max(0, int(v or 0)))
                for k, v in (event_type_counts or {}).items()
                if str(k or "").strip()
            ),
            key=lambda kv: kv[1],
            reverse=True,
        )
        kept = 0
        dropped = 0
        for ev_type, count in evt_items:
            if count <= 0:
                continue
            if kept < max_event_types:
                pipe.hincrby(key, f"et:{ev_type}", count)
                kept += 1
            else:
                dropped += count
        if dropped > 0:
            pipe.hincrby(key, "dropped_event_type_counts", int(dropped))

        pipe.hset(key, mapping={"bucket_ts": str(ts_s), "updated_at": str(int(time.time()))})
        pipe.expire(key, retention_s)
        pipe.execute()
        return True
    except Exception as exc:
        incr_counter("overview_live_write_failed_total", reason=type(exc).__name__)
        log_event(logger, "warning", "overview_live_write_failed", error_type=type(exc).__name__)
        return False


def record_overview_live_drop(*, dropped_events: int, bucket_ts: Optional[datetime] = None) -> None:
    r = get_redis()
    if r is None:
        return
    ts_s = int((bucket_ts or datetime.now(timezone.utc)).timestamp())
    key = _overview_live_dropped_key(ts_s)
    try:
        pipe = r.pipeline()
        pipe.incrby(key, max(0, int(dropped_events)))
        pipe.expire(key, max(60, _env_int("SEAGULL_OVERVIEW_LIVE_RETENTION_SECONDS", 1800)))
        pipe.execute()
    except Exception:
        return


def read_overview_live_last_ts(*, lookback_s: int = 15) -> Optional[datetime]:
    r = get_redis()
    if r is None:
        return None
    end_s = int(time.time())
    points = list(range(end_s, max(0, end_s - max(1, int(lookback_s))), -1))
    try:
        pipe = r.pipeline()
        for ts in points:
            pipe.exists(_overview_live_key(ts))
        flags = list(pipe.execute() or [])
    except Exception:
        return None
    for ts, flag in zip(points, flags, strict=False):
        if flag:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
    return None


def read_overview_live_window(*, now_s: Optional[int] = None, seconds: int = 900) -> Dict[str, Any]:

    r = get_redis()
    if r is None:
        return {
            "rows": [],
            "last_data_ts": None,
            "freshness_seconds": None,
            "ddos_samples_last_second": 0,
            "dropped_last_second": 0,
        }

    end_s = max(1, int(now_s or time.time()))
    max_seconds = max(30, _env_int("SEAGULL_OVERVIEW_LIVE_READ_MAX_SECONDS", 900))
    span = max(1, min(int(seconds), int(max_seconds)))
    start_s = max(1, end_s - span + 1)

    points = list(range(start_s, end_s + 1))
    rows_raw: List[Dict[Any, Any]] = []

    try:
        pipe = r.pipeline()
        for ts in points:
            pipe.hgetall(_overview_live_key(ts))
        rows_raw = list(pipe.execute() or [])
    except Exception:
        rows_raw = []

    rows: List[Dict[str, Any]] = []
    last_data_s: Optional[int] = None
    for ts, raw in zip(points, rows_raw, strict=False):
        if not raw:
            continue
        parsed: Dict[str, Any] = {
            "ts": datetime.fromtimestamp(int(ts), tz=timezone.utc),
            "ingest_received": 0,
            "processed_events": 0,
            "bytes_sum": 0,
            "ddos_packets_estimated": 0,
            "ddos_samples": 0,
            "ddos_peak_pps": 0.0,
            "ddos_peak_bps": 0.0,
            "ddos_peak_syn_ratio": 0.0,
            "ddos_peak_flow_rps": 0.0,
            "dropped_event_type_counts": 0,
            "event_types": {},
            "severity": {},
        }

        for raw_key, raw_val in dict(raw).items():
            key = _safe_text(raw_key)
            val = _safe_text(raw_val)
            if not key:
                continue
            if key == "ingest_received":
                parsed["ingest_received"] = max(0, _as_int(val, 0))
            elif key == "processed_events":
                parsed["processed_events"] = max(0, _as_int(val, 0))
            elif key == "bytes_sum":
                parsed["bytes_sum"] = max(0, _as_int(val, 0))
            elif key == "ddos_packets_estimated":
                parsed["ddos_packets_estimated"] = max(0, _as_int(val, 0))
            elif key == "ddos_samples":
                parsed["ddos_samples"] = max(0, _as_int(val, 0))
            elif key == "ddos_peak_pps":
                parsed["ddos_peak_pps"] = max(0.0, _as_float(val, 0.0))
            elif key == "ddos_peak_bps":
                parsed["ddos_peak_bps"] = max(0.0, _as_float(val, 0.0))
            elif key == "ddos_peak_syn_ratio":
                parsed["ddos_peak_syn_ratio"] = max(0.0, _as_float(val, 0.0))
            elif key == "ddos_peak_flow_rps":
                parsed["ddos_peak_flow_rps"] = max(0.0, _as_float(val, 0.0))
            elif key == "dropped_event_type_counts":
                parsed["dropped_event_type_counts"] = max(0, _as_int(val, 0))
            elif key.startswith("et:"):
                ev_type = key[3:].strip()
                if ev_type:
                    parsed["event_types"][ev_type] = max(0, _as_int(val, 0))
            elif key.startswith("sev:"):
                sev = key[4:].strip().lower()
                if sev:
                    parsed["severity"][sev] = max(0, _as_int(val, 0))

        has_signal = (
            int(parsed["ingest_received"]) > 0
            or int(parsed["processed_events"]) > 0
            or int(parsed["ddos_packets_estimated"]) > 0
            or int(parsed["ddos_samples"]) > 0
            or bool(parsed["event_types"])
        )
        if not has_signal:
            continue
        rows.append(parsed)
        last_data_s = int(ts)

    dropped_last_second = 0
    try:
        dropped_last_second = max(0, _as_int(r.get(_overview_live_dropped_key(end_s)), 0))
    except Exception:
        dropped_last_second = 0

    freshness = (end_s - last_data_s) if last_data_s is not None else None
    ddos_samples_last_second = 0
    if rows and last_data_s is not None and rows[-1]["ts"].timestamp() == float(last_data_s):
        ddos_samples_last_second = int(rows[-1].get("ddos_samples") or 0)

    return {
        "rows": rows,
        "last_data_ts": datetime.fromtimestamp(last_data_s, tz=timezone.utc).isoformat() if last_data_s is not None else None,
        "freshness_seconds": int(max(0, freshness)) if freshness is not None else None,
        "ddos_samples_last_second": int(max(0, ddos_samples_last_second)),
        "dropped_last_second": int(max(0, dropped_last_second)),
    }
