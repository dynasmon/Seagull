from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from app.core.config import settings
from app.core.db import engine
from app.core.observability import incr_counter, log_event
from app.core.recent_feed import recent_feed_health
from app.core.redis_client import get_redis
from app.features.alerts.models import AlertModel
from app.features.alerts.realtime import publish_alert_created_payload, publish_alert_updated_payload
from app.features.events.models import IngestStats1sModel

logger = logging.getLogger("netwatch.ingest.control")


def _env_int(name: str, default: int) -> int:
    v = getattr(settings, name, None)
    if v is None:
        return default
    try:
        return int(v)
    except Exception:
        return default


def _env_str(name: str, default: str) -> str:
    v = getattr(settings, name, None)
    if v is None:
        return default
    s = str(v).strip()
    return s if s else default


def _env_bool(name: str, default: bool) -> bool:
    v = getattr(settings, name, None)
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


# Redis keys

def queue_key() -> str:
    return _env_str("NETWATCH_INGEST_QUEUE_KEY", "netwatch:ingest:queue")


def processing_key() -> str:
    qk = queue_key()
    return _env_str("NETWATCH_INGEST_PROCESSING_KEY", f"{qk}:processing")


def backlog_events_key() -> str:
    return _env_str("NETWATCH_INGEST_BACKLOG_EVENTS_KEY", "netwatch:ingest:backlog_events")


def _eps_key(ts_s: int) -> str:
    return f"netwatch:ingest:eps:{ts_s}"


def _stats_key(ts_s: int) -> str:
    return f"netwatch:ingest:stats:{ts_s}"


def _flush_lock_key(ts_s: int) -> str:
    return f"netwatch:ingest:flush:{ts_s}"


def storm_active_key() -> str:
    return _env_str("NETWATCH_INGEST_STORM_ACTIVE_KEY", "netwatch:ingest:storm_active")


def storm_session_key() -> str:
    return _env_str("NETWATCH_INGEST_STORM_SESSION_KEY", "netwatch:ingest:storm_session")


def storm_since_key() -> str:
    return _env_str("NETWATCH_INGEST_STORM_SINCE_KEY", "netwatch:ingest:storm_since")


def storm_alert_id_key() -> str:
    return _env_str("NETWATCH_INGEST_STORM_ALERT_ID_KEY", "netwatch:ingest:storm_alert_id")


def _events_per_msg_avg_key() -> str:
    return "netwatch:ingest:events_per_msg_avg"


def _worker_eps_key(ts_s: int) -> str:
    return f"netwatch:ingest:worker:eps:{ts_s}"


def _worker_msgs_key(ts_s: int) -> str:
    return f"netwatch:ingest:worker:msgs:{ts_s}"


def _worker_hb_key(worker_id: str) -> str:
    return f"netwatch:ingest:worker:hb:{worker_id}"


def _pressure_state_key() -> str:
    return "netwatch:ingest:pressure_state"


def _quality_key(ts_s: int) -> str:
    return f"netwatch:ingest:quality:{ts_s}"


def _overview_live_key(ts_s: int) -> str:
    return f"netwatch:overview:live:1s:{ts_s}"


def _overview_live_dropped_key(ts_s: int) -> str:
    return f"netwatch:overview:live:dropped:{ts_s}"


def _sink_counter_key(*, sink: str, metric: str, ts_s: int) -> str:
    return f"netwatch:ingest:sink:{sink}:{metric}:{ts_s}"


def _sink_depth_key(*, sink: str) -> str:
    return f"netwatch:ingest:sink:{sink}:queue_depth"


def _safe_text(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return str(value or "")


@dataclass(frozen=True)
class BackpressureDecision:
    mode: str  # normal | rollup_only | reject_429
    reason: str
    backlog_events: int
    backlog_messages: int


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _as_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _update_events_per_msg_avg(r, sample_events_per_message: float) -> None:
    if sample_events_per_message <= 0:
        return
    try:
        key = _events_per_msg_avg_key()
        cur = _as_float(r.get(key), 1.0)
        nxt = (cur * 0.96) + (float(sample_events_per_message) * 0.04)
        if nxt < 1.0:
            nxt = 1.0
        r.setex(key, 3600, f"{nxt:.6f}")
    except Exception:
        return


def get_backlog() -> Tuple[int, int]:
    """Return (backlog_messages, backlog_events) best-effort."""

    r = get_redis()
    if r is None:
        return 0, 0

    try:
        # Include items being processed by the worker.
        msgs = int(r.llen(queue_key())) + int(r.llen(processing_key()))
    except Exception:
        msgs = 0

    key = backlog_events_key()
    try:
        ev = _as_int(r.get(key), 0)
    except Exception:
        ev = 0

    # Self-heal common drift scenarios so pressure state can recover:
    # - zero messages but stale positive event counter
    # - counter far above plausible envelope for current queue depth
    try:
        avg = max(1.0, _as_float(r.get(_events_per_msg_avg_key()), 1.0))
        if msgs <= 0:
            if ev > 0:
                r.set(key, 0)
            ev = 0
        else:
            if ev < msgs:
                ev = msgs
                r.set(key, ev)
            else:
                plausible_upper = int(max(msgs * 10, msgs * avg * 8.0))
                if ev > plausible_upper:
                    ev = int(max(msgs, round(msgs * avg)))
                    r.set(key, ev)
    except Exception:
        pass

    # Never expose negative backlog values: they break backpressure decisions
    # and cause the platform to oscillate under load.
    return msgs, max(0, ev)


def evaluate_backpressure(*, received: int) -> BackpressureDecision:
    """Decide how to handle ingestion based on Redis backlog.

    - soft limit: switch to rollup_only (default)
    - hard limit: reject 429 or rollup_only depending on NETWATCH_INGEST_BACKPRESSURE_MODE
    """

    soft = max(1, _env_int("NETWATCH_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS", 50_000))
    hard = max(soft + 1, _env_int("NETWATCH_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS", 200_000))
    soft_exit = max(0, _env_int("NETWATCH_INGEST_BACKPRESSURE_SOFT_EXIT_BACKLOG_EVENTS", int(soft * 0.6)))
    hard_exit = max(soft + 1, _env_int("NETWATCH_INGEST_BACKPRESSURE_HARD_EXIT_BACKLOG_EVENTS", int(hard * 0.75)))
    force_normal_max_msgs = max(0, _env_int("NETWATCH_INGEST_BACKPRESSURE_FORCE_NORMAL_MAX_MESSAGES", 4))
    mode = _env_str("NETWATCH_INGEST_BACKPRESSURE_MODE", "rollup_only").lower().strip()
    mode = mode if mode in {"rollup_only", "reject_429"} else "rollup_only"

    msgs, ev = get_backlog()
    r = get_redis()

    # Compute projected backlog to avoid races.
    projected = ev + max(0, int(received))
    prev_bp = ""
    if r is not None:
        try:
            prev_bp = str(r.get("netwatch:ingest:bp_mode") or "").strip().lower()
        except Exception:
            prev_bp = ""

    selected = "normal"
    reason = "ok"

    if projected >= hard:
        selected = "reject_429" if mode == "reject_429" else "rollup_only"
        reason = "hard_backlog"
    elif projected >= soft:
        selected = "rollup_only"
        reason = "soft_backlog"
    elif prev_bp == "reject_429" and projected >= hard_exit:
        selected = "reject_429" if mode == "reject_429" else "rollup_only"
        reason = "hard_backlog_hysteresis"
    elif prev_bp in {"reject_429", "rollup_only"} and projected >= soft_exit:
        selected = "rollup_only"
        reason = "soft_backlog_hysteresis"

    # Recovery fast-path:
    # if queue depth is already tiny, do not keep normal traffic in rollup_only
    # just because a stale event counter is slightly above the soft-exit threshold.
    if selected != "normal" and projected < soft and msgs <= force_normal_max_msgs:
        selected = "normal"
        reason = "recovery_small_queue"

    if r is not None:
        try:
            r.setex("netwatch:ingest:bp_mode", 30, selected)
        except Exception:
            pass

    return BackpressureDecision(mode=selected, reason=reason, backlog_events=ev, backlog_messages=msgs)


def enqueue_ingest_message(*, message: Dict[str, Any], received: int) -> bool:
    r = get_redis()
    if r is None:
        return False

    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False)

    try:
        pipe = r.pipeline()
        pipe.rpush(queue_key(), payload)
        pipe.incrby(backlog_events_key(), int(received))
        pipe.execute()
        _update_events_per_msg_avg(r, float(max(1, int(received))))
        return True
    except Exception:
        return False


def bump_ingest_counters(*, received: int, hot_kept: int, warm_kept: int, dropped: int, rejected: int, rollup_only: int, storm_active: bool, sample_hot: int, sample_warm: int) -> None:
    """Aggregate per-second metrics in Redis (best-effort)."""

    r = get_redis()
    if r is None:
        return

    ts_s = int(time.time())

    try:
        pipe = r.pipeline()
        pipe.incrby(_eps_key(ts_s), int(received))
        pipe.expire(_eps_key(ts_s), 5)

        hk = _stats_key(ts_s)
        pipe.hincrby(hk, "received", int(received))
        pipe.hincrby(hk, "hot_kept", int(hot_kept))
        pipe.hincrby(hk, "warm_kept", int(warm_kept))
        pipe.hincrby(hk, "dropped", int(dropped))
        pipe.hincrby(hk, "rejected", int(rejected))
        pipe.hincrby(hk, "rollup_only", int(rollup_only))
        # Best-effort last-known values (not counters)
        pipe.hset(hk, mapping={
            "storm_active": "1" if storm_active else "0",
            "sample_hot": str(int(sample_hot)),
            "sample_warm": str(int(sample_warm)),
        })
        pipe.expire(hk, 180)

        pipe.execute()
    except Exception:
        return


def record_ingest_quality(*, breakdown: Dict[str, Dict[str, int]]) -> None:
    """Record short-lived per-event-type ingest quality counters (best-effort)."""

    if not isinstance(breakdown, dict) or not breakdown:
        return

    r = get_redis()
    if r is None:
        return

    ts_s = int(time.time())
    key = _quality_key(ts_s)
    try:
        pipe = r.pipeline()
        # Keep only a bounded number of event_type buckets per second.
        items = sorted(
            (
                (str(k or "").strip().lower(), v if isinstance(v, dict) else {})
                for k, v in breakdown.items()
            ),
            key=lambda kv: int((kv[1] or {}).get("received") or 0),
            reverse=True,
        )
        for event_type, vals in items[:24]:
            if not event_type:
                continue
            rec = max(0, int(vals.get("received") or 0))
            hot = max(0, int(vals.get("hot") or 0))
            warm = max(0, int(vals.get("warm") or 0))
            analytics = max(0, int(vals.get("analytics") or 0))
            if rec <= 0 and hot <= 0 and warm <= 0 and analytics <= 0:
                continue
            pipe.hincrby(key, f"{event_type}:received", rec)
            pipe.hincrby(key, f"{event_type}:hot", hot)
            pipe.hincrby(key, f"{event_type}:warm", warm)
            pipe.hincrby(key, f"{event_type}:analytics", analytics)
        pipe.expire(key, 180)
        pipe.execute()
    except Exception:
        return


def _read_ingest_quality_window(*, now_s: int, seconds: int = 15) -> list[Dict[str, Any]]:
    r = get_redis()
    if r is None:
        return []

    start = max(0, int(now_s) - max(1, int(seconds)) + 1)
    acc: Dict[str, Dict[str, int]] = {}
    try:
        for ts in range(start, int(now_s) + 1):
            fields = r.hgetall(_quality_key(ts)) or {}
            for raw_key, raw_val in fields.items():
                try:
                    key = str(raw_key)
                    val = int(raw_val or 0)
                except Exception:
                    continue
                if ":" not in key:
                    continue
                ev_type, metric = key.rsplit(":", 1)
                if metric not in {"received", "hot", "warm", "analytics"}:
                    continue
                bucket = acc.setdefault(ev_type, {"received": 0, "hot": 0, "warm": 0, "analytics": 0})
                bucket[metric] = int(bucket.get(metric) or 0) + max(0, int(val))
    except Exception:
        return []

    out: list[Dict[str, Any]] = []
    for ev_type, vals in acc.items():
        received = max(0, int(vals.get("received") or 0))
        hot = max(0, int(vals.get("hot") or 0))
        warm = max(0, int(vals.get("warm") or 0))
        analytics = max(0, int(vals.get("analytics") or 0))
        kept = hot + warm
        dropped = max(0, received - kept)

        out.append(
            {
                "event_type": ev_type,
                "received": received,
                "hot_kept": hot,
                "warm_kept": warm,
                "analytics_kept": analytics,
                "dropped_estimated": dropped,
                "kept_percent": int(round((kept / received) * 100.0)) if received > 0 else 0,
                "drop_percent": int(round((dropped / received) * 100.0)) if received > 0 else 0,
                "analytics_percent": int(round((analytics / received) * 100.0)) if received > 0 else 0,
            }
        )
    out.sort(key=lambda x: (int(x.get("received") or 0), int(x.get("hot_kept") or 0)), reverse=True)
    return out[:8]


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
    """Record short-lived live telemetry buckets used by overview fallback charts."""

    r = get_redis()
    if r is None:
        incr_counter("overview_live_write_failed_total", reason="redis_unavailable")
        return False

    ts_s = int((bucket_ts or datetime.now(timezone.utc)).timestamp())
    key = _overview_live_key(ts_s)
    retention_s = max(60, _env_int("NETWATCH_OVERVIEW_LIVE_RETENTION_SECONDS", 1800))
    max_event_types = max(4, _env_int("NETWATCH_OVERVIEW_LIVE_MAX_EVENT_TYPES_PER_SECOND", 16))

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
        pipe.expire(key, max(60, _env_int("NETWATCH_OVERVIEW_LIVE_RETENTION_SECONDS", 1800)))
        pipe.execute()
    except Exception:
        return


def read_overview_live_window(*, now_s: Optional[int] = None, seconds: int = 900) -> Dict[str, Any]:
    """Read a bounded live telemetry window from Redis."""

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
    max_seconds = max(30, _env_int("NETWATCH_OVERVIEW_LIVE_READ_MAX_SECONDS", 900))
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
    for ts, raw in zip(points, rows_raw):
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


def record_sink_runtime_metric(*, sink: str, metric: str, value: int) -> None:
    r = get_redis()
    if r is None:
        return
    ts_s = int(time.time())
    key = _sink_counter_key(sink=str(sink), metric=str(metric), ts_s=ts_s)
    try:
        pipe = r.pipeline()
        pipe.incrby(key, max(0, int(value)))
        pipe.expire(key, 30)
        pipe.execute()
    except Exception:
        return


def set_sink_queue_depth(*, sink: str, depth: int) -> None:
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(_sink_depth_key(sink=str(sink)), 30, str(max(0, int(depth))))
    except Exception:
        return


def record_worker_progress(*, processed_events: int, processed_messages: int) -> None:
    r = get_redis()
    if r is None:
        return

    ts_s = int(time.time())
    ev = max(0, int(processed_events))
    msgs = max(0, int(processed_messages))
    try:
        pipe = r.pipeline()
        pipe.incrby(_worker_eps_key(ts_s), ev)
        pipe.expire(_worker_eps_key(ts_s), 10)
        pipe.incrby(_worker_msgs_key(ts_s), msgs)
        pipe.expire(_worker_msgs_key(ts_s), 10)
        pipe.hincrby(_overview_live_key(ts_s), "processed_events", ev)
        pipe.expire(_overview_live_key(ts_s), max(60, _env_int("NETWATCH_OVERVIEW_LIVE_RETENTION_SECONDS", 1800)))
        pipe.execute()
        if msgs > 0:
            _update_events_per_msg_avg(r, ev / float(msgs))
    except Exception:
        return


def worker_heartbeat(worker_id: str, *, ttl_seconds: int = 8) -> None:
    if not worker_id:
        return
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(_worker_hb_key(worker_id), max(2, int(ttl_seconds)), str(int(time.time())))
    except Exception:
        return


def count_active_workers() -> int:
    r = get_redis()
    if r is None:
        return 0
    try:
        # This is a tiny keyspace (ingest workers), so SCAN is cheap.
        n = 0
        for _ in r.scan_iter(match="netwatch:ingest:worker:hb:*", count=64):
            n += 1
        return max(0, int(n))
    except Exception:
        return 0


def maybe_flush_stats_to_db() -> None:
    """Flush the previous second's Redis stats to Postgres (at most once per second).

    We use a per-second Redis lock so only one request performs the DB upsert.
    """

    r = get_redis()
    if r is None:
        return

    now_s = int(time.time())
    ts_s = now_s - 1

    # Acquire lock
    try:
        if not r.set(_flush_lock_key(ts_s), "1", nx=True, ex=3):
            return
    except Exception:
        return

    hk = _stats_key(ts_s)
    try:
        data = r.hgetall(hk) or {}
    except Exception:
        data = {}

    if not data:
        return

    # Backlog snapshot
    backlog_msgs, backlog_ev = get_backlog()

    received = _as_int(data.get("received"))
    hot_kept = _as_int(data.get("hot_kept"))
    warm_kept = _as_int(data.get("warm_kept"))
    dropped = _as_int(data.get("dropped"))
    rejected = _as_int(data.get("rejected"))
    rollup_only = _as_int(data.get("rollup_only"))

    storm_active = str(data.get("storm_active") or "0") == "1"
    sample_hot = max(0, min(_as_int(data.get("sample_hot") or 100), 100))
    sample_warm = max(0, min(_as_int(data.get("sample_warm") or 0), 100))

    bucket_ts = datetime.fromtimestamp(ts_s, tz=timezone.utc).replace(microsecond=0)

    try:
        ins = insert(IngestStats1sModel).values(
            bucket_ts=bucket_ts,
            received=received,
            hot_stored=hot_kept,
            warm_indexed=warm_kept,
            dropped=dropped,
            rejected=rejected,
            rollup_only=rollup_only,
            backlog_messages=backlog_msgs,
            backlog_events=backlog_ev,
            storm_active=storm_active,
            sample_hot_percent=sample_hot,
            sample_warm_percent=sample_warm,
        )
        upsert = ins.on_conflict_do_update(
            index_elements=[IngestStats1sModel.bucket_ts],
            set_={
                "received": IngestStats1sModel.received + ins.excluded.received,
                "hot_stored": IngestStats1sModel.hot_stored + ins.excluded.hot_stored,
                "warm_indexed": IngestStats1sModel.warm_indexed + ins.excluded.warm_indexed,
                "dropped": IngestStats1sModel.dropped + ins.excluded.dropped,
                "rejected": IngestStats1sModel.rejected + ins.excluded.rejected,
                "rollup_only": IngestStats1sModel.rollup_only + ins.excluded.rollup_only,
                # Backlog and sampling must reflect latest snapshot, not peak.
                "backlog_messages": ins.excluded.backlog_messages,
                "backlog_events": ins.excluded.backlog_events,
                "storm_active": ins.excluded.storm_active,
                "sample_hot_percent": ins.excluded.sample_hot_percent,
                "sample_warm_percent": ins.excluded.sample_warm_percent,
                "updated_at": datetime.now(timezone.utc),
            },
        )
        with engine.begin() as conn:
            conn.execute(upsert)
    except Exception:
        # fail open
        return


def mark_storm_active(*, reason: str, sample_hot: int, sample_warm: int) -> None:
    r = get_redis()
    if r is None:
        return

    ttl_s = _env_int("NETWATCH_INGEST_STORM_TTL_SECONDS", 20)

    try:
        pipe = r.pipeline()
        pipe.setex(storm_active_key(), ttl_s, "1")
        pipe.setex("netwatch:ingest:storm_reason", ttl_s, (reason or "storm")[:64])
        pipe.setex("netwatch:ingest:storm_sample_hot", ttl_s, str(int(sample_hot)))
        pipe.setex("netwatch:ingest:storm_sample_warm", ttl_s, str(int(sample_warm)))
        pipe.execute()
    except Exception:
        return


def storm_maybe_open_alert(*, reason: str, sample_hot: int, sample_warm: int) -> None:
    """Open a single 'Ingest Storm Detected' alert per storm session."""

    r = get_redis()
    if r is None:
        return

    # If an alert id is cached, verify it still exists in Postgres.
    # This protects us from stale Redis keys after crashes or manual DB resets.
    try:
        existing = (r.get(storm_alert_id_key()) or "").strip()
        if existing:
            try:
                eid = int(existing)
                with engine.begin() as conn:
                    ok = conn.execute(select(AlertModel.id).where(AlertModel.id == eid).limit(1)).first()
                if ok:
                    return
                # stale key: allow re-open
                r.delete(storm_alert_id_key())
            except Exception:
                try:
                    r.delete(storm_alert_id_key())
                except Exception:
                    pass
    except Exception:
        return

    # Small lock to avoid stampeding Postgres under heavy load.
    lock_key = "netwatch:ingest:storm_alert_open_lock"
    try:
        if not r.set(lock_key, "1", nx=True, ex=5):
            return
    except Exception:
        return

    now = datetime.now(timezone.utc)

    # Reuse session metadata if already created (important for retries).
    try:
        session_id = (r.get(storm_session_key()) or "").strip()
        since_iso = (r.get(storm_since_key()) or "").strip()
    except Exception:
        session_id, since_iso = "", ""

    if not session_id:
        session_id = str(uuid.uuid4())
        try:
            r.setnx(storm_session_key(), session_id)
        except Exception:
            pass

    if not since_iso:
        since_iso = now.isoformat()
        try:
            r.setnx(storm_since_key(), since_iso)
        except Exception:
            pass

    details = {
        "storm": {
            "session_id": session_id,
            "started_at": since_iso,
            "reason": reason,
            "sample_hot_percent": int(sample_hot),
            "sample_warm_percent": int(sample_warm),
        },
        "timeline": [],
    }

    # Insert alert in Postgres (rare path).
    try:
        with engine.begin() as conn:
            row = conn.execute(
                insert(AlertModel)
                .values(
                    created_at=now,
                    rule_id="system.ingest_storm",
                    severity="high",
                    mitre_tactic="impact",
                    mitre_technique_id="T1498",
                    mitre_technique="Network Denial of Service",
                    confidence=85,
                    description="Ingest Storm Detected",
                    details=details,
                )
                .returning(AlertModel.id)
            ).fetchone()
            alert_id = int(row[0]) if row else 0

        if alert_id:
            r.setex(storm_alert_id_key(), _env_int("NETWATCH_INGEST_STORM_ALERT_TTL_SECONDS", 3600), str(alert_id))
            publish_alert_created_payload(
                {
                    "alert_id": int(alert_id),
                    "created_at": now.isoformat(),
                    "rule_id": "system.ingest_storm",
                    "severity": "high",
                    "description": "Ingest Storm Detected",
                }
            )
    except Exception:
        # fail open; the lock will expire and we can retry later
        return
    finally:
        try:
            r.delete(lock_key)
        except Exception:
            pass


def storm_maybe_close_alert() -> None:
    """Finalize an open storm alert if the storm has ended."""

    r = get_redis()
    if r is None:
        return

    try:
        active = bool(r.get(storm_active_key()))
        alert_id_raw = r.get(storm_alert_id_key())
        since_iso = r.get(storm_since_key())
    except Exception:
        return

    if active or not alert_id_raw or not since_iso:
        return

    try:
        alert_id = int(alert_id_raw)
    except Exception:
        return

    try:
        start = datetime.fromisoformat(since_iso)
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
    except Exception:
        start = datetime.now(timezone.utc) - timedelta(minutes=10)  # type: ignore[name-defined]

    end = datetime.now(timezone.utc)

    # Pull timeline from ingest_stats_1s (bounded).
    try:
        with engine.begin() as conn:
            rows = conn.execute(
                select(
                    IngestStats1sModel.bucket_ts,
                    IngestStats1sModel.received,
                    IngestStats1sModel.hot_stored,
                    IngestStats1sModel.warm_indexed,
                    IngestStats1sModel.dropped,
                    IngestStats1sModel.rejected,
                    IngestStats1sModel.rollup_only,
                    IngestStats1sModel.backlog_events,
                    IngestStats1sModel.backlog_messages,
                    IngestStats1sModel.storm_active,
                    IngestStats1sModel.sample_hot_percent,
                    IngestStats1sModel.sample_warm_percent,
                )
                .where(IngestStats1sModel.bucket_ts >= start, IngestStats1sModel.bucket_ts <= end)
                .order_by(IngestStats1sModel.bucket_ts.asc())
                .limit(1200)
            ).mappings().all()

            timeline = []
            for rr in rows:
                timeline.append(
                    {
                        "ts": (rr.get("bucket_ts").isoformat() if rr.get("bucket_ts") else None),
                        "eps": int(rr.get("received") or 0),
                        "hot": int(rr.get("hot_stored") or 0),
                        "warm": int(rr.get("warm_indexed") or 0),
                        "dropped": int(rr.get("dropped") or 0),
                        "rejected": int(rr.get("rejected") or 0),
                        "backlog_events": int(rr.get("backlog_events") or 0),
                        "backlog_messages": int(rr.get("backlog_messages") or 0),
                        "sample_hot_percent": int(rr.get("sample_hot_percent") or 100),
                        "sample_warm_percent": int(rr.get("sample_warm_percent") or 0),
                    }
                )

            # Patch alert details
            patch = {
                "storm": {
                    "ended_at": end.isoformat(),
                },
                "timeline": timeline,
            }

            conn.execute(
                AlertModel.__table__.update()
                .where(AlertModel.id == alert_id)
                .values(details=AlertModel.details.op("||")(patch))
            )

        publish_alert_updated_payload(
            {
                "alert_id": int(alert_id),
                "rule_id": "system.ingest_storm",
                "severity": "high",
                "status": "closed",
                "updated_at": end.isoformat(),
            }
        )

        # Clear keys
        try:
            r.delete(storm_alert_id_key(), storm_session_key(), storm_since_key())
        except Exception:
            pass

    except Exception:
        return


def decide_pressure_phase(
    *,
    prev_phase: str,
    eps: int,
    processed_eps: int,
    backlog_events: int,
    prev_backlog_events: int,
    rejected: int,
    stalled_seconds: int,
) -> Tuple[str, str]:
    storm_entry = max(1, _env_int("NETWATCH_INGEST_STORM_EVENTS_PER_SECOND", 8000))
    storm_exit = max(1, _env_int("NETWATCH_INGEST_STORM_EXIT_EVENTS_PER_SECOND", int(storm_entry * 0.65)))
    soft_entry = max(1, _env_int("NETWATCH_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS", 50_000))
    soft_exit = max(0, _env_int("NETWATCH_INGEST_BACKPRESSURE_DRAIN_EXIT_BACKLOG_EVENTS", int(soft_entry * 0.55)))
    hard_backlog = max(soft_entry + 1, _env_int("NETWATCH_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS", 200_000))
    drain_stall_timeout = max(30, _env_int("NETWATCH_INGEST_DRAIN_STALL_TIMEOUT_SECONDS", 300))

    eps_i = max(0, int(eps))
    proc_i = max(0, int(processed_eps))
    back_i = max(0, int(backlog_events))
    prev_back_i = max(0, int(prev_backlog_events))

    storm_like = eps_i >= storm_entry or back_i >= hard_backlog
    improving = back_i < prev_back_i or proc_i > eps_i
    overloaded = rejected > 0 and storm_like

    if prev_phase in {"storm", "shedding"}:
        if overloaded:
            return "shedding", "hard_backlog"
        if storm_like:
            return "storm", "storm_eps"
        if back_i > soft_exit:
            return "draining", "recovery"
        return "ok", "recovered"

    if prev_phase == "draining":
        if overloaded:
            return "shedding", "hard_backlog"
        if storm_like and eps_i >= storm_entry:
            return "storm", "storm_eps"
        if back_i <= soft_exit and eps_i <= storm_exit:
            return "ok", "recovered"
        if stalled_seconds >= drain_stall_timeout and back_i <= soft_entry:
            # Failsafe against stale draining state.
            return "ok", "drain_timeout_exit"
        if not improving and stalled_seconds >= drain_stall_timeout:
            return "shedding", "drain_stalled"
        return "draining", ("draining" if improving else "draining_slow")

    if overloaded:
        return "shedding", "hard_backlog"
    if storm_like:
        return "storm", "storm_eps"
    if back_i >= soft_entry:
        return "draining", "soft_backlog"
    return "ok", "ok"


def _read_pressure_state(r) -> Dict[str, Any]:
    try:
        raw = r.hgetall(_pressure_state_key()) or {}
    except Exception:
        raw = {}
    return {
        "phase": str(raw.get("phase") or "ok"),
        "reason": str(raw.get("reason") or "ok"),
        "since_ts": _as_int(raw.get("since_ts"), 0),
        "prev_backlog_events": _as_int(raw.get("prev_backlog_events"), 0),
        "last_progress_ts": _as_int(raw.get("last_progress_ts"), 0),
    }


def _write_pressure_state(
    r,
    *,
    phase: str,
    reason: str,
    since_ts: int,
    prev_backlog_events: int,
    last_progress_ts: int,
) -> None:
    try:
        r.hset(
            _pressure_state_key(),
            mapping={
                "phase": phase,
                "reason": reason,
                "since_ts": str(max(0, int(since_ts))),
                "prev_backlog_events": str(max(0, int(prev_backlog_events))),
                "last_progress_ts": str(max(0, int(last_progress_ts))),
                "updated_ts": str(int(time.time())),
            },
        )
        r.expire(_pressure_state_key(), 3600)
    except Exception:
        return


def _clear_ui_runtime_caches(r) -> int:
    if r is None:
        return 0
    deleted = 0
    for pattern in ("netwatch:overview:v2:*", "netwatch:overview:live:*", "netwatch:events:*", "netwatch:inventory:overview:*"):
        try:
            batch = []
            for k in r.scan_iter(match=pattern, count=256):
                batch.append(k)
                if len(batch) >= 256:
                    deleted += int(r.delete(*batch) or 0)
                    batch = []
            if batch:
                deleted += int(r.delete(*batch) or 0)
        except Exception:
            continue
    return int(deleted)


def get_storm_status() -> Dict[str, Any]:
    """Return a small status payload for the UI (best-effort)."""

    r = get_redis()
    now_s = int(time.time())
    storm_th = max(1, _env_int("NETWATCH_INGEST_STORM_EVENTS_PER_SECOND", 8000))
    soft = max(1, _env_int("NETWATCH_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS", 50_000))

    if r is None:
        # Redis is unavailable: fall back to the latest persisted ingest_stats_1s row.
        # This keeps Overview usable without exposing internal transport errors as state.
        try:
            with engine.begin() as conn:
                row = (
                    conn.execute(
                        select(
                            IngestStats1sModel.bucket_ts,
                            IngestStats1sModel.received,
                            IngestStats1sModel.dropped,
                            IngestStats1sModel.backlog_events,
                            IngestStats1sModel.backlog_messages,
                            IngestStats1sModel.storm_active,
                            IngestStats1sModel.sample_hot_percent,
                            IngestStats1sModel.sample_warm_percent,
                        )
                        .where(IngestStats1sModel.bucket_ts >= datetime.now(timezone.utc) - timedelta(minutes=5))
                        .order_by(IngestStats1sModel.bucket_ts.desc())
                        .limit(1)
                    )
                    .mappings()
                    .first()
                )
        except Exception:
            row = None

        if not row:
            recent = recent_feed_health()
            return {
                "active": False,
                "phase": "ok",
                "eps": 0,
                "ingest_rate_eps": 0,
                "process_rate_eps": 0,
                "sample_hot_percent": 100,
                "sample_warm_percent": 0,
                "drop_percent": 0,
                "shed_percent": 0,
                "backlog_events": 0,
                "backlog_messages": 0,
                "workers_active": 0,
                "draining_seconds": 0,
                "reason": "ok",
                "since": None,
                "open_alert_id": None,
                "clickhouse_write_events_per_sec": 0,
                "clickhouse_write_batches_per_sec": 0,
                "recent_feed_events_per_sec": int(recent.get("events_last_second") or 0),
                "recent_feed_dropped_per_sec": int(recent.get("dropped_last_second") or 0),
                "recent_feed_last_event_ts": recent.get("last_event_ts"),
                "recent_feed_freshness_seconds": recent.get("freshness_seconds"),
                "clickhouse_state": "unknown",
                "clickhouse_error_type": None,
                "analytics_continuity_mode": "degraded",
                "optional_sinks": {
                    "clickhouse": {
                        "queue_depth": 0,
                        "failed_batches_per_sec": 0,
                        "dropped_events_per_sec": 0,
                    },
                    "warm": {
                        "queue_depth": 0,
                        "failed_batches_per_sec": 0,
                        "dropped_events_per_sec": 0,
                    },
                },
                "overview_live_dropped_per_sec": 0,
                "quality_by_event_type": [],
            }

        eps = _as_int(row.get("received"), 0)
        dropped = _as_int(row.get("dropped"), 0)
        backlog_ev = max(0, _as_int(row.get("backlog_events"), 0))
        backlog_msgs = max(0, _as_int(row.get("backlog_messages"), 0))

        drop_pct = int(round((dropped / eps) * 100.0)) if eps > 0 else 0

        storm_like = bool(row.get("storm_active")) or int(eps) >= int(storm_th)
        draining_flag = (not storm_like) and int(backlog_ev) >= int(soft)
        phase = "storm" if storm_like else ("draining" if draining_flag else "ok")
        recent = recent_feed_health()

        return {
            "active": bool(phase != "ok"),
            "phase": phase,
            "eps": int(eps),
            "ingest_rate_eps": int(eps),
            "process_rate_eps": 0,
            "sample_hot_percent": int(max(0, min(_as_int(row.get("sample_hot_percent"), 100), 100))),
            "sample_warm_percent": int(max(0, min(_as_int(row.get("sample_warm_percent"), 0), 100))),
            "drop_percent": int(max(0, min(drop_pct, 100))),
            "shed_percent": int(max(0, min(drop_pct, 100))),
            "backlog_events": int(backlog_ev),
            "backlog_messages": int(backlog_msgs),
            "workers_active": 0,
            "draining_seconds": 0,
            "reason": phase,
            "since": None,
            "open_alert_id": None,
            "clickhouse_write_events_per_sec": 0,
            "clickhouse_write_batches_per_sec": 0,
            "recent_feed_events_per_sec": int(recent.get("events_last_second") or 0),
            "recent_feed_dropped_per_sec": int(recent.get("dropped_last_second") or 0),
            "recent_feed_last_event_ts": recent.get("last_event_ts"),
            "recent_feed_freshness_seconds": recent.get("freshness_seconds"),
            "clickhouse_state": "unknown",
            "clickhouse_error_type": None,
            "analytics_continuity_mode": "degraded",
            "optional_sinks": {
                "clickhouse": {
                    "queue_depth": 0,
                    "failed_batches_per_sec": 0,
                    "dropped_events_per_sec": 0,
                },
                "warm": {
                    "queue_depth": 0,
                    "failed_batches_per_sec": 0,
                    "dropped_events_per_sec": 0,
                },
            },
            "overview_live_dropped_per_sec": 0,
            "quality_by_event_type": [],
        }

    # Ensure we close alerts if storm is over.
    storm_maybe_close_alert()

    backlog_msgs, backlog_ev = get_backlog()

    # Prefer the last completed second.
    ts_s = now_s - 1
    try:
        eps = int(r.get(_eps_key(ts_s)) or 0)
    except Exception:
        eps = 0

    try:
        stats = r.hgetall(_stats_key(ts_s)) or {}
    except Exception:
        stats = {}

    received = _as_int(stats.get("received"), eps)
    dropped = _as_int(stats.get("dropped"), 0)
    rejected = _as_int(stats.get("rejected"), 0)
    rollup_only = _as_int(stats.get("rollup_only"), 0)

    try:
        processed_eps = _as_int(r.get(_worker_eps_key(ts_s)), 0)
    except Exception:
        processed_eps = 0
    try:
        processed_messages = _as_int(r.get(_worker_msgs_key(ts_s)), 0)
    except Exception:
        processed_messages = 0
    try:
        clickhouse_rows = _as_int(r.get(f"netwatch:ingest:clickhouse:rows:{ts_s}"), 0)
    except Exception:
        clickhouse_rows = 0
    try:
        clickhouse_batches = _as_int(r.get(f"netwatch:ingest:clickhouse:batches:{ts_s}"), 0)
    except Exception:
        clickhouse_batches = 0
    try:
        clickhouse_state = str(r.get("netwatch:ingest:clickhouse:state") or "unknown")
    except Exception:
        clickhouse_state = "unknown"
    try:
        clickhouse_error_type = r.get("netwatch:ingest:clickhouse:error_type")
    except Exception:
        clickhouse_error_type = None
    try:
        clickhouse_q_depth = _as_int(r.get(_sink_depth_key(sink="clickhouse")), 0)
    except Exception:
        clickhouse_q_depth = 0
    try:
        warm_q_depth = _as_int(r.get(_sink_depth_key(sink="warm")), 0)
    except Exception:
        warm_q_depth = 0
    try:
        clickhouse_failed_batches = _as_int(r.get(_sink_counter_key(sink="clickhouse", metric="failed_batches", ts_s=ts_s)), 0)
    except Exception:
        clickhouse_failed_batches = 0
    try:
        clickhouse_dropped_events = _as_int(r.get(_sink_counter_key(sink="clickhouse", metric="dropped_events", ts_s=ts_s)), 0)
    except Exception:
        clickhouse_dropped_events = 0
    try:
        warm_failed_batches = _as_int(r.get(_sink_counter_key(sink="warm", metric="failed_batches", ts_s=ts_s)), 0)
    except Exception:
        warm_failed_batches = 0
    try:
        warm_dropped_events = _as_int(r.get(_sink_counter_key(sink="warm", metric="dropped_events", ts_s=ts_s)), 0)
    except Exception:
        warm_dropped_events = 0
    try:
        overview_live_dropped = _as_int(r.get(_overview_live_dropped_key(ts_s)), 0)
    except Exception:
        overview_live_dropped = 0

    workers_active = count_active_workers()
    recent = recent_feed_health()
    quality_rows = _read_ingest_quality_window(now_s=now_s, seconds=max(5, _env_int("NETWATCH_INGEST_QUALITY_WINDOW_SECONDS", 15)))

    drop_pct = 0
    if received > 0:
        drop_pct = int(round((dropped / received) * 100.0))
    shed_pct = 0
    if received > 0:
        shed_pct = int(round(((dropped + rejected) / received) * 100.0))

    state = _read_pressure_state(r)
    prev_phase = str(state.get("phase") or "ok")
    prev_backlog_events = _as_int(state.get("prev_backlog_events"), int(backlog_ev))
    last_progress_ts = _as_int(state.get("last_progress_ts"), 0)
    since_ts = _as_int(state.get("since_ts"), 0)
    if since_ts <= 0:
        since_ts = now_s
    if last_progress_ts <= 0:
        last_progress_ts = now_s

    stalled_seconds = max(0, now_s - int(since_ts))
    phase, reason = decide_pressure_phase(
        prev_phase=prev_phase,
        eps=int(eps),
        processed_eps=int(processed_eps),
        backlog_events=int(backlog_ev),
        prev_backlog_events=int(prev_backlog_events),
        rejected=int(rejected),
        stalled_seconds=stalled_seconds,
    )

    if phase != prev_phase:
        since_ts = now_s
    progressed = (int(received) > 0) or (int(processed_eps) > 0) or (int(backlog_ev) < int(prev_backlog_events))
    if progressed:
        last_progress_ts = now_s

    drain_idle_timeout = max(60, _env_int("NETWATCH_INGEST_DRAIN_IDLE_TIMEOUT_SECONDS", 180))
    if (
        phase == "draining"
        and (now_s - last_progress_ts) >= drain_idle_timeout
        and (int(backlog_msgs) <= 1 or int(backlog_ev) <= soft)
        and int(received) == 0
    ):
        phase = "ok"
        reason = "drain_idle_timeout_exit"
        since_ts = now_s

    _write_pressure_state(
        r,
        phase=phase,
        reason=reason,
        since_ts=since_ts,
        prev_backlog_events=int(backlog_ev),
        last_progress_ts=int(last_progress_ts),
    )

    recovered_to_ok = (prev_phase != "ok") and (phase == "ok")
    if recovered_to_ok:
        # Self-heal stale protection keys/caches as soon as pressure returns to normal.
        # This avoids dashboards remaining pinned in draining/storm visuals.
        try:
            pipe = r.pipeline()
            pipe.delete(
                storm_active_key(),
                "netwatch:ingest:storm_reason",
                "netwatch:ingest:storm_sample_hot",
                "netwatch:ingest:storm_sample_warm",
            )
            pipe.execute()
        except Exception:
            pass
        storm_maybe_close_alert()
        _clear_ui_runtime_caches(r)

    try:
        sample_hot = _as_int(r.get("netwatch:ingest:storm_sample_hot"), 100)
        sample_warm = _as_int(r.get("netwatch:ingest:storm_sample_warm"), 0)
    except Exception:
        sample_hot, sample_warm = 100, 0

    try:
        since_storm = r.get(storm_since_key())
    except Exception:
        since_storm = None

    try:
        alert_id = r.get(storm_alert_id_key())
    except Exception:
        alert_id = None

    active = phase != "ok"
    draining_seconds = (now_s - since_ts) if phase == "draining" else 0
    since_iso = None
    if phase in {"draining", "storm", "shedding"}:
        if phase in {"storm", "shedding"} and since_storm:
            since_iso = str(since_storm)
        else:
            since_iso = datetime.fromtimestamp(max(0, since_ts), tz=timezone.utc).isoformat()

    return {
        "active": bool(active),
        "phase": phase,
        "eps": int(eps),
        "ingest_rate_eps": int(received),
        "process_rate_eps": int(processed_eps),
        "processed_messages_per_sec": int(processed_messages),
        "sample_hot_percent": int(max(0, min(sample_hot, 100))),
        "sample_warm_percent": int(max(0, min(sample_warm, 100))),
        "drop_percent": int(max(0, min(drop_pct, 100))),
        "shed_percent": int(max(0, min(shed_pct, 100))),
        "rejected_events": int(max(0, rejected)),
        "rollup_only_events": int(max(0, rollup_only)),
        "backlog_events": int(max(0, backlog_ev)),
        "backlog_messages": int(max(0, backlog_msgs)),
        "workers_active": int(max(0, workers_active)),
        "draining_seconds": int(max(0, draining_seconds)),
        "reason": reason,
        "since": since_iso,
        "open_alert_id": int(alert_id) if (alert_id and str(alert_id).isdigit()) else None,
        "clickhouse_write_events_per_sec": int(max(0, clickhouse_rows)),
        "clickhouse_write_batches_per_sec": int(max(0, clickhouse_batches)),
        "recent_feed_events_per_sec": int(max(0, int(recent.get("events_last_second") or 0))),
        "recent_feed_dropped_per_sec": int(max(0, int(recent.get("dropped_last_second") or 0))),
        "recent_feed_last_event_ts": recent.get("last_event_ts"),
        "recent_feed_freshness_seconds": recent.get("freshness_seconds"),
        "clickhouse_state": clickhouse_state,
        "clickhouse_error_type": (str(clickhouse_error_type) if clickhouse_error_type else None),
        "analytics_continuity_mode": ("full" if clickhouse_state in {"available", "disabled"} else "degraded"),
        "optional_sinks": {
            "clickhouse": {
                "queue_depth": int(max(0, clickhouse_q_depth)),
                "failed_batches_per_sec": int(max(0, clickhouse_failed_batches)),
                "dropped_events_per_sec": int(max(0, clickhouse_dropped_events)),
            },
            "warm": {
                "queue_depth": int(max(0, warm_q_depth)),
                "failed_batches_per_sec": int(max(0, warm_failed_batches)),
                "dropped_events_per_sec": int(max(0, warm_dropped_events)),
            },
        },
        "overview_live_dropped_per_sec": int(max(0, overview_live_dropped)),
        "quality_by_event_type": quality_rows,
    }


def recover_runtime_state(*, clear_backlog_counters: bool = False, clear_ui_caches: bool = True) -> Dict[str, Any]:
    """Force-reset volatile ingest runtime state in Redis.

    This is an operational recovery action for post-incident scenarios where
    stale runtime keys keep the UI in draining/protection mode.
    """

    r = get_redis()
    if r is None:
        return {"ok": False, "reason": "redis_unavailable"}

    keys = [
        storm_active_key(),
        "netwatch:ingest:storm_reason",
        "netwatch:ingest:storm_sample_hot",
        "netwatch:ingest:storm_sample_warm",
        storm_session_key(),
        storm_since_key(),
        storm_alert_id_key(),
        _pressure_state_key(),
        "netwatch:ingest:bp_mode",
    ]

    if clear_backlog_counters:
        keys.append(backlog_events_key())

    deleted_direct = 0
    try:
        deleted_direct = int(r.delete(*keys) or 0)
    except Exception:
        deleted_direct = 0

    deleted_pattern = _clear_ui_runtime_caches(r) if clear_ui_caches else 0

    return {
        "ok": True,
        "deleted_direct_keys": int(deleted_direct),
        "deleted_cache_keys": int(deleted_pattern),
        "clear_backlog_counters": bool(clear_backlog_counters),
        "clear_ui_caches": bool(clear_ui_caches),
    }
