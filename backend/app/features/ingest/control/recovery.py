from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Tuple

from sqlalchemy import select

from app.core.cache import get_redis
from app.core.db import engine
from app.features.events.models import IngestStats1sModel
from app.features.events.recent_feed import recent_feed_health
from app.features.ingest.control.backpressure import get_backlog
from app.features.ingest.control.counters import _read_ingest_quality_window
from app.features.ingest.control.queue_keys import (
    _as_int,
    _clickhouse_batches_key,
    _clickhouse_error_type_key,
    _clickhouse_rows_key,
    _clickhouse_state_key,
    _env_int,
    _eps_key,
    _overview_live_dropped_key,
    _pressure_state_key,
    _sink_counter_key,
    _sink_depth_key,
    _stats_key,
    _worker_eps_key,
    _worker_msgs_key,
    backlog_events_key,
    storm_active_key,
    storm_alert_id_key,
    storm_session_key,
    storm_since_key,
)
from app.features.ingest.control.storm import storm_maybe_close_alert
from app.features.ingest.control.worker_state import count_active_workers


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
    storm_entry = max(1, _env_int("SEAGULL_INGEST_STORM_EVENTS_PER_SECOND", 8000))
    storm_exit = max(1, _env_int("SEAGULL_INGEST_STORM_EXIT_EVENTS_PER_SECOND", int(storm_entry * 0.65)))
    soft_entry = max(1, _env_int("SEAGULL_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS", 50_000))
    soft_exit = max(0, _env_int("SEAGULL_INGEST_BACKPRESSURE_DRAIN_EXIT_BACKLOG_EVENTS", int(soft_entry * 0.55)))
    hard_backlog = max(soft_entry + 1, _env_int("SEAGULL_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS", 200_000))
    drain_stall_timeout = max(30, _env_int("SEAGULL_INGEST_DRAIN_STALL_TIMEOUT_SECONDS", 300))

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
    for pattern in ("seagull:overview:v2:*", "seagull:overview:live:*", "seagull:events:*", "seagull:inventory:overview:*"):
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

    r = get_redis()
    now_s = int(time.time())
    storm_th = max(1, _env_int("SEAGULL_INGEST_STORM_EVENTS_PER_SECOND", 8000))
    soft = max(1, _env_int("SEAGULL_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS", 50_000))

    if r is None:
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
                    "clickhouse": {"queue_depth": 0, "failed_batches_per_sec": 0, "dropped_events_per_sec": 0},
                    "warm": {"queue_depth": 0, "failed_batches_per_sec": 0, "dropped_events_per_sec": 0},
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
                "clickhouse": {"queue_depth": 0, "failed_batches_per_sec": 0, "dropped_events_per_sec": 0},
                "warm": {"queue_depth": 0, "failed_batches_per_sec": 0, "dropped_events_per_sec": 0},
            },
            "overview_live_dropped_per_sec": 0,
            "quality_by_event_type": [],
        }

    storm_maybe_close_alert()

    backlog_msgs, backlog_ev = get_backlog()

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
        clickhouse_rows = _as_int(r.get(_clickhouse_rows_key(ts_s)), 0)
    except Exception:
        clickhouse_rows = 0
    try:
        clickhouse_batches = _as_int(r.get(_clickhouse_batches_key(ts_s)), 0)
    except Exception:
        clickhouse_batches = 0
    try:
        clickhouse_state = str(r.get(_clickhouse_state_key()) or "unknown")
    except Exception:
        clickhouse_state = "unknown"
    try:
        clickhouse_error_type = r.get(_clickhouse_error_type_key())
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
    quality_rows = _read_ingest_quality_window(now_s=now_s, seconds=max(5, _env_int("SEAGULL_INGEST_QUALITY_WINDOW_SECONDS", 15)))

    drop_pct = int(round((dropped / received) * 100.0)) if received > 0 else 0
    shed_pct = int(round(((dropped + rejected) / received) * 100.0)) if received > 0 else 0

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

    drain_idle_timeout = max(60, _env_int("SEAGULL_INGEST_DRAIN_IDLE_TIMEOUT_SECONDS", 180))
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
        try:
            pipe = r.pipeline()
            pipe.delete(
                storm_active_key(),
                "seagull:ingest:storm_reason",
                "seagull:ingest:storm_sample_hot",
                "seagull:ingest:storm_sample_warm",
            )
            pipe.execute()
        except Exception:
            pass
        storm_maybe_close_alert()
        _clear_ui_runtime_caches(r)

    try:
        sample_hot = _as_int(r.get("seagull:ingest:storm_sample_hot"), 100)
        sample_warm = _as_int(r.get("seagull:ingest:storm_sample_warm"), 0)
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

    r = get_redis()
    if r is None:
        return {"ok": False, "reason": "redis_unavailable"}

    keys = [
        storm_active_key(),
        "seagull:ingest:storm_reason",
        "seagull:ingest:storm_sample_hot",
        "seagull:ingest:storm_sample_warm",
        storm_session_key(),
        storm_since_key(),
        storm_alert_id_key(),
        _pressure_state_key(),
        "seagull:ingest:bp_mode",
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
