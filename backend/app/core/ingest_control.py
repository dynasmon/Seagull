from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import text

from app.core.redis_client import get_redis
from app.core.db import engine


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return int(raw, 10)
    except Exception:
        return default


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    return raw if raw else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    s = raw.strip().lower()
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


@dataclass(frozen=True)
class BackpressureDecision:
    mode: str  # normal | rollup_only | reject_429
    reason: str
    backlog_events: int
    backlog_messages: int


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

    try:
        ev = int(r.get(backlog_events_key()) or 0)
    except Exception:
        ev = 0

    return msgs, ev


def evaluate_backpressure(*, received: int) -> BackpressureDecision:
    """Decide how to handle ingestion based on Redis backlog.

    - soft limit: switch to rollup_only (default)
    - hard limit: reject 429 or rollup_only depending on NETWATCH_INGEST_BACKPRESSURE_MODE
    """

    soft = _env_int("NETWATCH_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS", 50_000)
    hard = _env_int("NETWATCH_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS", 200_000)
    mode = _env_str("NETWATCH_INGEST_BACKPRESSURE_MODE", "rollup_only").lower().strip()
    mode = mode if mode in {"rollup_only", "reject_429"} else "rollup_only"

    msgs, ev = get_backlog()

    # Compute projected backlog to avoid races.
    projected = ev + max(0, int(received))

    if hard > 0 and projected >= hard:
        return BackpressureDecision(
            mode="reject_429" if mode == "reject_429" else "rollup_only",
            reason="hard_backlog",
            backlog_events=ev,
            backlog_messages=msgs,
        )

    if soft > 0 and projected >= soft:
        return BackpressureDecision(mode="rollup_only", reason="soft_backlog", backlog_events=ev, backlog_messages=msgs)

    return BackpressureDecision(mode="normal", reason="ok", backlog_events=ev, backlog_messages=msgs)


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

    def _as_int(v: Any) -> int:
        try:
            return int(v)
        except Exception:
            return 0

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

    sql = text(
        """
        INSERT INTO ingest_stats_1s (
            bucket_ts, received, hot_stored, warm_indexed, dropped, rejected,
            rollup_only, backlog_messages, backlog_events, storm_active,
            sample_hot_percent, sample_warm_percent
        ) VALUES (
            :bucket_ts, :received, :hot_stored, :warm_indexed, :dropped, :rejected,
            :rollup_only, :backlog_messages, :backlog_events, :storm_active,
            :sample_hot_percent, :sample_warm_percent
        )
        ON CONFLICT (bucket_ts)
        DO UPDATE SET
            received = ingest_stats_1s.received + EXCLUDED.received,
            hot_stored = ingest_stats_1s.hot_stored + EXCLUDED.hot_stored,
            warm_indexed = ingest_stats_1s.warm_indexed + EXCLUDED.warm_indexed,
            dropped = ingest_stats_1s.dropped + EXCLUDED.dropped,
            rejected = ingest_stats_1s.rejected + EXCLUDED.rejected,
            rollup_only = ingest_stats_1s.rollup_only + EXCLUDED.rollup_only,
            backlog_messages = GREATEST(ingest_stats_1s.backlog_messages, EXCLUDED.backlog_messages),
            backlog_events = GREATEST(ingest_stats_1s.backlog_events, EXCLUDED.backlog_events),
            storm_active = (ingest_stats_1s.storm_active OR EXCLUDED.storm_active),
            sample_hot_percent = LEAST(ingest_stats_1s.sample_hot_percent, EXCLUDED.sample_hot_percent),
            sample_warm_percent = GREATEST(ingest_stats_1s.sample_warm_percent, EXCLUDED.sample_warm_percent),
            updated_at = now();
        """
    )

    try:
        with engine.begin() as conn:
            conn.execute(
                sql,
                {
                    "bucket_ts": bucket_ts,
                    "received": received,
                    "hot_stored": hot_kept,
                    "warm_indexed": warm_kept,
                    "dropped": dropped,
                    "rejected": rejected,
                    "rollup_only": rollup_only,
                    "backlog_messages": backlog_msgs,
                    "backlog_events": backlog_ev,
                    "storm_active": storm_active,
                    "sample_hot_percent": sample_hot,
                    "sample_warm_percent": sample_warm,
                },
            )
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

    # If an alert is already open, nothing to do.
    try:
        existing = r.get(storm_alert_id_key())
        if existing:
            return
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
                text(
                    """
                    INSERT INTO alerts (
                        created_at, rule_id, severity,
                        mitre_tactic, mitre_technique_id, mitre_technique, confidence,
                        description, details
                    ) VALUES (
                        now(), :rule_id, :severity,
                        :tactic, :technique_id, :technique, :confidence,
                        :description, :details::jsonb
                    )
                    RETURNING id;
                    """
                ),
                {
                    "rule_id": "system.ingest_storm",
                    "severity": "high",
                    "tactic": "impact",
                    "technique_id": "T1498",
                    "technique": "Network Denial of Service",
                    "confidence": 85,
                    "description": "Ingest Storm Detected",
                    "details": json.dumps(details, ensure_ascii=False),
                },
            ).fetchone()
            alert_id = int(row[0]) if row else 0

        if alert_id:
            r.setex(storm_alert_id_key(), _env_int("NETWATCH_INGEST_STORM_ALERT_TTL_SECONDS", 3600), str(alert_id))
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
                text(
                    """
                    SELECT bucket_ts, received, hot_stored, warm_indexed, dropped, rejected,
                           rollup_only, backlog_events, backlog_messages, storm_active,
                           sample_hot_percent, sample_warm_percent
                    FROM ingest_stats_1s
                    WHERE bucket_ts >= :start_ts AND bucket_ts <= :end_ts
                    ORDER BY bucket_ts ASC
                    LIMIT 1200;
                    """
                ),
                {"start_ts": start, "end_ts": end},
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
                text(
                    """
                    UPDATE alerts
                       SET details = details || :patch::jsonb
                     WHERE id = :id;
                    """
                ),
                {"id": alert_id, "patch": json.dumps(patch, ensure_ascii=False)},
            )

        # Clear keys
        try:
            r.delete(storm_alert_id_key(), storm_session_key(), storm_since_key())
        except Exception:
            pass

    except Exception:
        return


def get_storm_status() -> Dict[str, Any]:
    """Return a small status payload for the UI (best-effort)."""

    r = get_redis()
    now_s = int(time.time())

    if r is None:
        return {
            "active": False,
            "eps": 0,
            "sample_hot_percent": 100,
            "sample_warm_percent": 0,
            "drop_percent": 0,
            "backlog_events": 0,
            "backlog_messages": 0,
            "reason": "redis_unavailable",
            "since": None,
            "open_alert_id": None,
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

    def _as_int(v: Any, default: int = 0) -> int:
        try:
            return int(v)
        except Exception:
            return default

    received = _as_int(stats.get("received"), eps)
    dropped = _as_int(stats.get("dropped"), 0)

    drop_pct = 0
    if received > 0:
        drop_pct = int(round((dropped / received) * 100.0))

    try:
        storm_flag = bool(r.get(storm_active_key()))
    except Exception:
        storm_flag = False

    # "Draining" means the attack rate is back to normal, but the async queue still has backlog.
    soft = _env_int("NETWATCH_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS", 50_000)
    draining_flag = (not storm_flag) and soft > 0 and int(backlog_ev) >= int(soft)

    phase = "storm" if storm_flag else ("draining" if draining_flag else "ok")
    active = phase != "ok"

    try:
        reason = (r.get("netwatch:ingest:storm_reason") or "").strip() or (phase if active else "ok")
    except Exception:
        reason = "ok"

    try:
        sample_hot = _as_int(r.get("netwatch:ingest:storm_sample_hot"), 100)
        sample_warm = _as_int(r.get("netwatch:ingest:storm_sample_warm"), 0)
    except Exception:
        sample_hot, sample_warm = 100, 0

    try:
        since = r.get(storm_since_key())
    except Exception:
        since = None

    try:
        alert_id = r.get(storm_alert_id_key())
    except Exception:
        alert_id = None

    return {
        "active": bool(active),
        "phase": phase,
        "eps": int(eps),
        "sample_hot_percent": int(max(0, min(sample_hot, 100))),
        "sample_warm_percent": int(max(0, min(sample_warm, 100))),
        "drop_percent": int(max(0, min(drop_pct, 100))),
        "backlog_events": int(max(0, backlog_ev)),
        "backlog_messages": int(max(0, backlog_msgs)),
        "reason": reason,
        "since": since,
        "open_alert_id": int(alert_id) if (alert_id and str(alert_id).isdigit()) else None,
    }
