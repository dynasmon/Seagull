import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from fastapi import APIRouter, Depends, HTTPException, status
from psycopg2.extras import Json, execute_values

from app.core.db import engine
from app.core.agent_auth import AgentPrincipal, get_current_agent
from app.core.portal_auth import get_current_user
from app.core.storm_control import evaluate_storm, stable_sample
from app.core.ingest_control import (
    evaluate_backpressure,
    enqueue_ingest_message,
    bump_ingest_counters,
    maybe_flush_stats_to_db,
    mark_storm_active,
    storm_maybe_open_alert,
    get_storm_status,
)
from app.schemas.events import NetEvent


router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
)


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


def _fallback_direct_insert(*, raw_rows: List[Tuple], rollup_rows: List[Tuple]) -> int:
    """Fail-open path if Redis is unavailable.

    This keeps the platform usable, but may increase DB pressure under storm.
    """

    stored = 0
    conn = engine.raw_connection()
    try:
        cur = conn.cursor()

        cols = (
            "agent_id",
            "event_type",
            "schema_version",
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "proto",
            "bytes",
            "extra",
        )

        if raw_rows:
            insert_sql = f"INSERT INTO net_events ({', '.join(cols)}) VALUES %s"
            execute_values(cur, insert_sql, raw_rows, page_size=_env_int("NETWATCH_INGEST_VALUES_PAGE_SIZE", 1000))
            stored = len(raw_rows)

        if rollup_rows:
            rollup_sql = """
                INSERT INTO net_event_rollups_1s (
                    bucket_ts, agent_id, event_type, dst_ip, dst_port, proto, count, bytes_sum
                ) VALUES %s
                ON CONFLICT (bucket_ts, agent_id, event_type, dst_ip, dst_port, proto)
                DO UPDATE SET
                    count = net_event_rollups_1s.count + EXCLUDED.count,
                    bytes_sum = net_event_rollups_1s.bytes_sum + EXCLUDED.bytes_sum;
            """
            execute_values(cur, rollup_sql, rollup_rows, page_size=_env_int("NETWATCH_INGEST_ROLLUP_PAGE_SIZE", 500))

        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return stored


@router.get("/storm/status")
def storm_status(_: object = Depends(get_current_user)):
    """Storm Mode health payload for the Overview page."""

    return get_storm_status()


@router.post("/events")
def ingest_events(
    events: List[NetEvent],
    agent: AgentPrincipal = Depends(get_current_agent),
):
    """Ingest network/security events from agents.

    Goals:
    - Survive volumetric attacks without collapsing Postgres.
    - Provide "Storm Mode" sampling + 1-second rollups.
    - Add backpressure using a Redis queue (fast ingest, async persistence).

    Behavior under load:
    - Normal: 100% hot (Postgres), rollups optional.
    - Storm: sample hot + optional warm (Elasticsearch), always rollups.
    - Backpressure: rollup_only or 429 (configurable).
    """

    if not events:
        return {"received": 0, "enqueued": 0}

    max_batch = _env_int("NETWATCH_INGEST_MAX_BATCH", 10000)
    if len(events) > max_batch:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Too many events in one request (max {max_batch}).",
        )

    # Enforce that an agent can only send its own events.
    for e in events:
        if e.agent_id != agent.agent_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent_id mismatch")

    # Backpressure decision based on current backlog.
    bp = evaluate_backpressure(received=len(events))

    # Only trust client timestamp if it is close enough to server time.
    max_skew_s = _env_int("NETWATCH_MAX_EVENT_CLOCK_SKEW_SECONDS", 30)

    now = datetime.now(timezone.utc)

    # Storm control (best-effort; fails open).
    # IMPORTANT: "storm" is strictly volumetric (events/sec). Backpressure (queue backlog)
    # is treated separately so the UI can show "DRAINING" once the attack stops.
    decision = evaluate_storm(agent.agent_id, len(events))

    # Final mode
    mode = "normal"
    if bp.mode == "reject_429":
        # We intentionally reject early to protect the platform.
        bump_ingest_counters(
            received=len(events),
            hot_kept=0,
            warm_kept=0,
            dropped=0,
            rejected=len(events),
            rollup_only=0,
            storm_active=True,
            sample_hot=0,
            sample_warm=0,
        )
        maybe_flush_stats_to_db()
        mark_storm_active(reason=bp.reason, sample_hot=0, sample_warm=0)
        storm_maybe_open_alert(reason=bp.reason, sample_hot=0, sample_warm=0)

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Ingest overloaded (backpressure). Please retry.",
            headers={"Retry-After": "2"},
        )

    if bp.mode == "rollup_only":
        mode = "rollup_only"

    storm_active = bool(decision.storm_active)
    pressure_active = mode != "normal"
    active_for_metrics = storm_active or pressure_active
    storm_reason = decision.reason if decision.storm_active else (bp.reason if pressure_active else "ok")

    rollup_always = _env_bool("NETWATCH_INGEST_ROLLUP_ALWAYS", False)
    do_rollup = rollup_always or active_for_metrics

    # Sampling policy (hot vs warm)
    if mode == "rollup_only":
        hot_pct = 0
        warm_pct = _env_int("NETWATCH_INGEST_BACKPRESSURE_WARM_SAMPLE_PERCENT", _env_int("NETWATCH_INGEST_STORM_SAMPLE_PERCENT", 2))
    elif storm_active:
        hot_pct = _env_int("NETWATCH_INGEST_STORM_HOT_SAMPLE_PERCENT", int(decision.sample_percent))
        warm_pct = _env_int("NETWATCH_INGEST_STORM_WARM_SAMPLE_PERCENT", int(decision.sample_percent))
    else:
        hot_pct = 100
        warm_pct = _env_int("NETWATCH_INGEST_WARM_SAMPLE_PERCENT", 0)

    hot_pct = max(0, min(int(hot_pct), 100))
    warm_pct = max(0, min(int(warm_pct), 100))

    # Normalize to deterministic sample.
    # We only send warm events when ES is enabled AND the event was NOT kept hot.
    warm_enabled = warm_pct > 0 and _env_bool("NETWATCH_INGEST_WARM_ENABLED", True)

    # Build rollups + sampled event payloads.
    hot_events: List[List] = []
    warm_events: List[List] = []
    rollups: Dict[Tuple, Tuple[int, int]] = {}

    hot_kept = 0
    warm_kept = 0

    for e in events:
        extra = dict(e.extra or {})

        ts = e.timestamp
        use_client_ts = False
        try:
            skew = abs((now - ts).total_seconds())
            use_client_ts = skew <= max_skew_s
            if not use_client_ts:
                extra.setdefault("client_timestamp", ts.isoformat())
                extra.setdefault("clock_skew_seconds", round(skew, 3))
        except Exception:
            use_client_ts = False

        ts_eff = ts if use_client_ts else now

        if do_rollup:
            bucket_ts = ts_eff.replace(microsecond=0)
            k = (
                bucket_ts,
                e.agent_id,
                e.event_type,
                e.dst_ip,
                e.dst_port,
                e.proto,
            )
            prev = rollups.get(k)
            c_prev, b_prev = (prev if prev is not None else (0, 0))
            rollups[k] = (c_prev + 1, b_prev + int(e.bytes or 0))

        seed = "|".join(
            [
                e.agent_id or "",
                e.event_type or "",
                str(ts_eff.replace(microsecond=0).timestamp()),
                e.src_ip or "",
                e.dst_ip or "",
                str(e.src_port or 0),
                str(e.dst_port or 0),
                e.proto or "",
            ]
        )

        keep_hot = stable_sample(seed=seed + "|hot", sample_percent=hot_pct)
        keep_warm = warm_enabled and stable_sample(seed=seed + "|warm", sample_percent=warm_pct)

        row = [
            e.agent_id,
            e.event_type,
            int(getattr(e, "schema_version", 1) or 1),
            ts_eff.isoformat(),
            e.src_ip,
            e.dst_ip,
            e.src_port,
            e.dst_port,
            e.proto,
            e.bytes,
            extra,
        ]

        if keep_hot:
            hot_events.append(row)
            hot_kept += 1
        elif keep_warm:
            warm_events.append(row)
            warm_kept += 1

    dropped = max(0, len(events) - hot_kept - warm_kept)

    # Rollup rows for async worker
    rollup_rows = [
        [
            bucket_ts.isoformat(),
            agent_id,
            event_type,
            dst_ip,
            dst_port,
            proto,
            cnt,
            bsum,
        ]
        for (bucket_ts, agent_id, event_type, dst_ip, dst_port, proto), (cnt, bsum) in rollups.items()
    ]

    msg = {
        "v": 1,
        "received_at": now.isoformat(),
        "agent_id": agent.agent_id,
        "mode": mode,
        "storm_active": bool(storm_active),
        "storm_reason": storm_reason,
        "sample_hot_percent": hot_pct,
        "sample_warm_percent": warm_pct,
        "received": len(events),
        "hot_events": hot_events,
        "warm_events": warm_events,
        "rollups": rollup_rows,
    }

    enqueued = enqueue_ingest_message(message=msg, received=len(events))

    # Redis unavailable: fail open to direct DB insert.
    if not enqueued:
        raw_rows: List[Tuple] = []
        for row in hot_events:
            raw_rows.append(
                (
                    row[0],
                    row[1],
                    row[2],
                    datetime.fromisoformat(row[3]),
                    row[4],
                    row[5],
                    row[6],
                    row[7],
                    row[8],
                    row[9],
                    Json(row[10], dumps=json.dumps),
                )
            )

        rr: List[Tuple] = []
        for rrow in rollup_rows:
            rr.append(
                (
                    datetime.fromisoformat(rrow[0]),
                    rrow[1],
                    rrow[2],
                    rrow[3],
                    rrow[4],
                    rrow[5],
                    int(rrow[6]),
                    int(rrow[7]),
                )
            )

        stored = _fallback_direct_insert(raw_rows=raw_rows, rollup_rows=rr)

        bump_ingest_counters(
            received=len(events),
            hot_kept=stored,
            warm_kept=0,
            dropped=len(events) - stored,
            rejected=0,
            rollup_only=1 if mode == "rollup_only" else 0,
            storm_active=active_for_metrics,
            sample_hot=hot_pct,
            sample_warm=warm_pct,
        )
        maybe_flush_stats_to_db()

        if active_for_metrics:
            mark_storm_active(reason=storm_reason, sample_hot=hot_pct, sample_warm=warm_pct)
            storm_maybe_open_alert(reason=storm_reason, sample_hot=hot_pct, sample_warm=warm_pct)

        return {
            "received": len(events),
            "stored": stored,
            "enqueued": 0,
            "mode": mode,
            "storm_active": bool(storm_active),
            "storm_reason": storm_reason,
            "sample_hot_percent": hot_pct,
            "sample_warm_percent": warm_pct,
            "rollups_written": bool(do_rollup),
            "backpressure": {"mode": bp.mode, "reason": bp.reason, "backlog_events": bp.backlog_events, "backlog_messages": bp.backlog_messages},
            "note": "redis_unavailable_fallback",
        }

    # Update counters for metrics
    bump_ingest_counters(
        received=len(events),
        hot_kept=hot_kept,
        warm_kept=warm_kept,
        dropped=dropped,
        rejected=0,
        rollup_only=1 if mode == "rollup_only" else 0,
        storm_active=active_for_metrics,
        sample_hot=hot_pct,
        sample_warm=warm_pct,
    )
    maybe_flush_stats_to_db()

    # Open/refresh the ingest-shield key and system alert whenever protection is active.
    # This ensures we still alert even if the storm is queue-driven (backpressure).
    if active_for_metrics:
        mark_storm_active(reason=storm_reason, sample_hot=hot_pct, sample_warm=warm_pct)
        storm_maybe_open_alert(reason=storm_reason, sample_hot=hot_pct, sample_warm=warm_pct)

    return {
        "received": len(events),
        "enqueued": 1,
        "mode": mode,
        "storm_active": bool(storm_active),
        "storm_reason": storm_reason,
        "sample_hot_percent": hot_pct,
        "sample_warm_percent": warm_pct,
        "rollups_written": bool(do_rollup),
        "backpressure": {"mode": bp.mode, "reason": bp.reason, "backlog_events": bp.backlog_events, "backlog_messages": bp.backlog_messages},
    }
