import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Sequence, Set, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.dialects.postgresql import insert

from app.core.db import engine
from app.core.agent_auth import AgentPrincipal, get_current_agent
from app.core.portal_auth import get_current_user, require_admin
from app.core.storm_control import evaluate_storm, stable_sample
from app.core.ingest_control import (
    evaluate_backpressure,
    enqueue_ingest_message,
    bump_ingest_counters,
    maybe_flush_stats_to_db,
    mark_storm_active,
    storm_maybe_open_alert,
    get_storm_status,
    recover_runtime_state,
)
from app.core.recent_feed import push_recent_events
from app.core.config import settings
from app.core.clickhouse import (
    clickhouse_events_table_ref,
    clickhouse_is_enabled,
    ensure_clickhouse_events_schema,
    get_clickhouse_client,
)
from app.core.observability import log_event
from app.models.events import NetEventModel, NetEventRollup1sModel
from app.schemas.events import NetEvent


router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
)
logger = logging.getLogger("netwatch.api.ingest")


def _degradation_level(*, bp_mode: str, storm_active: bool, backlog_events: int, received: int) -> str:
    soft = max(1, int(settings.NETWATCH_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS or 50000))
    hard = max(soft + 1, int(settings.NETWATCH_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS or 200000))
    storm_batch = max(1, int(settings.NETWATCH_INGEST_STORM_MIN_BATCH or 2500))

    if bp_mode == "reject_429" or backlog_events >= hard:
        return "critical"
    if bp_mode == "rollup_only" or backlog_events >= soft or storm_active:
        return "degraded"
    if backlog_events >= max(soft // 2, 1) or received >= storm_batch:
        return "elevated"
    return "normal"


def _target_sample_policy(*, level: str, storm_active: bool) -> tuple[int, int, int, int]:
    warm_pct = max(0, int(settings.NETWATCH_INGEST_WARM_SAMPLE_PERCENT or 0))
    if level == "critical":
        return (
            max(1, int(settings.NETWATCH_INGEST_CRITICAL_HOT_SAMPLE_PERCENT or 1)),
            max(1, int(settings.NETWATCH_INGEST_CRITICAL_CLICKHOUSE_SAMPLE_PERCENT or 10)),
            max(0, int(settings.NETWATCH_INGEST_BACKPRESSURE_WARM_SAMPLE_PERCENT or 2)),
            max(1, int(settings.NETWATCH_INGEST_RECENT_FEED_MIN_BATCH or 24)),
        )
    if level == "degraded":
        return (
            max(int(settings.NETWATCH_INGEST_STORM_HOT_SAMPLE_PERCENT or 2), int(settings.NETWATCH_INGEST_DEGRADED_HOT_SAMPLE_PERCENT or 5)),
            max(1, int(settings.NETWATCH_INGEST_DEGRADED_CLICKHOUSE_SAMPLE_PERCENT or 25)),
            max(0, int(settings.NETWATCH_INGEST_BACKPRESSURE_WARM_SAMPLE_PERCENT or 2)),
            max(1, int(settings.NETWATCH_INGEST_RECENT_FEED_MIN_BATCH or 24)),
        )
    if level == "elevated":
        return (
            max(1, int(settings.NETWATCH_INGEST_ELEVATED_HOT_SAMPLE_PERCENT or 50)),
            max(1, int(settings.NETWATCH_INGEST_CLICKHOUSE_SAMPLE_PERCENT or 100)),
            warm_pct,
            max(8, int(settings.NETWATCH_INGEST_RECENT_FEED_MIN_BATCH or 24) // 2),
        )
    return (100, max(1, int(settings.NETWATCH_INGEST_CLICKHOUSE_SAMPLE_PERCENT or 100)), warm_pct, 12 if storm_active else 8)


def _minimum_indexes(total: int, min_count: int) -> Set[int]:
    if total <= 0 or min_count <= 0:
        return set()
    target = min(total, max(0, int(min_count)))
    if target >= total:
        return set(range(total))
    if target == 1:
        return {0}
    out: Set[int] = set()
    for i in range(target):
        pos = round(i * (total - 1) / max(1, target - 1))
        out.add(int(pos))
    cur = 0
    while len(out) < target:
        out.add(cur)
        cur += 1
    return out


def _ensure_minimum(sampled: Set[int], total: int, min_count: int) -> Set[int]:
    out = set(sampled)
    out.update(_minimum_indexes(total, max(0, int(min_count)) - len(out)))
    return out


def _row_to_recent_payload(row: Sequence) -> Dict:
    return {
        "agent_id": row[0],
        "event_type": row[1],
        "schema_version": int(row[2] or 1),
        "timestamp": row[3],
        "src_ip": row[4],
        "dst_ip": row[5],
        "src_port": row[6],
        "dst_port": row[7],
        "proto": row[8],
        "bytes": row[9],
    }

def _fallback_direct_insert(*, hot_events: List[List], rollup_rows: List[List]) -> int:
    """Fail-open path if Redis is unavailable.

    This keeps the platform usable, but may increase DB pressure under storm.
    """

    stored = 0
    with engine.begin() as conn:
        if hot_events:
            raw_rows = [
                {
                    "agent_id": row[0],
                    "event_type": row[1],
                    "schema_version": int(row[2] or 1),
                    "timestamp": datetime.fromisoformat(row[3]),
                    "src_ip": row[4],
                    "dst_ip": row[5],
                    "src_port": row[6],
                    "dst_port": row[7],
                    "proto": row[8],
                    "bytes": row[9],
                    "extra": dict(row[10] or {}),
                }
                for row in hot_events
            ]
            conn.execute(insert(NetEventModel), raw_rows)
            stored = len(raw_rows)

        if rollup_rows:
            rr = [
                {
                    "bucket_ts": datetime.fromisoformat(rrow[0]),
                    "agent_id": rrow[1],
                    "event_type": rrow[2],
                    "dst_ip": rrow[3],
                    "dst_port": rrow[4],
                    "proto": rrow[5],
                    "count": int(rrow[6]),
                    "bytes_sum": int(rrow[7]),
                }
                for rrow in rollup_rows
            ]
            ins = insert(NetEventRollup1sModel).values(rr)
            upsert = ins.on_conflict_do_update(
                index_elements=[
                    NetEventRollup1sModel.bucket_ts,
                    NetEventRollup1sModel.agent_id,
                    NetEventRollup1sModel.event_type,
                    NetEventRollup1sModel.dst_ip,
                    NetEventRollup1sModel.dst_port,
                    NetEventRollup1sModel.proto,
                ],
                set_={
                    "count": NetEventRollup1sModel.count + ins.excluded.count,
                    "bytes_sum": NetEventRollup1sModel.bytes_sum + ins.excluded.bytes_sum,
                },
            )
            conn.execute(upsert)

    return int(stored)


def _fallback_clickhouse_insert(*, analytics_events: List[List]) -> int:
    if not analytics_events:
        return 0
    if not clickhouse_is_enabled():
        return 0

    try:
        if not ensure_clickhouse_events_schema():
            return 0
        ch = get_clickhouse_client()
        rows = []
        for ev in analytics_events:
            try:
                ts = datetime.fromisoformat(ev[3]) if (len(ev) > 3 and ev[3]) else datetime.now(timezone.utc)
            except Exception:
                ts = datetime.now(timezone.utc)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            extra = ev[10] if (len(ev) > 10 and isinstance(ev[10], dict)) else {}
            rows.append(
                (
                    ts,
                    0,
                    str(ev[0] if len(ev) > 0 else ""),
                    str(ev[1] if len(ev) > 1 else ""),
                    int(ev[2] if len(ev) > 2 and ev[2] is not None else 1),
                    str((extra or {}).get("severity") or "") or None,
                    (str(ev[4]) if len(ev) > 4 and ev[4] else None),
                    (str(ev[5]) if len(ev) > 5 and ev[5] else None),
                    (int(ev[6]) if len(ev) > 6 and ev[6] is not None else None),
                    (int(ev[7]) if len(ev) > 7 and ev[7] is not None else None),
                    (str(ev[8]) if len(ev) > 8 and ev[8] else None),
                    (int(ev[9]) if len(ev) > 9 and ev[9] is not None else None),
                    json.dumps(extra, ensure_ascii=False, separators=(",", ":"), default=str),
                )
            )
        ch.insert(
            clickhouse_events_table_ref(),
            rows,
            column_names=[
                "timestamp",
                "pg_event_id",
                "agent_id",
                "event_type",
                "schema_version",
                "severity",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "proto",
                "bytes",
                "extra_json",
            ],
        )
        return len(rows)
    except Exception as exc:
        log_event(logger, "warning", "ingest_fallback_clickhouse_error", error_type=type(exc).__name__)
        return 0


@router.get("/storm/status")
def storm_status(_: object = Depends(get_current_user)):
    """Storm Mode health payload for the Overview page."""

    return get_storm_status()


@router.post("/storm/recover")
def storm_recover(
    clear_backlog_counters: bool = Query(False, description="Also reset backlog event counter key."),
    clear_ui_caches: bool = Query(True, description="Clear overview/events/inventory redis caches."),
    _admin=Depends(require_admin),
):
    """Administrative runtime recovery for post-incident stuck states.

    Clears volatile ingest pressure/storm keys and cache keys so dashboards and
    timelines resume normal update behavior immediately.
    """

    res = recover_runtime_state(
        clear_backlog_counters=bool(clear_backlog_counters),
        clear_ui_caches=bool(clear_ui_caches),
    )
    if not bool(res.get("ok")):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(res.get("reason") or "recover_failed"))
    return res


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

    max_batch = max(1, int(settings.NETWATCH_INGEST_MAX_BATCH or 10000))
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
    max_skew_s = max(0, int(settings.NETWATCH_MAX_EVENT_CLOCK_SKEW_SECONDS or 30))

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
    level = _degradation_level(
        bp_mode=bp.mode,
        storm_active=storm_active,
        backlog_events=int(bp.backlog_events or 0),
        received=len(events),
    )

    rollup_always = bool(settings.NETWATCH_INGEST_ROLLUP_ALWAYS)
    do_rollup = rollup_always or active_for_metrics

    hot_pct, analytics_pct, warm_pct, recent_min_batch = _target_sample_policy(level=level, storm_active=storm_active)
    hot_pct = max(0, min(int(hot_pct), 100))
    analytics_pct = max(1, min(int(analytics_pct), 100))
    warm_pct = max(0, min(int(warm_pct), 100))

    # Normalize to deterministic sample.
    # We only send warm events when ES is enabled AND the event was NOT kept hot.
    warm_enabled = warm_pct > 0 and bool(settings.NETWATCH_INGEST_WARM_ENABLED)

    # Build rollups + sampled event payloads.
    all_rows: List[List] = []
    hot_events: List[List] = []
    analytics_events: List[List] = []
    warm_events: List[List] = []
    rollups: Dict[Tuple, Tuple[int, int]] = {}

    hot_selected: Set[int] = set()
    analytics_selected: Set[int] = set()
    warm_selected: Set[int] = set()

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

        idx = len(all_rows)
        all_rows.append(row)
        if keep_hot:
            hot_selected.add(idx)
        if stable_sample(seed=seed + "|analytics", sample_percent=analytics_pct):
            analytics_selected.add(idx)
        if keep_warm and not keep_hot:
            warm_selected.add(idx)

    hot_selected = _ensure_minimum(
        hot_selected,
        len(all_rows),
        int(settings.NETWATCH_INGEST_MIN_HOT_EVENTS_PER_BATCH or 1) if all_rows else 0,
    )
    analytics_selected = _ensure_minimum(
        analytics_selected,
        len(all_rows),
        int(settings.NETWATCH_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH or 32) if all_rows else 0,
    )
    recent_selected = _ensure_minimum(set(analytics_selected), len(all_rows), int(recent_min_batch or 0))

    for idx, row in enumerate(all_rows):
        if idx in hot_selected:
            hot_events.append(row)
        if idx in analytics_selected:
            analytics_events.append(row)
        if idx in warm_selected and idx not in hot_selected:
            warm_events.append(row)

    hot_kept = len(hot_events)
    warm_kept = len(warm_events)
    analytics_kept = len(analytics_events)

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
        "degradation_level": level,
        "storm_active": bool(storm_active),
        "storm_reason": storm_reason,
        "sample_hot_percent": hot_pct,
        "sample_analytics_percent": analytics_pct,
        "sample_warm_percent": warm_pct,
        "received": len(events),
        "hot_events": hot_events,
        "analytics_events": analytics_events,
        "warm_events": warm_events,
        "rollups": rollup_rows,
    }

    enqueued = enqueue_ingest_message(message=msg, received=len(events))

    # Redis unavailable: fail open to direct DB insert.
    if not enqueued:
        stored = _fallback_direct_insert(hot_events=hot_events, rollup_rows=rollup_rows)
        ch_stored = _fallback_clickhouse_insert(analytics_events=analytics_events)
        recent_feed_rows = [_row_to_recent_payload(all_rows[idx]) for idx in sorted(recent_selected)]
        pushed_recent = push_recent_events(recent_feed_rows) if (stored > 0 or ch_stored > 0) else 0

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
            "degradation_level": level,
            "storm_active": bool(storm_active),
            "storm_reason": storm_reason,
            "sample_hot_percent": hot_pct,
            "sample_analytics_percent": analytics_pct,
            "sample_warm_percent": warm_pct,
            "analytics_events": analytics_kept,
            "analytics_stored_clickhouse": int(ch_stored),
            "recent_visibility_events": pushed_recent,
            "rollups_written": bool(do_rollup),
            "backpressure": {"mode": bp.mode, "reason": bp.reason, "backlog_events": bp.backlog_events, "backlog_messages": bp.backlog_messages},
            "note": "redis_unavailable_fallback",
        }

    recent_feed_rows = [_row_to_recent_payload(all_rows[idx]) for idx in sorted(recent_selected)]
    pushed_recent = push_recent_events(recent_feed_rows)

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
        "degradation_level": level,
        "storm_active": bool(storm_active),
        "storm_reason": storm_reason,
        "sample_hot_percent": hot_pct,
        "sample_analytics_percent": analytics_pct,
        "sample_warm_percent": warm_pct,
        "analytics_events": analytics_kept,
        "recent_visibility_events": pushed_recent,
        "rollups_written": bool(do_rollup),
        "backpressure": {"mode": bp.mode, "reason": bp.reason, "backlog_events": bp.backlog_events, "backlog_messages": bp.backlog_messages},
    }
