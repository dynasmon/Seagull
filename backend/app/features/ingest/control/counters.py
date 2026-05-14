from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy.dialects.postgresql import insert

from app.core.cache import get_redis
from app.core.db import engine
from app.features.events.models import IngestStats1sModel
from app.features.ingest.control.backpressure import get_backlog
from app.features.ingest.control.queue_keys import (
    _as_int,
    _eps_key,
    _flush_lock_key,
    _quality_key,
    _stats_key,
)


def bump_ingest_counters(
    *,
    received: int,
    hot_kept: int,
    warm_kept: int,
    dropped: int,
    rejected: int,
    rollup_only: int,
    storm_active: bool,
    sample_hot: int,
    sample_warm: int,
) -> None:
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
        pipe.hset(
            hk,
            mapping={
                "storm_active": "1" if storm_active else "0",
                "sample_hot": str(int(sample_hot)),
                "sample_warm": str(int(sample_warm)),
            },
        )
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


def maybe_flush_stats_to_db() -> None:
    """Flush the previous second's Redis stats to Postgres (at most once per second)."""

    r = get_redis()
    if r is None:
        return

    now_s = int(time.time())
    ts_s = now_s - 1

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
        return
