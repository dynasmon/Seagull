from __future__ import annotations

import os
import threading
import zlib
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text

from app.core.db import SessionLocal
from app.core.es import es_is_available, get_es_client
from app.core.redis_client import get_redis

from app.core.portal_auth import get_current_user

router = APIRouter(
    prefix="",
    tags=["overview"],
    dependencies=[Depends(get_current_user)],
)

_overview_cache_lock = threading.Lock()
_overview_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def _env_int(name: str, default: int) -> int:
    import os

    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if not raw:
        return default
    try:
        return int(raw, 10)
    except Exception:
        return default


def _overview_cache_get(key: str) -> Optional[Dict[str, Any]]:
    ttl_s = max(0, _env_int("NETWATCH_OVERVIEW_CACHE_TTL_SECONDS", 3))
    if ttl_s <= 0:
        return None
    now = time.time()
    with _overview_cache_lock:
        item = _overview_cache.get(key)
        if not item:
            return None
        expires_at, payload = item
        if expires_at <= now:
            _overview_cache.pop(key, None)
            return None
        return payload


def _overview_cache_set(key: str, payload: Dict[str, Any]) -> None:
    ttl_s = max(0, _env_int("NETWATCH_OVERVIEW_CACHE_TTL_SECONDS", 3))
    if ttl_s <= 0:
        return
    now = time.time()
    max_entries = max(16, _env_int("NETWATCH_OVERVIEW_CACHE_MAX_ENTRIES", 128))
    with _overview_cache_lock:
        _overview_cache[key] = (now + float(ttl_s), payload)
        if len(_overview_cache) > max_entries:
            # Best-effort trim by expiry timestamp.
            keys = sorted(_overview_cache.items(), key=lambda kv: kv[1][0])
            for k, _ in keys[: max(1, len(_overview_cache) - max_entries)]:
                _overview_cache.pop(k, None)


def _utc_now() -> datetime:
    """Return timezone-aware UTC 'now'."""
    return datetime.now(timezone.utc)


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    return raw if raw else default


def _best_effort_ingest_backlog() -> Tuple[int, int]:
    """Return (backlog_events, backlog_messages) from Redis best-effort."""

    r = get_redis()
    if r is None:
        return (0, 0)

    try:
        backlog_key = _env_str("NETWATCH_INGEST_BACKLOG_EVENTS_KEY", "netwatch:ingest:backlog_events")
        qk = _env_str("NETWATCH_INGEST_QUEUE_KEY", "netwatch:ingest:queue")
        pk = _env_str("NETWATCH_INGEST_PROCESSING_KEY", f"{qk}:processing")

        ev = int(r.get(backlog_key) or 0)
        msgs = int(r.llen(qk) or 0) + int(r.llen(pk) or 0)
        return (max(0, ev), max(0, msgs))
    except Exception:
        return (0, 0)


def _storm_key_active() -> bool:
    """Return True if the ingest protection (storm/backpressure) key is active in Redis."""

    r = get_redis()
    if r is None:
        return False

    try:
        k = _env_str("NETWATCH_INGEST_STORM_ACTIVE_KEY", "netwatch:ingest:storm_active")
        return bool(r.get(k))
    except Exception:
        return False


def _warm_index_prefix() -> str:
    return _env_str(
        "NETWATCH_INGEST_WARM_INDEX_PREFIX",
        _env_str("NETWATCH_ES_INDEX_PREFIX", "netwatch-events") + "-warm",
    )


def _warm_recent_events(*, agent_id: Optional[str], start_ts: datetime, end_ts: datetime, limit: int = 30) -> List[Dict[str, Any]]:
    """Fetch a small sample of recent events from the warm tier (Elasticsearch).

    This keeps the UI usable when hot (Postgres) storage is heavily sampled.
    """

    if not es_is_available():
        return []

    try:
        es = get_es_client()

        must: List[Dict[str, Any]] = []
        if agent_id:
            must.append({"term": {"agent_id": agent_id}})

        # Keep it bounded so we don't scan large warm tiers.
        must.append({"range": {"timestamp": {"gte": start_ts.isoformat(), "lte": end_ts.isoformat()}}})

        q = {"bool": {"must": must}} if must else {"match_all": {}}

        resp = es.search(
            index=f"{_warm_index_prefix()}-*",
            size=max(1, min(int(limit), 200)),
            sort=[{"timestamp": {"order": "desc"}}],
            query=q,
            track_total_hits=False,
            source=["timestamp", "agent_id", "event_type", "src_ip", "dst_ip", "dst_port"],
        )

        out: List[Dict[str, Any]] = []
        for hit in (resp.get("hits") or {}).get("hits") or []:
            src = hit.get("_source") or {}
            ts = src.get("timestamp")
            aid = src.get("agent_id")
            et = src.get("event_type")
            if not ts or not aid or not et:
                continue

            # UI expects a numeric id; generate a stable-ish one.
            raw_id = f"{aid}|{et}|{ts}|{src.get('dst_ip','')}|{src.get('dst_port','')}"
            eid = int(zlib.crc32(raw_id.encode("utf-8")) & 0xFFFFFFFF)

            out.append(
                {
                    "id": eid,
                    "timestamp": ts,
                    "agent_id": aid,
                    "event_type": et,
                    "src_ip": src.get("src_ip"),
                    "dst_ip": src.get("dst_ip"),
                    "dst_port": src.get("dst_port"),
                }
            )

        return out
    except Exception:
        return []


def _fmt_hhmm(dt: datetime) -> str:
    """Format a datetime to HH:MM (24h)."""
    # If dt is naive, assume UTC. Prefer tz-aware everywhere.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%H:%M")


def _make_buckets_rows(rows: List[Dict[str, Any]], series_keys: List[str], alias_map: Dict[str, str]) -> List[Dict[str, Any]]:
    """Convert SQL rows with fixed aliases into chart rows with dynamic keys.

    Example:
      SQL returns: {bucket_ts, s1, s2, s3, other}
      alias_map: {"s1": "flow", "s2": "ssh_auth", "s3": "dos_attack", "other": "other"}
      Output: {t: "12:30", "flow": 10, "ssh_auth": 2, "dos_attack": 1, "other": 7}
    """
    out: List[Dict[str, Any]] = []
    for r in rows:
        ts = r.get("bucket_ts")
        if ts is None:
            continue
        row = {"t": _fmt_hhmm(ts)}
        for k in series_keys:
            row[k] = 0

        # Fill based on alias_map
        for alias, key_name in alias_map.items():
            if key_name in series_keys:
                row[key_name] = int(r.get(alias) or 0)

        out.append(row)
    return out


def _top_event_types(db, start_ts: datetime, end_ts: datetime, agent_id: Optional[str]) -> List[str]:
    """Find top 3 event_types in the window using rollups (fallback to net_events)."""

    params = {"start_ts": start_ts, "end_ts": end_ts, "agent_id": agent_id}

    # Prefer rollups: much cheaper than scanning net_events.
    # Exclude summary-only synthetic events so traffic charts keep operational signal.
    q_rollups = text(
        r"""
        SELECT event_type, SUM(count) AS total
        FROM event_rollups_1m
        WHERE bucket_ts >= :start_ts
          AND bucket_ts <= :end_ts
          AND (:agent_id IS NULL OR agent_id = :agent_id)
          AND event_type IS NOT NULL
          AND event_type NOT LIKE '%\_summary' ESCAPE '\'
        GROUP BY event_type
        ORDER BY total DESC
        LIMIT 3;
        """
    )
    rows = db.execute(q_rollups, params).mappings().all()
    if rows:
        return [str(r["event_type"]) for r in rows if r.get("event_type")]

    # Fallback: raw events
    q_raw = text(
        r"""
        SELECT event_type, COUNT(*) AS total
        FROM net_events
        WHERE "timestamp" >= :start_ts
          AND "timestamp" <= :end_ts
          AND (:agent_id IS NULL OR agent_id = :agent_id)
          AND event_type IS NOT NULL
          AND event_type NOT LIKE '%\_summary' ESCAPE '\'
        GROUP BY event_type
        ORDER BY total DESC
        LIMIT 3;
        """
    )
    rows2 = db.execute(q_raw, params).mappings().all()
    return [str(r["event_type"]) for r in rows2 if r.get("event_type")]


@router.get("/overview")
def get_overview(
    window_minutes: int = Query(60, ge=5, le=1440, description="Time window (minutes) for charts"),
    agent_id: Optional[str] = Query(None, description="Optional agent filter for charts/tables"),
    lite: bool = Query(False, description="If true, skip heavy tables for faster first paint"),
):
    """Return an aggregated snapshot for the portal Overview page.

    Design goals:
    - Fast refresh (Grafana-like polling)
    - Minimal client-side aggregation
    - Prefer rollup tables when available
    """

    cache_key = f"w={int(window_minutes)}|a={agent_id or '*'}|lite={1 if lite else 0}"
    cached = _overview_cache_get(cache_key)
    if cached is not None:
        return cached

    now = _utc_now()

    # Redis-backed queue/backpressure provides backlog + draining signals.
    backlog_ev, backlog_msgs = _best_effort_ingest_backlog()

    db = SessionLocal()
    try:
        # -----------------------------
        # Ingest pressure + rollup availability detection
        # -----------------------------
        # IMPORTANT: the async ingest queue can be briefly non-empty even under
        # normal traffic. Do NOT switch data sources based solely on backlog.
        # Only use 1-second ingest rollups when they are actually being produced
        # (storm/backpressure or explicit rollup-always).

        pressure_window_s = max(30, _env_int("NETWATCH_OVERVIEW_PRESSURE_LOOKBACK_SECONDS", 120))
        rollup_fresh_s = max(10, _env_int("NETWATCH_OVERVIEW_INGEST_ROLLUP_FRESH_SECONDS", 120))
        draining_ev_threshold = max(0, _env_int("NETWATCH_OVERVIEW_DRAINING_BACKLOG_EVENTS_THRESHOLD", 25_000))
        draining_msg_threshold = max(0, _env_int("NETWATCH_OVERVIEW_DRAINING_BACKLOG_MESSAGES_THRESHOLD", 5))

        protection_active = _storm_key_active()

        # DB signal: recent ingest_stats_1s rows (storm/backpressure paths only).
        try:
            q_pressure = text(
                """
                SELECT
                  COALESCE(MAX(CASE WHEN storm_active THEN 1 ELSE 0 END), 0)::int AS storm_active,
                  COALESCE(SUM(rollup_only), 0)::bigint AS rollup_only,
                  COALESCE(MIN(sample_hot_percent), 100)::int AS min_hot
                FROM ingest_stats_1s
                WHERE bucket_ts >= (now() AT TIME ZONE 'utc') - (:window_s || ' seconds')::interval;
                """
            )
            pr = db.execute(q_pressure, {"window_s": int(pressure_window_s)}).mappings().first() or {}
            protection_active = protection_active or int(pr.get("storm_active") or 0) == 1
            protection_active = protection_active or int(pr.get("rollup_only") or 0) > 0
            protection_active = protection_active or int(pr.get("min_hot") or 100) < 100
        except Exception:
            # Fail open: keep only the Redis key signal.
            pass

        # Check whether ingest rollups exist and are fresh.
        last_roll_ts = None
        try:
            q_last_roll = text(
                """
                SELECT MAX(bucket_ts) AS last_bucket_ts
                FROM net_event_rollups_1s
                WHERE bucket_ts >= (now() AT TIME ZONE 'utc') - interval '2 days'
                  AND (:agent_id IS NULL OR agent_id = :agent_id);
                """
            )
            rr = db.execute(q_last_roll, {"agent_id": agent_id}).mappings().first() or {}
            last_roll_ts = rr.get("last_bucket_ts")
            if last_roll_ts is not None and last_roll_ts.tzinfo is None:
                last_roll_ts = last_roll_ts.replace(tzinfo=timezone.utc)
        except Exception:
            last_roll_ts = None

        rollups_fresh = False
        if last_roll_ts is not None:
            try:
                rollups_fresh = (now - last_roll_ts).total_seconds() <= float(rollup_fresh_s)
            except Exception:
                rollups_fresh = False

        draining = (backlog_ev >= draining_ev_threshold and draining_ev_threshold > 0) or (backlog_msgs >= draining_msg_threshold and draining_msg_threshold > 0)

        use_ingest_rollups = bool(rollups_fresh and (protection_active or draining))

        # Anchor the window to the freshest data_end_ts when ingest rollups are used.
        data_end_ts = last_roll_ts if (use_ingest_rollups and last_roll_ts is not None) else now

        start_ts = data_end_ts - timedelta(minutes=window_minutes)
        params = {"start_ts": start_ts, "end_ts": data_end_ts, "agent_id": agent_id}

        # -----------------------------
        # KPIs
        # -----------------------------
        q_agents = text(
            """
            SELECT
              COUNT(*)::int AS total_agents,
              COUNT(*) FILTER (WHERE last_seen_at >= (now() AT TIME ZONE 'utc') - interval '5 minutes')::int AS online_agents
            FROM agents;
            """
        )
        ag = db.execute(q_agents).mappings().first() or {}

        q_alerts = text(
            """
            SELECT
              COUNT(*) FILTER (WHERE created_at >= (now() AT TIME ZONE 'utc') - interval '60 minutes')::int AS alerts_60m
            FROM alerts;
            """
        )
        al = db.execute(q_alerts).mappings().first() or {}

        events_5m = 0
        last_event_ts = None

        if use_ingest_rollups:
            # When draining, report event KPIs relative to the latest known data_end_ts.
            q_ev = text(
                """
                SELECT
                  COALESCE(SUM(count), 0)::bigint AS events_5m
                FROM net_event_rollups_1s
                WHERE bucket_ts >= :start_5m
                  AND bucket_ts <= :end_5m
                  AND (:agent_id IS NULL OR agent_id = :agent_id);
                """
            )
            rr = db.execute(
                q_ev,
                {
                    "start_5m": data_end_ts - timedelta(minutes=5),
                    "end_5m": data_end_ts,
                    "agent_id": agent_id,
                },
            ).mappings().first() or {}
            events_5m = int(rr.get("events_5m") or 0)
            last_event_ts = data_end_ts if last_roll_ts is not None else None
        else:
            q_ev2 = text(
                """
                SELECT
                  COUNT(*) FILTER (WHERE "timestamp" >= (now() AT TIME ZONE 'utc') - interval '5 minutes')::int AS events_5m,
                  MAX("timestamp") AS last_event_ts
                FROM net_events
                WHERE (:agent_id IS NULL OR agent_id = :agent_id);
                """
            )
            rr2 = db.execute(q_ev2, {"agent_id": agent_id}).mappings().first() or {}
            events_5m = int(rr2.get("events_5m") or 0)
            last_event_ts = rr2.get("last_event_ts")
            if last_event_ts is not None and last_event_ts.tzinfo is None:
                last_event_ts = last_event_ts.replace(tzinfo=timezone.utc)

        last_event_age_m = None
        if last_event_ts is not None:
            try:
                last_event_age_m = int(((now - last_event_ts).total_seconds()) // 60)
            except Exception:
                last_event_age_m = None

        kpis = {
            "total_agents": int(ag.get("total_agents") or 0),
            "online_agents": int(ag.get("online_agents") or 0),
            "events_5m": int(events_5m),
            "alerts_60m": int(al.get("alerts_60m") or 0),
            "last_event_age_m": last_event_age_m,
        }

        # -----------------------------
        # Traffic time-series (top 3 event_types + other)
        # Prefer rollups (event_rollups_1m).
        # -----------------------------
        # For time-series: prefer event_rollups_1m (cheap). Under ingest pressure,
        # fall back to net_event_rollups_1s aggregated by minute.
        if use_ingest_rollups:
            q_top = text(
                r"""
                SELECT event_type, SUM(count) AS total
                FROM net_event_rollups_1s
                WHERE bucket_ts >= :start_ts
                  AND bucket_ts <= :end_ts
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                  AND event_type IS NOT NULL
                  AND event_type NOT LIKE '%\_summary' ESCAPE '\'
                GROUP BY event_type
                ORDER BY total DESC
                LIMIT 3;
                """
            )
            rows_top = db.execute(q_top, params).mappings().all()
            top_types = [str(r["event_type"]) for r in rows_top if r.get("event_type")]
        else:
            top_types = _top_event_types(db, start_ts, data_end_ts, agent_id)
        while len(top_types) < 3:
            top_types.append(None)  # placeholder for query binding

        t1, t2, t3 = top_types[0], top_types[1], top_types[2]

        if use_ingest_rollups:
            # Under pressure/draining, always build from ingest rollups.
            q_traffic2 = text(
                r"""
                WITH buckets AS (
                  SELECT generate_series(
                    date_trunc('minute', :start_ts),
                    date_trunc('minute', :end_ts),
                    interval '1 minute'
                  ) AS bucket_ts
                ),
                agg AS (
                  SELECT
                    date_trunc('minute', bucket_ts) AS bucket_ts,
                    event_type,
                    SUM(count)::bigint AS cnt
                  FROM net_event_rollups_1s
                  WHERE bucket_ts >= :start_ts
                    AND bucket_ts <= :end_ts
                    AND (:agent_id IS NULL OR agent_id = :agent_id)
                    AND event_type IS NOT NULL
                    AND event_type NOT LIKE '%\_summary' ESCAPE '\'
                  GROUP BY 1, 2
                )
                SELECT
                  b.bucket_ts,
                  COALESCE(SUM(CASE WHEN agg.event_type = :t1 THEN agg.cnt END), 0)::bigint AS s1,
                  COALESCE(SUM(CASE WHEN agg.event_type = :t2 THEN agg.cnt END), 0)::bigint AS s2,
                  COALESCE(SUM(CASE WHEN agg.event_type = :t3 THEN agg.cnt END), 0)::bigint AS s3,
                  COALESCE(SUM(CASE WHEN agg.event_type IS NOT NULL AND agg.event_type NOT IN (:t1, :t2, :t3) THEN agg.cnt END), 0)::bigint AS other
                FROM buckets b
                LEFT JOIN agg ON agg.bucket_ts = b.bucket_ts
                GROUP BY b.bucket_ts
                ORDER BY b.bucket_ts ASC;
                """
            )
            traffic_rows = db.execute(q_traffic2, {**params, "t1": t1, "t2": t2, "t3": t3}).mappings().all()
        else:
            q_traffic = text(
                r"""
                WITH buckets AS (
                  SELECT generate_series(
                    date_trunc('minute', :start_ts),
                    date_trunc('minute', :end_ts),
                    interval '1 minute'
                  ) AS bucket_ts
                ),
                agg AS (
                  SELECT
                    date_trunc('minute', bucket_ts) AS bucket_ts,
                    event_type,
                    SUM(count)::bigint AS cnt
                  FROM event_rollups_1m
                  WHERE bucket_ts >= :start_ts
                    AND bucket_ts <= :end_ts
                    AND (:agent_id IS NULL OR agent_id = :agent_id)
                    AND event_type IS NOT NULL
                    AND event_type NOT LIKE '%\_summary' ESCAPE '\'
                  GROUP BY 1, 2
                )
                SELECT
                  b.bucket_ts,
                  COALESCE(SUM(CASE WHEN agg.event_type = :t1 THEN agg.cnt END), 0)::bigint AS s1,
                  COALESCE(SUM(CASE WHEN agg.event_type = :t2 THEN agg.cnt END), 0)::bigint AS s2,
                  COALESCE(SUM(CASE WHEN agg.event_type = :t3 THEN agg.cnt END), 0)::bigint AS s3,
                  COALESCE(SUM(CASE WHEN agg.event_type IS NOT NULL AND agg.event_type NOT IN (:t1, :t2, :t3) THEN agg.cnt END), 0)::bigint AS other
                FROM buckets b
                LEFT JOIN agg ON agg.bucket_ts = b.bucket_ts
                GROUP BY b.bucket_ts
                ORDER BY b.bucket_ts ASC;
                """
            )
            traffic_rows = db.execute(q_traffic, {**params, "t1": t1, "t2": t2, "t3": t3}).mappings().all()

        traffic_series = [x for x in [t1, t2, t3] if x] + ["other"]
        alias_map = {"s1": t1 or "x1", "s2": t2 or "x2", "s3": t3 or "x3", "other": "other"}
        traffic_data = _make_buckets_rows(traffic_rows, traffic_series, alias_map)

        # -----------------------------
        # SSH failures time-series (rollup)
        # failures = SUM(count) where action != 'accepted'
        # -----------------------------
        q_ssh = text(
            """
            WITH buckets AS (
              SELECT generate_series(
                date_trunc('minute', :start_ts),
                date_trunc('minute', :end_ts),
                interval '1 minute'
              ) AS bucket_ts
            ),
            agg AS (
              SELECT
                date_trunc('minute', bucket_ts) AS bucket_ts,
                SUM(count)::bigint AS failures
              FROM ssh_fail_rollups_1m
              WHERE bucket_ts >= :start_ts
                AND bucket_ts <= :end_ts
                AND action <> 'accepted'
                AND (:agent_id IS NULL OR agent_id = :agent_id)
              GROUP BY 1
            )
            SELECT
              b.bucket_ts,
              COALESCE(a.failures, 0)::bigint AS failures
            FROM buckets b
            LEFT JOIN agg a ON a.bucket_ts = b.bucket_ts
            ORDER BY b.bucket_ts ASC;
            """
        )
        ssh_rows = db.execute(q_ssh, params).mappings().all()
        ssh_data = [{"t": _fmt_hhmm(r["bucket_ts"]), "failures": int(r["failures"] or 0)} for r in ssh_rows]
        ssh_series = ["failures"]

        # -----------------------------
        # Alerts severity time-series
        # -----------------------------
        q_sev = text(
            """
            WITH buckets AS (
              SELECT generate_series(
                date_trunc('minute', :start_ts),
                date_trunc('minute', :end_ts),
                interval '1 minute'
              ) AS bucket_ts
            ),
            agg AS (
              SELECT
                date_trunc('minute', created_at) AS bucket_ts,
                lower(COALESCE(severity, 'unknown')) AS sev,
                COUNT(*)::bigint AS cnt
              FROM alerts
              WHERE created_at >= :start_ts
                AND created_at <= :end_ts
              GROUP BY 1, 2
            )
            SELECT
              b.bucket_ts,
              COALESCE(SUM(CASE WHEN agg.sev = 'critical' THEN agg.cnt END), 0)::bigint AS critical,
              COALESCE(SUM(CASE WHEN agg.sev = 'high' THEN agg.cnt END), 0)::bigint AS high,
              COALESCE(SUM(CASE WHEN agg.sev = 'medium' THEN agg.cnt END), 0)::bigint AS medium,
              COALESCE(SUM(CASE WHEN agg.sev = 'low' THEN agg.cnt END), 0)::bigint AS low,
              COALESCE(SUM(CASE WHEN agg.sev NOT IN ('critical','high','medium','low') THEN agg.cnt END), 0)::bigint AS unknown
            FROM buckets b
            LEFT JOIN agg ON agg.bucket_ts = b.bucket_ts
            GROUP BY b.bucket_ts
            ORDER BY b.bucket_ts ASC;
            """
        )
        sev_rows = db.execute(q_sev, params).mappings().all()
        sev_series = ["critical", "high", "medium", "low", "unknown"]
        sev_data = [
            {
                "t": _fmt_hhmm(r["bucket_ts"]),
                "critical": int(r["critical"] or 0),
                "high": int(r["high"] or 0),
                "medium": int(r["medium"] or 0),
                "low": int(r["low"] or 0),
                "unknown": int(r["unknown"] or 0),
            }
            for r in sev_rows
        ]

        # -----------------------------
        # DDoS time-series (ONLY critical/high) by rule_id prefix
        # -----------------------------
        q_ddos = text(
            r"""
            WITH buckets AS (
              SELECT generate_series(
                date_trunc('minute', :start_ts),
                date_trunc('minute', :end_ts),
                interval '1 minute'
              ) AS bucket_ts
            ),
            dd AS (
              SELECT
                date_trunc('minute', created_at) AS bucket_ts,
                lower(severity) AS sev,
                COUNT(*)::bigint AS cnt
              FROM alerts
              WHERE created_at >= :start_ts
                AND created_at <= :end_ts
                AND lower(severity) IN ('critical','high')
                AND (
                  rule_id = 'incident_ddos_correlated_v1'
                  OR rule_id LIKE 'ddos\_%' ESCAPE '\'
                  OR rule_id LIKE 'dos\_%'  ESCAPE '\'
                  OR rule_id LIKE 'l7\_%'   ESCAPE '\'
                )
              GROUP BY 1, 2
            )
            SELECT
              b.bucket_ts,
              COALESCE(SUM(CASE WHEN dd.sev = 'critical' THEN dd.cnt END), 0)::bigint AS critical,
              COALESCE(SUM(CASE WHEN dd.sev = 'high' THEN dd.cnt END), 0)::bigint AS high
            FROM buckets b
            LEFT JOIN dd ON dd.bucket_ts = b.bucket_ts
            GROUP BY b.bucket_ts
            ORDER BY b.bucket_ts ASC;
            """
        )
        ddos_rows = db.execute(q_ddos, params).mappings().all()
        ddos_series = ["critical", "high"]
        ddos_data = [
            {
                "t": _fmt_hhmm(r["bucket_ts"]),
                "critical": int(r["critical"] or 0),
                "high": int(r["high"] or 0),
            }
            for r in ddos_rows
        ]

        # DDoS volume time-series (packets + peak pps) from dos_attack extras
        q_ddos_volume = text(
            r"""
            WITH buckets AS (
              SELECT generate_series(
                date_trunc('minute', :start_ts),
                date_trunc('minute', :end_ts),
                interval '1 minute'
              ) AS bucket_ts
            ),
            agg AS (
              SELECT
                date_trunc('minute', "timestamp") AS bucket_ts,
                COALESCE(
                  SUM(
                    CASE
                      WHEN (extra->>'packets') ~ '^[0-9]+(\.[0-9]+)?$'
                      THEN (extra->>'packets')::double precision
                      ELSE 0
                    END
                  ),
                  0
                )::bigint AS packets,
                COALESCE(
                  MAX(
                    CASE
                      WHEN (extra->>'pps') ~ '^[0-9]+(\.[0-9]+)?$'
                      THEN (extra->>'pps')::double precision
                      ELSE 0
                    END
                  ),
                  0
                ) AS peak_pps
              FROM net_events
              WHERE "timestamp" >= :start_ts
                AND "timestamp" <= :end_ts
                AND event_type = 'dos_attack'
                AND (:agent_id IS NULL OR agent_id = :agent_id)
              GROUP BY 1
            )
            SELECT
              b.bucket_ts,
              COALESCE(a.packets, 0)::bigint AS packets,
              COALESCE(a.peak_pps, 0)::double precision AS peak_pps
            FROM buckets b
            LEFT JOIN agg a ON a.bucket_ts = b.bucket_ts
            ORDER BY b.bucket_ts ASC;
            """
        )
        ddos_vol_rows = db.execute(q_ddos_volume, params).mappings().all()
        ddos_volume_series = ["packets", "peak_pps"]
        ddos_volume_data = [
            {
                "t": _fmt_hhmm(r["bucket_ts"]),
                "packets": int(r["packets"] or 0),
                "peak_pps": float(r["peak_pps"] or 0),
            }
            for r in ddos_vol_rows
        ]

        ports: List[Dict[str, Any]] = []
        top_sources: List[Dict[str, Any]] = []
        recent_alerts: List[Dict[str, Any]] = []
        ddos_alerts: List[Dict[str, Any]] = []
        recent_ssh: List[Dict[str, Any]] = []
        raw_events: List[Dict[str, Any]] = []

        if not lite:
            # -----------------------------
            # Ports distribution (window)
            # -----------------------------
            if use_ingest_rollups:
                q_ports = text(
                    """
                    SELECT
                      dst_port AS port,
                      SUM(count)::bigint AS count
                    FROM net_event_rollups_1s
                    WHERE bucket_ts >= :start_ts
                      AND bucket_ts <= :end_ts
                      AND dst_port IS NOT NULL
                      AND (:agent_id IS NULL OR agent_id = :agent_id)
                    GROUP BY dst_port
                    ORDER BY count DESC
                    LIMIT 10;
                    """
                )
                ports = [
                    {"port": int(r["port"]), "count": int(r["count"] or 0)}
                    for r in db.execute(q_ports, params).mappings().all()
                    if r.get("port") is not None
                ]
            else:
                q_ports = text(
                    """
                    SELECT
                      dst_port AS port,
                      COUNT(*)::bigint AS count
                    FROM net_events
                    WHERE "timestamp" >= :start_ts
                      AND "timestamp" <= :end_ts
                      AND dst_port IS NOT NULL
                      AND (:agent_id IS NULL OR agent_id = :agent_id)
                    GROUP BY dst_port
                    ORDER BY count DESC
                    LIMIT 10;
                    """
                )
                ports = [
                    {"port": int(r["port"]), "count": int(r["count"] or 0)}
                    for r in db.execute(q_ports, params).mappings().all()
                    if r.get("port") is not None
                ]

            # -----------------------------
            # Top sources (window)
            # -----------------------------
            q_sources = text(
                """
                SELECT
                  src_ip,
                  COUNT(*)::bigint AS count
                FROM net_events
                WHERE "timestamp" >= :start_ts
                  AND "timestamp" <= :end_ts
                  AND src_ip IS NOT NULL
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT 10;
                """
            )
            top_sources = [
                {"src_ip": str(r["src_ip"]), "count": int(r["count"] or 0)}
                for r in db.execute(q_sources, params).mappings().all()
                if r.get("src_ip")
            ]

            # -----------------------------
            # Recent alerts (table)
            # -----------------------------
            q_recent_alerts = text(
                """
                SELECT id, created_at, rule_id, severity, src_ip, dst_ip, dst_port, description, details
                FROM alerts
                ORDER BY created_at DESC
                LIMIT 25;
                """
            )
            recent_alerts = [dict(r) for r in db.execute(q_recent_alerts).mappings().all()]

            # -----------------------------
            # Recent DDoS alerts (table) - ONLY critical/high
            # -----------------------------
            q_ddos_alerts = text(
                r"""
                SELECT id, created_at, rule_id, severity, src_ip, dst_ip, dst_port, description, details
                FROM alerts
                WHERE lower(severity) IN ('critical','high')
                  AND (
                    rule_id = 'incident_ddos_correlated_v1'
                    OR rule_id LIKE 'ddos\_%' ESCAPE '\'
                    OR rule_id LIKE 'dos\_%'  ESCAPE '\'
                    OR rule_id LIKE 'l7\_%'   ESCAPE '\'
                  )
                ORDER BY created_at DESC
                LIMIT 15;
                """
            )
            ddos_alerts = [dict(r) for r in db.execute(q_ddos_alerts).mappings().all()]

            # -----------------------------
            # Recent SSH stream (table)
            # -----------------------------
            q_ssh_stream = text(
                """
                SELECT
                  "timestamp" AS ts,
                  id,
                  src_ip,
                  dst_ip,
                  extra
                FROM net_events
                WHERE event_type = 'ssh_auth'
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                ORDER BY "timestamp" DESC, id DESC
                LIMIT 20;
                """
            )
            ssh_stream_rows = db.execute(q_ssh_stream, {"agent_id": agent_id}).mappings().all()
            for r in ssh_stream_rows:
                extra = r.get("extra") or {}
                recent_ssh.append(
                    {
                        "ts": _fmt_hhmm(r["ts"]),
                        "src": str(r.get("src_ip") or "-"),
                        "dst": str(r.get("dst_ip") or "-"),
                        "user": str((extra or {}).get("username") or "-"),
                        "action": str((extra or {}).get("action") or "-"),
                    }
                )

            # -----------------------------
            # Raw event stream
            # -----------------------------
            if use_ingest_rollups:
                raw_events = _warm_recent_events(agent_id=agent_id, start_ts=start_ts, end_ts=data_end_ts, limit=30)
                if not raw_events:
                    q_hot_fallback = text(
                        """
                        SELECT id, "timestamp", agent_id, event_type, src_ip, dst_ip, dst_port
                        FROM net_events
                        WHERE (:agent_id IS NULL OR agent_id = :agent_id)
                        ORDER BY "timestamp" DESC, id DESC
                        LIMIT 30;
                        """
                    )
                    raw_events = [dict(r) for r in db.execute(q_hot_fallback, {"agent_id": agent_id}).mappings().all()]
                if not raw_events and last_roll_ts is not None:
                    raw_events = [
                        {
                            "id": 0,
                            "timestamp": last_roll_ts.isoformat(),
                            "agent_id": agent_id or "-",
                            "event_type": "rollup",
                            "src_ip": None,
                            "dst_ip": None,
                            "dst_port": None,
                        }
                    ]
            else:
                q_raw_events = text(
                    """
                    SELECT id, "timestamp", agent_id, event_type, src_ip, dst_ip, dst_port
                    FROM net_events
                    WHERE (:agent_id IS NULL OR agent_id = :agent_id)
                    ORDER BY "timestamp" DESC, id DESC
                    LIMIT 30;
                    """
                )
                raw_events = [dict(r) for r in db.execute(q_raw_events, {"agent_id": agent_id}).mappings().all()]

        data_lag_s = int(max(0.0, (now - data_end_ts).total_seconds()))

        payload = {
            "meta": {
                "lite": bool(lite),
                "use_ingest_rollups": bool(use_ingest_rollups),
                "protection_active": bool(protection_active),
                "draining": bool(draining),
                "rollups_fresh": bool(rollups_fresh),
                "rollups_last_bucket": (last_roll_ts.isoformat() if last_roll_ts is not None else None),
                "window_start": start_ts.isoformat(),
                "window_end": data_end_ts.isoformat(),
                "data_lag_seconds": data_lag_s,
                "backlog_events": int(backlog_ev),
                "backlog_messages": int(backlog_msgs),
            },
            "kpis": kpis,
            "traffic": {"series": traffic_series, "data": traffic_data},
            "ssh_failures": {"series": ssh_series, "data": ssh_data},
            "alert_severity": {"series": sev_series, "data": sev_data},
            "ddos": {"series": ddos_series, "data": ddos_data},
            "ddos_volume": {"series": ddos_volume_series, "data": ddos_volume_data},
            "ports": ports,
            "top_sources": top_sources,
            "recent_alerts": recent_alerts,
            "ddos_alerts": ddos_alerts,
            "recent_ssh": recent_ssh,
            "raw_events": raw_events,
        }
        _overview_cache_set(cache_key, payload)
        return payload
    finally:
        db.close()
