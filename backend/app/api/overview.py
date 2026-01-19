from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Query, Depends, Request
from sqlalchemy import text

from app.core.db import SessionLocal

from app.core.admin_auth import require_admin


def _admin_dep(request: Request) -> None:
    require_admin(request)

router = APIRouter(
    prefix="",
    tags=["overview"],
    dependencies=[Depends(_admin_dep)],
)


def _utc_now() -> datetime:
    """Return timezone-aware UTC 'now'."""
    return datetime.now(timezone.utc)


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
    q_rollups = text(
        """
        SELECT event_type, SUM(count) AS total
        FROM event_rollups_1m
        WHERE bucket_ts >= :start_ts
          AND bucket_ts <= :end_ts
          AND (:agent_id IS NULL OR agent_id = :agent_id)
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
        """
        SELECT event_type, COUNT(*) AS total
        FROM net_events
        WHERE "timestamp" >= :start_ts
          AND "timestamp" <= :end_ts
          AND (:agent_id IS NULL OR agent_id = :agent_id)
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
):
    """Return an aggregated snapshot for the portal Overview page.

    Design goals:
    - Fast refresh (Grafana-like polling)
    - Minimal client-side aggregation
    - Prefer rollup tables when available
    """

    now = _utc_now()
    start_ts = now - timedelta(minutes=window_minutes)

    db = SessionLocal()
    try:
        params = {"start_ts": start_ts, "end_ts": now, "agent_id": agent_id}

        # -----------------------------
        # KPIs
        # -----------------------------
        q_kpis = text(
            """
            WITH
            a AS (
              SELECT
                COUNT(*)::int AS total_agents,
                COUNT(*) FILTER (WHERE last_seen_at >= (now() AT TIME ZONE 'utc') - interval '5 minutes')::int AS online_agents
              FROM agents
            ),
            e AS (
              SELECT
                COUNT(*) FILTER (WHERE "timestamp" >= (now() AT TIME ZONE 'utc') - interval '5 minutes')::int AS events_5m,
                MAX("timestamp") AS last_event_ts
              FROM net_events
              WHERE (:agent_id IS NULL OR agent_id = :agent_id)
            ),
            al AS (
              SELECT
                COUNT(*) FILTER (WHERE created_at >= (now() AT TIME ZONE 'utc') - interval '60 minutes')::int AS alerts_60m
              FROM alerts
            )
            SELECT
              a.total_agents,
              a.online_agents,
              e.events_5m,
              al.alerts_60m,
              CASE
                WHEN e.last_event_ts IS NULL THEN NULL
                ELSE FLOOR(EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'utc') - e.last_event_ts)) / 60)::int
              END AS last_event_age_m
            FROM a, e, al;
            """
        )
        kpi_row = db.execute(q_kpis, {"agent_id": agent_id}).mappings().first() or {}
        kpis = {
            "total_agents": int(kpi_row.get("total_agents") or 0),
            "online_agents": int(kpi_row.get("online_agents") or 0),
            "events_5m": int(kpi_row.get("events_5m") or 0),
            "alerts_60m": int(kpi_row.get("alerts_60m") or 0),
            "last_event_age_m": kpi_row.get("last_event_age_m"),
        }

        # -----------------------------
        # Traffic time-series (top 3 event_types + other)
        # Prefer rollups (event_rollups_1m).
        # -----------------------------
        top_types = _top_event_types(db, start_ts, now, agent_id)
        while len(top_types) < 3:
            top_types.append(None)  # placeholder for query binding

        t1, t2, t3 = top_types[0], top_types[1], top_types[2]

        q_traffic = text(
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
                event_type,
                SUM(count)::bigint AS cnt
              FROM event_rollups_1m
              WHERE bucket_ts >= :start_ts
                AND bucket_ts <= :end_ts
                AND (:agent_id IS NULL OR agent_id = :agent_id)
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

        # -----------------------------
        # Ports distribution (window)
        # -----------------------------
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
        # Pre-format small rows for the UI.
        # -----------------------------
        q_ssh_stream = text(
            """
            SELECT
              "timestamp" AS ts,
              src_ip,
              dst_ip,
              extra
            FROM net_events
            WHERE event_type = 'ssh_auth'
              AND (:agent_id IS NULL OR agent_id = :agent_id)
            ORDER BY "timestamp" DESC
            LIMIT 20;
            """
        )
        ssh_stream_rows = db.execute(q_ssh_stream, {"agent_id": agent_id}).mappings().all()
        recent_ssh = []
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
        # Raw event stream (optional table in UI)
        # -----------------------------
        q_raw_events = text(
            """
            SELECT id, "timestamp", agent_id, event_type, src_ip, dst_ip, dst_port
            FROM net_events
            WHERE (:agent_id IS NULL OR agent_id = :agent_id)
            ORDER BY "timestamp" DESC
            LIMIT 30;
            """
        )
        raw_events = [dict(r) for r in db.execute(q_raw_events, {"agent_id": agent_id}).mappings().all()]

        return {
            "kpis": kpis,
            "traffic": {"series": traffic_series, "data": traffic_data},
            "ssh_failures": {"series": ssh_series, "data": ssh_data},
            "alert_severity": {"series": sev_series, "data": sev_data},
            "ddos": {"series": ddos_series, "data": ddos_data},
            "ports": ports,
            "top_sources": top_sources,
            "recent_alerts": recent_alerts,
            "ddos_alerts": ddos_alerts,
            "recent_ssh": recent_ssh,
            "raw_events": raw_events,
        }
    finally:
        db.close()
