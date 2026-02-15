from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, or_, select, text

from app.core.portal_auth import get_current_user
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.db import SessionLocal
from app.models.events import NetEventModel
from app.schemas.pagination import CursorPage
from app.schemas.events import (
    NetEventDB,
    NetworkSummaryResponse,
    NetworkSummaryTotals,
    TopValueStat,
    DnsQnameStat,
    TlsJa4Stat,
    SshIpStat,
    SshLoginEvent,
    SshSummaryResponse,
    SshUserStat,
    SudoEventSummary,
)
router = APIRouter(
    prefix="/events",
    tags=["events"],
    dependencies=[Depends(get_current_user)],
)


@router.get("", response_model=CursorPage[NetEventDB])
def list_events(
    page_size: int = Query(50, ge=1, le=200, description="Page size (max 200)"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, min_length=1, max_length=32, description="Filter by event type"),
):
    """Cursor-paginated event timeline.

    Returns the most recent events first (DESC). To fetch the next page, pass the
    `next_cursor` from the previous response.

    This endpoint is the recommended replacement for `/events/recent` when you
    want an infinite-scroll / paginated UI.
    """

    db = SessionLocal()
    try:
        stmt = select(NetEventModel).order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())

        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventModel.event_type == event_type)

        if cursor:
            c_ts, c_id = parse_cursor_ts_id(cursor)
            # Keyset pagination for DESC order.
            stmt = stmt.where(
                or_(
                    NetEventModel.timestamp < c_ts,
                    and_(NetEventModel.timestamp == c_ts, NetEventModel.id < c_id),
                )
            )

        rows = db.execute(stmt.limit(page_size + 1)).scalars().all()

        has_more = len(rows) > page_size
        items = rows[:page_size]

        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = make_cursor_ts_id(last.timestamp, last.id)

        return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)
    finally:
        db.close()


@router.get("/recent", response_model=List[NetEventDB])
def get_recent_events(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of events to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
):
    # Return the most recent events, optionally filtered by agent_id and event_type.
    db = SessionLocal()
    try:
        stmt = select(NetEventModel).order_by(NetEventModel.timestamp.desc())
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventModel.event_type == event_type)
        stmt = stmt.limit(limit)

        result = db.execute(stmt)
        return result.scalars().all()
    finally:
        db.close()


@router.get("/stats/ports")
def get_port_stats(
    limit: int = Query(20, ge=1, le=200, description="Maximum number of ports to return"),
):
    # Return a simple distribution of events by destination port.
    db = SessionLocal()
    try:
        stmt = (
            select(
                NetEventModel.dst_port.label("port"),
                func.count().label("count"),
            )
            .where(NetEventModel.dst_port.is_not(None))
            .group_by(NetEventModel.dst_port)
            .order_by(func.count().desc())
            .limit(limit)
        )

        rows = db.execute(stmt).all()
        return [{"port": row.port, "count": row.count} for row in rows]
    finally:
        db.close()


@router.get("/ssh/summary", response_model=SshSummaryResponse)
def get_ssh_summary(
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(20, ge=1, le=200, description="Top-N limit for aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
):
    """Lupe-style SSH summary.

    Mirrors the original bash script output, but returns structured JSON.
    Works best when the lupe_enricher worker is enabled (geo/asn fields).
    """

    since_ts = datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes))

    db = SessionLocal()
    try:
        params_base = {
            "since": since_ts,
            "limit": int(limit),
            "agent_id": agent_id,
        }

        def _top_ips(action: str) -> list[SshIpStat]:
            rows = db.execute(
                text(
                    """
                    SELECT
                        src_ip,
                        COUNT(*)::bigint AS count,
                        MAX(extra->>'geo_country') AS geo_country,
                        MAX(extra->>'geo_org') AS geo_org,
                        MAX(extra->>'asn') AS asn,
                        MAX(extra->>'asn_org') AS asn_org
                    FROM net_events
                    WHERE event_type = 'ssh_auth'
                      AND (extra->>'action') = :action
                      AND "timestamp" >= :since
                      AND (:agent_id IS NULL OR agent_id = :agent_id)
                      AND src_ip IS NOT NULL
                    GROUP BY src_ip
                    ORDER BY count DESC
                    LIMIT :limit;
                    """
                ),
                {**params_base, "action": action},
            ).mappings().all()
            return [SshIpStat(**dict(r)) for r in rows]

        successful_logins = _top_ips("accepted")
        failed_attempts = _top_ips("failed_password")
        invalid_user_attempts = _top_ips("invalid_user")

        # Most active IPs across the main SSH actions
        rows = db.execute(
            text(
                """
                SELECT
                    src_ip,
                    COUNT(*)::bigint AS count,
                    MAX(extra->>'geo_country') AS geo_country,
                    MAX(extra->>'geo_org') AS geo_org,
                    MAX(extra->>'asn') AS asn,
                    MAX(extra->>'asn_org') AS asn_org
                FROM net_events
                WHERE event_type = 'ssh_auth'
                  AND (extra->>'action') = ANY(:actions)
                  AND "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                  AND src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT :limit;
                """
            ),
            {**params_base, "actions": ["accepted", "failed_password", "invalid_user"]},
        ).mappings().all()
        most_active_ips = [SshIpStat(**dict(r)) for r in rows]

        # Root logins
        rows = db.execute(
            text(
                """
                SELECT
                    "timestamp" AS timestamp,
                    agent_id,
                    src_ip,
                    (extra->>'username') AS username,
                    (extra->>'geo_country') AS geo_country,
                    (extra->>'geo_org') AS geo_org,
                    (extra->>'asn') AS asn,
                    (extra->>'asn_org') AS asn_org
                FROM net_events
                WHERE event_type = 'ssh_auth'
                  AND (extra->>'action') = 'accepted'
                  AND (extra->>'username') = 'root'
                  AND "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                ORDER BY "timestamp" DESC
                LIMIT :limit;
                """
            ),
            params_base,
        ).mappings().all()
        root_logins = [SshLoginEvent(**dict(r)) for r in rows]

        # Users that attempted to log in (failed/invalid)
        rows = db.execute(
            text(
                """
                SELECT
                    (extra->>'username') AS username,
                    COUNT(*)::bigint AS count
                FROM net_events
                WHERE event_type = 'ssh_auth'
                  AND (extra->>'action') = ANY(:actions)
                  AND "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                  AND (extra ? 'username')
                GROUP BY (extra->>'username')
                ORDER BY count DESC
                LIMIT :limit;
                """
            ),
            {**params_base, "actions": ["failed_password", "invalid_user"]},
        ).mappings().all()
        users_attempted = [SshUserStat(**dict(r)) for r in rows]

        # Recent sudo commands (from auth.log)
        rows = db.execute(
            text(
                """
                SELECT
                    "timestamp" AS timestamp,
                    agent_id,
                    (extra->>'username') AS username,
                    (extra->>'target_user') AS target_user,
                    (extra->>'command') AS command,
                    (extra->>'tty') AS tty,
                    (extra->>'pwd') AS pwd
                FROM net_events
                WHERE event_type = 'sudo_cmd'
                  AND "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                ORDER BY "timestamp" DESC
                LIMIT :limit;
                """
            ),
            params_base,
        ).mappings().all()
        sudo_recent = [SudoEventSummary(**dict(r)) for r in rows]

        return SshSummaryResponse(
            generated_at=datetime.now(timezone.utc),
            since_minutes=int(since_minutes),
            agent_id=agent_id,
            successful_logins=successful_logins,
            failed_attempts=failed_attempts,
            invalid_user_attempts=invalid_user_attempts,
            most_active_ips=most_active_ips,
            root_logins=root_logins,
            users_attempted=users_attempted,
            sudo_recent=sudo_recent,
        )
    finally:
        db.close()


@router.get("/network/summary", response_model=NetworkSummaryResponse)
def get_network_summary(
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(25, ge=5, le=200, description="Top-N limit for aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
):
    """Protocol intelligence summary.

    Aggregates protocol-aware metadata that is produced by the proto_intel worker.
    The worker patches JSONB (extra) with keys such as:

    - dns_qname, dns_qtype, dns_risk
    - http_host, http_method, http_path
    - ja3, ja4, ja4_ptype, tls_sni, tls_alpn_first

    This endpoint is intended for dashboards and fast pivoting. It is deliberately
    "summary-first": once you find an interesting indicator, pivot to /events with
    a hunt token.
    """

    since_ts = datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes))
    db = SessionLocal()
    try:
        params = {"since": since_ts, "limit": int(limit), "agent_id": agent_id}

        def _count(where_extra: str | None = None) -> int:
            extra_clause = f"AND ({where_extra})" if where_extra else ""
            row = db.execute(
                text(
                    f"""
                    SELECT COUNT(*)::bigint AS c
                    FROM net_events
                    WHERE \"timestamp\" >= :since
                      AND (:agent_id IS NULL OR agent_id = :agent_id)
                      {extra_clause};
                    """
                ),
                params,
            ).mappings().first()
            return int(row["c"] if row else 0)

        totals = NetworkSummaryTotals(
            total_events=_count(),
            proto_intel_events=_count("extra ? 'proto_intel_at'"),
            dns_events=_count("extra ? 'dns_qname'"),
            http_events=_count("extra ? 'http_host'"),
            tls_events=_count("(extra ? 'ja4') OR (extra ? 'ja3') OR (extra ? 'tls_sni')"),
        )

        def _top_value(expr: str, where_extra: str, out_field: str = "value") -> list[TopValueStat]:
            rows = db.execute(
                text(
                    f"""
                    SELECT {expr} AS {out_field}, COUNT(*)::bigint AS count
                    FROM net_events
                    WHERE \"timestamp\" >= :since
                      AND (:agent_id IS NULL OR agent_id = :agent_id)
                      AND ({where_extra})
                    GROUP BY {out_field}
                    ORDER BY count DESC
                    LIMIT :limit;
                    """
                ),
                params,
            ).mappings().all()
            out: list[TopValueStat] = []
            for r in rows:
                v = r.get(out_field)
                if v is None or str(v).strip() == "":
                    continue
                out.append(TopValueStat(value=str(v), count=int(r.get("count") or 0)))
            return out

        app_proto = _top_value("extra->>'app_proto'", "extra ? 'app_proto'")
        http_hosts = _top_value("extra->>'http_host'", "extra ? 'http_host'")
        http_methods = _top_value("extra->>'http_method'", "extra ? 'http_method'")
        tls_sni = _top_value("extra->>'tls_sni'", "extra ? 'tls_sni'")
        tls_alpn = _top_value("extra->>'tls_alpn_first'", "extra ? 'tls_alpn_first'")
        tls_ja3 = _top_value("extra->>'ja3'", "extra ? 'ja3'")
        ja4_ptype = _top_value("extra->>'ja4_ptype'", "extra ? 'ja4_ptype'")

        dns_rows = db.execute(
            text(
                """
                SELECT
                    (extra->>'dns_qname') AS qname,
                    COUNT(*)::bigint AS count,
                    MAX(COALESCE(NULLIF(extra->>'dns_risk',''), '0')::int) AS max_risk
                FROM net_events
                WHERE \"timestamp\" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                  AND (extra ? 'dns_qname')
                GROUP BY (extra->>'dns_qname')
                ORDER BY count DESC
                LIMIT :limit;
                """
            ),
            params,
        ).mappings().all()
        dns_qnames = [DnsQnameStat(qname=str(r["qname"]), count=int(r["count"]), max_risk=int(r["max_risk"] or 0)) for r in dns_rows]

        ja4_rows = db.execute(
            text(
                """
                SELECT
                    (extra->>'ja4') AS ja4,
                    COUNT(*)::bigint AS count,
                    MAX(extra->>'ja4_ptype') AS ptype
                FROM net_events
                WHERE \"timestamp\" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                  AND (extra ? 'ja4')
                GROUP BY (extra->>'ja4')
                ORDER BY count DESC
                LIMIT :limit;
                """
            ),
            params,
        ).mappings().all()
        tls_ja4 = [TlsJa4Stat(ja4=str(r["ja4"]), count=int(r["count"]), ptype=(r.get("ptype") or None)) for r in ja4_rows]

        return NetworkSummaryResponse(
            generated_at=datetime.now(timezone.utc),
            since_minutes=int(since_minutes),
            limit=int(limit),
            agent_id=agent_id,
            totals=totals,
            app_proto=app_proto,
            dns_qnames=dns_qnames,
            http_hosts=http_hosts,
            http_methods=http_methods,
            tls_sni=tls_sni,
            tls_alpn=tls_alpn,
            tls_ja4=tls_ja4,
            tls_ja3=tls_ja3,
            ja4_ptype=ja4_ptype,
        )
    finally:
        db.close()
