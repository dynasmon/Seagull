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
    ProtocolIntelSummaryResponse,
    ProtoCount,
    ProtoDnsQueryStat,
    ProtoJa4Stat,
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


def _strip_large_extra(extra: dict) -> dict:
    """Remove large payload fields before returning samples to the UI."""

    if not isinstance(extra, dict):
        return {}
    out = dict(extra)
    for k in ["payload_b64", "l7_payload_b64", "raw_payload_b64", "packet_b64", "pcap_b64"]:
        if k in out:
            out.pop(k, None)
    return out


@router.get("/network/summary", response_model=ProtocolIntelSummaryResponse)
def get_protocol_intel_summary(
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(25, ge=1, le=200, description="Top-N limit for aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
):
    """Protocol Intelligence summary.

    Aggregates protocol-aware metadata produced by the protocol_intel worker:
    DNS (qname/risk), HTTP (host/method), TLS/DTLS/QUIC (JA3/JA4 + ptype, SNI, ALPN),
    and a best-effort app_proto classification.
    """

    since_ts = datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes))

    db = SessionLocal()
    try:
        params_base = {
            "since": since_ts,
            "limit": int(limit),
            "agent_id": agent_id,
        }

        def _scalar(sql: str, params: dict) -> int:
            v = db.execute(text(sql), params).scalar_one()
            return int(v or 0)

        total_events = _scalar(
            """
            SELECT COUNT(*)::bigint
            FROM net_events
            WHERE "timestamp" >= :since
              AND (:agent_id IS NULL OR agent_id = :agent_id);
            """,
            params_base,
        )

        with_proto_metadata = _scalar(
            """
            SELECT COUNT(*)::bigint
            FROM net_events
            WHERE "timestamp" >= :since
              AND (:agent_id IS NULL OR agent_id = :agent_id)
              AND (
                (extra ? 'app_proto') OR (extra ? 'dns_qname') OR (extra ? 'http_host')
                OR (extra ? 'ja4') OR (extra ? 'ja3') OR (extra ? 'tls_sni')
              );
            """,
            params_base,
        )

        dns_events = _scalar(
            """
            SELECT COUNT(*)::bigint
            FROM net_events
            WHERE "timestamp" >= :since
              AND (:agent_id IS NULL OR agent_id = :agent_id)
              AND (extra ? 'dns_qname');
            """,
            params_base,
        )

        http_events = _scalar(
            """
            SELECT COUNT(*)::bigint
            FROM net_events
            WHERE "timestamp" >= :since
              AND (:agent_id IS NULL OR agent_id = :agent_id)
              AND ((extra ? 'http_host') OR (extra ? 'http_method'));
            """,
            params_base,
        )

        tls_events = _scalar(
            """
            SELECT COUNT(*)::bigint
            FROM net_events
            WHERE "timestamp" >= :since
              AND (:agent_id IS NULL OR agent_id = :agent_id)
              AND ((extra ? 'ja4') OR (extra ? 'ja3') OR (extra ? 'tls_sni'));
            """,
            params_base,
        )

        def _top_k(expr: str, where_key: str | None = None) -> list[ProtoCount]:
            where = "" if not where_key else f"AND (extra ? '{where_key}')"
            rows = db.execute(
                text(
                    f"""
                    SELECT {expr} AS key, COUNT(*)::bigint AS count
                    FROM net_events
                    WHERE "timestamp" >= :since
                      AND (:agent_id IS NULL OR agent_id = :agent_id)
                      {where}
                      AND {expr} IS NOT NULL
                      AND {expr} <> ''
                    GROUP BY {expr}
                    ORDER BY count DESC
                    LIMIT :limit;
                    """
                ),
                params_base,
            ).mappings().all()
            return [ProtoCount(**dict(r)) for r in rows]

        app_protocols = _top_k("extra->>'app_proto'", "app_proto")
        ja4_ptypes = _top_k("COALESCE(NULLIF(extra->>'ja4_ptype',''), 't')")
        http_methods = _top_k("upper(extra->>'http_method')", "http_method")

        dns_rows = db.execute(
            text(
                """
                SELECT
                    (extra->>'dns_qname') AS qname,
                    COALESCE(MAX((extra->>'dns_risk')::int), 0) AS risk,
                    COUNT(*)::bigint AS count
                FROM net_events
                WHERE "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                  AND (extra ? 'dns_qname')
                  AND (extra->>'dns_qname') IS NOT NULL
                  AND (extra->>'dns_qname') <> ''
                GROUP BY (extra->>'dns_qname')
                ORDER BY count DESC
                LIMIT :limit;
                """
            ),
            params_base,
        ).mappings().all()
        top_dns_queries = [ProtoDnsQueryStat(**dict(r)) for r in dns_rows]

        top_http_hosts = _top_k("lower(extra->>'http_host')", "http_host")
        top_tls_sni = _top_k("lower(extra->>'tls_sni')", "tls_sni")
        top_alpn = _top_k("lower(extra->>'tls_alpn_first')", "tls_alpn_first")

        ja4_rows = db.execute(
            text(
                """
                SELECT
                    (extra->>'ja4') AS ja4,
                    COALESCE(NULLIF(MAX(extra->>'ja4_ptype'), ''), 't') AS ptype,
                    COUNT(*)::bigint AS count
                FROM net_events
                WHERE "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                  AND (extra ? 'ja4')
                  AND (extra->>'ja4') IS NOT NULL
                  AND (extra->>'ja4') <> ''
                GROUP BY (extra->>'ja4')
                ORDER BY count DESC
                LIMIT :limit;
                """
            ),
            params_base,
        ).mappings().all()
        top_ja4 = [ProtoJa4Stat(**dict(r)) for r in ja4_rows]

        top_ja3 = _top_k("extra->>'ja3'", "ja3")

        return ProtocolIntelSummaryResponse(
            generated_at=datetime.now(timezone.utc),
            since_minutes=int(since_minutes),
            agent_id=agent_id,
            total_events=total_events,
            with_proto_metadata=with_proto_metadata,
            dns_events=dns_events,
            http_events=http_events,
            tls_events=tls_events,
            app_protocols=app_protocols,
            ja4_ptypes=ja4_ptypes,
            http_methods=http_methods,
            top_dns_queries=top_dns_queries,
            top_http_hosts=top_http_hosts,
            top_tls_sni=top_tls_sni,
            top_alpn=top_alpn,
            top_ja4=top_ja4,
            top_ja3=top_ja3,
        )
    finally:
        db.close()


@router.get("/network/samples", response_model=List[NetEventDB])
def get_protocol_intel_samples(
    kind: str = Query(..., min_length=2, max_length=32, description="Which field to filter on"),
    value: str = Query(..., min_length=1, max_length=512, description="Exact value for the selected field"),
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of events to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
):
    """Return recent events matching a specific protocol-intel indicator.

    This endpoint is designed for the UI drawer and intentionally strips raw payload fields.
    """

    since_ts = datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes))

    # Whitelist to avoid SQL injection.
    kind_map = {
        "app_proto": "extra->>'app_proto'",
        "dns_qname": "extra->>'dns_qname'",
        "http_host": "lower(extra->>'http_host')",
        "http_method": "upper(extra->>'http_method')",
        "tls_sni": "lower(extra->>'tls_sni')",
        "tls_alpn_first": "lower(extra->>'tls_alpn_first')",
        "ja4": "extra->>'ja4'",
        "ja4_ptype": "COALESCE(NULLIF(extra->>'ja4_ptype',''), 't')",
        "ja3": "extra->>'ja3'",
    }
    expr = kind_map.get(kind)
    if not expr:
        # Keep it simple: return an empty list on unknown kind.
        return []

    value_norm = value
    if kind in {"http_host", "tls_sni", "tls_alpn_first"}:
        value_norm = value.lower()
    elif kind == "http_method":
        value_norm = value.upper()

    db = SessionLocal()
    try:
        rows = db.execute(
            text(
                f"""
                SELECT *
                FROM net_events
                WHERE "timestamp" >= :since
                  AND (:agent_id IS NULL OR agent_id = :agent_id)
                  AND {expr} = :value
                ORDER BY "timestamp" DESC
                LIMIT :limit;
                """
            ),
            {
                "since": since_ts,
                "agent_id": agent_id,
                "value": value_norm,
                "limit": int(limit),
            },
        ).mappings().all()

        out: list[NetEventDB] = []
        for r in rows:
            item = NetEventDB(**dict(r))
            item.extra = _strip_large_extra(item.extra)
            out.append(item)
        return out
    finally:
        db.close()
