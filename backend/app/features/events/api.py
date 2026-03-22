from __future__ import annotations

import json
import time
from datetime import date, datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Integer, String, and_, cast, func, or_, select

from app.core.clickhouse import (
    clickhouse_events_table_ref,
    clickhouse_events_1m_table_ref,
    clickhouse_is_available,
    clickhouse_is_enabled,
    get_clickhouse_client,
)
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.es import es_is_available, get_es_client, search_backend_mode
from app.core.observability import incr_counter, log_event, observe_hist
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.portal_auth import get_current_user
from app.core.recent_feed import fetch_recent_events as fetch_recent_feed_events
from app.core.redis_client import get_redis
from app.models.events import NetEventModel, NetEventRollup1sModel
from app.schemas.events import (
    NetEventDB,
    NetEventRollup1s,
    ProtocolIntelSummaryResponse,
    ProtoCount,
    ProtoDnsQueryStat,
    ProtoJa4Stat,
    SshAuthEvent,
    SshIpStat,
    SshLoginEvent,
    SshSummaryResponse,
    SshUserStat,
    SudoEventSummary,
)
from app.schemas.pagination import CursorPage

router = APIRouter(
    prefix="/events",
    tags=["events"],
    dependencies=[Depends(get_current_user)],
)

logger = logging.getLogger("netwatch.api.events")


def _cache_get_json(key: str) -> Optional[Dict[str, Any]]:
    r = get_redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
        if not raw:
            return None
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _cache_set_json(key: str, payload: Dict[str, Any], ttl_s: int) -> None:
    if ttl_s <= 0:
        return
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(key, int(ttl_s), json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str))
    except Exception:
        return


def _feed_row_to_event(row: Dict[str, Any]) -> NetEventDB | None:
    payload = dict(row or {})
    payload["extra"] = _strip_large_extra(payload.get("extra") or {})
    if not payload.get("id"):
        payload["id"] = 0
    return _row_to_event_safe(payload)


def _merge_recent_events(*, primary: List[NetEventDB], secondary: List[NetEventDB], limit: int) -> List[NetEventDB]:
    seen: set[tuple[str, int]] = set()
    out: List[NetEventDB] = []
    for item in list(primary) + list(secondary):
        key = (item.timestamp.isoformat(), int(item.id or 0))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    out.sort(key=lambda x: (x.timestamp, x.id), reverse=True)
    return out[: int(limit)]


def _parse_iso_dt(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    s = value.strip()
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s[:-1] + "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.now(timezone.utc)


def _parse_iso_dt_or_none(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str) and value.strip():
        s = value.strip()
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            parsed = datetime.fromisoformat(s)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None
    return None


def _strip_large_extra(extra: Any) -> Dict[str, Any]:
    if not isinstance(extra, dict):
        return {}

    # Keep payloads bounded for list/sample endpoints.
    max_keys = 128
    max_value_chars = 4096
    out: Dict[str, Any] = {}
    for i, (k, v) in enumerate(extra.items()):
        if i >= max_keys:
            break
        key = str(k)[:128]
        if isinstance(v, str):
            out[key] = v[:max_value_chars]
        else:
            out[key] = v
    return out


def _row_to_event_safe(row: Dict[str, Any]) -> NetEventDB | None:
    if not isinstance(row, dict):
        return None

    ts = _parse_iso_dt_or_none(row.get("timestamp")) or datetime.now(timezone.utc)
    try:
        row_id = int(row.get("id") or 0)
    except Exception:
        row_id = 0
    try:
        schema_version = int(row.get("schema_version") or 1)
    except Exception:
        schema_version = 1
    if schema_version < 1 or schema_version > 16:
        schema_version = 1

    extra = _strip_large_extra(row.get("extra") or {})
    if not extra and isinstance(row.get("extra"), str):
        try:
            parsed = json.loads(row.get("extra") or "")
            extra = _strip_large_extra(parsed)
        except Exception:
            extra = {}

    try:
        return NetEventDB(
            id=row_id,
            agent_id=str(row.get("agent_id") or ""),
            event_type=str(row.get("event_type") or ""),
            schema_version=schema_version,
            timestamp=ts,
            src_ip=row.get("src_ip"),
            dst_ip=row.get("dst_ip"),
            src_port=row.get("src_port"),
            dst_port=row.get("dst_port"),
            proto=row.get("proto"),
            bytes=row.get("bytes"),
            extra=extra,
        )
    except Exception:
        return None


def _guess_app_proto_from_port(port: int | None, transport: str | None) -> str:
    if port in {53, 5353}:
        return "dns"
    if port in {80, 8080, 8000, 8888}:
        return "http"
    if port in {443, 8443}:
        return "tls"
    if port == 22:
        return "ssh"
    t = (transport or "").strip().lower()
    return t if t else "unknown"


def _guess_app_protocols_from_port_counts(port_counts: List[ProtoCount]) -> List[ProtoCount]:
    acc: Dict[str, int] = {}
    for item in port_counts:
        try:
            port = int(str(item.key))
        except Exception:
            continue
        guessed = _guess_app_proto_from_port(port, None)
        acc[guessed] = int(acc.get(guessed, 0)) + int(item.count or 0)
    out = [ProtoCount(key=k, count=v) for k, v in acc.items() if v > 0]
    out.sort(key=lambda x: int(x.count or 0), reverse=True)
    return out


def _pg_rollup_l4_snapshot(
    db,
    *,
    since_ts: datetime,
    limit: int,
    agent_id: str | None,
) -> tuple[int, list[ProtoCount], list[ProtoCount]]:
    total_stmt = select(func.coalesce(func.sum(NetEventRollup1sModel.count), 0)).where(NetEventRollup1sModel.bucket_ts >= since_ts)
    if agent_id:
        total_stmt = total_stmt.where(NetEventRollup1sModel.agent_id == agent_id)
    total_events = int(db.execute(total_stmt).scalar() or 0)

    transport_stmt = (
        select(
            func.lower(cast(NetEventRollup1sModel.proto, String)).label("k"),
            func.coalesce(func.sum(NetEventRollup1sModel.count), 0).label("c"),
        )
        .where(NetEventRollup1sModel.bucket_ts >= since_ts, NetEventRollup1sModel.proto.is_not(None))
        .group_by("k")
        .order_by(func.coalesce(func.sum(NetEventRollup1sModel.count), 0).desc())
        .limit(int(limit))
    )
    if agent_id:
        transport_stmt = transport_stmt.where(NetEventRollup1sModel.agent_id == agent_id)
    transport_rows = db.execute(transport_stmt).all()
    transport_protocols = [ProtoCount(key=str(r.k), count=int(r.c or 0)) for r in transport_rows if r.k]

    dst_stmt = (
        select(
            cast(NetEventRollup1sModel.dst_port, String).label("k"),
            func.coalesce(func.sum(NetEventRollup1sModel.count), 0).label("c"),
        )
        .where(NetEventRollup1sModel.bucket_ts >= since_ts, NetEventRollup1sModel.dst_port.is_not(None))
        .group_by("k")
        .order_by(func.coalesce(func.sum(NetEventRollup1sModel.count), 0).desc())
        .limit(int(limit))
    )
    if agent_id:
        dst_stmt = dst_stmt.where(NetEventRollup1sModel.agent_id == agent_id)
    dst_rows = db.execute(dst_stmt).all()
    top_dst_ports = [ProtoCount(key=str(r.k), count=int(r.c or 0)) for r in dst_rows if r.k is not None]

    return total_events, transport_protocols, top_dst_ports


def _es_index_pattern() -> str:
    prefix = (getattr(settings, "NETWATCH_ES_INDEX_PREFIX", "netwatch-events") or "netwatch-events").strip()
    return f"{prefix}-*"


def _ch_client_or_none() -> Any | None:
    if not clickhouse_is_enabled():
        return None
    if not clickhouse_is_available():
        return None
    try:
        return get_clickhouse_client()
    except Exception:
        return None


def _ch_where(
    *,
    since: datetime | None = None,
    agent_id: str | None = None,
    event_type: str | None = None,
) -> tuple[str, Dict[str, Any]]:
    conds = ["1=1"]
    params: Dict[str, Any] = {}
    if since is not None:
        conds.append("timestamp >= {since:DateTime64(3)}")
        params["since"] = since
    if agent_id:
        conds.append("agent_id = {agent_id:String}")
        params["agent_id"] = agent_id
    if event_type:
        conds.append("event_type = {event_type:String}")
        params["event_type"] = event_type
    return " AND ".join(conds), params


def _ch_query_dicts(ch: Any, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    res = ch.query(sql, parameters=(params or {}))
    cols = list(getattr(res, "column_names", []) or [])
    rows = list(getattr(res, "result_rows", []) or [])
    if not cols or not rows:
        return []
    out: List[Dict[str, Any]] = []
    for row in rows:
        out.append({cols[i]: row[i] for i in range(min(len(cols), len(row)))})
    return out


def _ch_dedup_key_expr(alias: str = "") -> str:
    prefix = f"{alias}." if alias else ""
    return (
        f"if({prefix}pg_event_id > 0, "
        f"concat('id:', toString({prefix}pg_event_id)), "
        f"concat('raw:', toString(cityHash64("
        f"{prefix}agent_id, "
        f"{prefix}event_type, "
        f"toInt64(toUnixTimestamp64Milli({prefix}timestamp)), "
        f"ifNull({prefix}src_ip, ''), "
        f"ifNull({prefix}dst_ip, ''), "
        f"ifNull({prefix}src_port, 0), "
        f"ifNull({prefix}dst_port, 0), "
        f"ifNull({prefix}proto, ''), "
        f"ifNull({prefix}bytes, 0), "
        f"{prefix}extra_json"
        f"))))"
    )


def _ch_deduped_events_source_sql(*, table: str, where_sql: str) -> str:
    dedup_key = _ch_dedup_key_expr()
    return (
        "SELECT "
        "argMax(timestamp, ingested_at) AS timestamp, "
        "argMax(pg_event_id, ingested_at) AS pg_event_id, "
        "argMax(agent_id, ingested_at) AS agent_id, "
        "argMax(event_type, ingested_at) AS event_type, "
        "argMax(schema_version, ingested_at) AS schema_version, "
        "argMax(severity, ingested_at) AS severity, "
        "argMax(src_ip, ingested_at) AS src_ip, "
        "argMax(dst_ip, ingested_at) AS dst_ip, "
        "argMax(src_port, ingested_at) AS src_port, "
        "argMax(dst_port, ingested_at) AS dst_port, "
        "argMax(proto, ingested_at) AS proto, "
        "argMax(bytes, ingested_at) AS bytes, "
        "argMax(app_proto, ingested_at) AS app_proto, "
        "argMax(app_proto_reason, ingested_at) AS app_proto_reason, "
        "argMax(app_proto_conf_band, ingested_at) AS app_proto_conf_band, "
        "argMax(dns_qname, ingested_at) AS dns_qname, "
        "argMax(http_host, ingested_at) AS http_host, "
        "argMax(http_method, ingested_at) AS http_method, "
        "argMax(tls_sni, ingested_at) AS tls_sni, "
        "argMax(tls_alpn_first, ingested_at) AS tls_alpn_first, "
        "argMax(ja3, ingested_at) AS ja3, "
        "argMax(ja4, ingested_at) AS ja4, "
        "argMax(ja4_ptype, ingested_at) AS ja4_ptype, "
        "argMax(ssh_action, ingested_at) AS ssh_action, "
        "argMax(ssh_username, ingested_at) AS ssh_username, "
        "argMax(sudo_username, ingested_at) AS sudo_username, "
        "argMax(sudo_target_user, ingested_at) AS sudo_target_user, "
        "argMax(sudo_command, ingested_at) AS sudo_command, "
        "argMax(sudo_tty, ingested_at) AS sudo_tty, "
        "argMax(extra_json, ingested_at) AS extra_json, "
        "max(ingested_at) AS ingested_at "
        f"FROM {table} "
        f"WHERE {where_sql} "
        f"GROUP BY {dedup_key}"
    )


def _ch_row_to_event(row: Dict[str, Any]) -> NetEventDB | None:
    try:
        row_id = int(row.get("pg_event_id") or 0)
    except Exception:
        row_id = 0
    ts_raw = row.get("timestamp")
    ts = ts_raw if isinstance(ts_raw, datetime) else _parse_iso_dt(str(ts_raw) if ts_raw else None)
    try:
        schema_version = int(row.get("schema_version") or 1)
    except Exception:
        schema_version = 1
    if schema_version < 1 or schema_version > 16:
        schema_version = 1

    extra: Dict[str, Any] = {}
    extra_raw = row.get("extra_json")
    if isinstance(extra_raw, str) and extra_raw.strip():
        try:
            payload = json.loads(extra_raw)
            if isinstance(payload, dict):
                extra = payload
        except Exception:
            extra = {}

    try:
        return NetEventDB(
            id=row_id,
            agent_id=str(row.get("agent_id") or ""),
            event_type=str(row.get("event_type") or ""),
            schema_version=schema_version,
            timestamp=ts,
            src_ip=row.get("src_ip"),
            dst_ip=row.get("dst_ip"),
            src_port=row.get("src_port"),
            dst_port=row.get("dst_port"),
            proto=row.get("proto"),
            bytes=row.get("bytes"),
            extra=extra,
        )
    except Exception:
        return None


def _ch_top_counts(
    ch: Any,
    *,
    source_sql: str,
    params: Optional[Dict[str, Any]],
    key_expr: str,
    limit: int,
    nonempty: bool = True,
) -> List[ProtoCount]:
    having = "k IS NOT NULL"
    if nonempty:
        having += " AND toString(k) != ''"
    sql = (
        f"SELECT {key_expr} AS k, count() AS c "
        f"FROM ({source_sql}) AS d "
        f"GROUP BY k "
        f"HAVING {having} "
        f"ORDER BY c DESC "
        f"LIMIT {int(limit)}"
    )
    rows = _ch_query_dicts(ch, sql, params)
    return [ProtoCount(key=str(r.get("k")), count=int(r.get("c") or 0)) for r in rows if r.get("k") is not None]


def _es_client_or_none() -> Any | None:
    mode = search_backend_mode()
    if mode == "postgres":
        return None

    if not es_is_available():
        if mode == "elasticsearch":
            raise HTTPException(status_code=503, detail="Elasticsearch unavailable")
        return None

    return get_es_client()


def _es_failover_allowed() -> bool:
    return search_backend_mode() != "elasticsearch"


def _pg_has_newer_event(*, latest_ts: datetime, agent_id: str | None = None, event_type: str | None = None, margin_s: int | None = None) -> bool:
    db = SessionLocal()
    try:
        stmt = select(func.max(NetEventModel.timestamp))
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventModel.event_type == event_type)
        pg_ts = db.execute(stmt).scalar()
        if not isinstance(pg_ts, datetime):
            return False
        if pg_ts.tzinfo is None:
            pg_ts = pg_ts.replace(tzinfo=timezone.utc)
        ref = latest_ts if latest_ts.tzinfo else latest_ts.replace(tzinfo=timezone.utc)
        threshold = int(margin_s or getattr(settings, "NETWATCH_EVENTS_ES_STALE_MARGIN_SECONDS", 15) or 15)
        return (pg_ts - ref).total_seconds() > float(max(1, threshold))
    except Exception:
        return False
    finally:
        db.close()


def _pg_has_protocol_metadata(*, since: datetime, agent_id: str | None = None) -> bool:
    db = SessionLocal()
    try:
        app_proto_expr = func.coalesce(NetEventModel.app_proto, NetEventModel.extra["app_proto"].astext)
        dns_qname_expr = func.coalesce(NetEventModel.dns_qname, NetEventModel.extra["dns_qname"].astext)
        http_host_expr = func.coalesce(NetEventModel.http_host, NetEventModel.extra["http_host"].astext)
        http_method_expr = func.coalesce(NetEventModel.http_method, NetEventModel.extra["http_method"].astext)
        tls_sni_expr = func.coalesce(NetEventModel.tls_sni, NetEventModel.extra["tls_sni"].astext)
        ja4_expr = func.coalesce(NetEventModel.ja4, NetEventModel.extra["ja4"].astext)
        ja3_expr = func.coalesce(NetEventModel.ja3, NetEventModel.extra["ja3"].astext)

        stmt = select(func.count()).where(
            NetEventModel.timestamp >= since,
            or_(
                func.nullif(app_proto_expr, "").is_not(None),
                func.nullif(dns_qname_expr, "").is_not(None),
                func.nullif(http_host_expr, "").is_not(None),
                func.nullif(http_method_expr, "").is_not(None),
                func.nullif(tls_sni_expr, "").is_not(None),
                func.nullif(ja4_expr, "").is_not(None),
                func.nullif(ja3_expr, "").is_not(None),
            ),
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        return int(db.execute(stmt).scalar() or 0) > 0
    except Exception:
        return False
    finally:
        db.close()


def _hit_to_event(hit: Dict[str, Any]) -> NetEventDB:
    src = hit.get("_source") or {}

    # Prefer explicit 'id' stored in _source, fallback to _id.
    try:
        row_id = int(src.get("id") or hit.get("_id"))
    except Exception:
        row_id = 0

    ts_raw = src.get("timestamp") or src.get("@timestamp")
    ts = _parse_iso_dt(ts_raw if isinstance(ts_raw, str) else None)
    try:
        schema_version = int(src.get("schema_version") or 1)
    except Exception:
        schema_version = 1
    if schema_version < 1 or schema_version > 16:
        schema_version = 1
    extra = src.get("extra") or {}
    if not isinstance(extra, dict):
        extra = {}

    return NetEventDB(
        id=row_id,
        agent_id=str(src.get("agent_id") or ""),
        event_type=str(src.get("event_type") or ""),
        schema_version=schema_version,
        timestamp=ts,
        src_ip=src.get("src_ip"),
        dst_ip=src.get("dst_ip"),
        src_port=src.get("src_port"),
        dst_port=src.get("dst_port"),
        proto=src.get("proto"),
        bytes=src.get("bytes"),
        extra=extra,
    )


def _es_base_filters(
    *,
    since: datetime | None = None,
    agent_id: str | None = None,
    event_type: str | None = None,
) -> List[Dict[str, Any]]:
    filters: List[Dict[str, Any]] = []

    if since is not None:
        filters.append({"range": {"timestamp": {"gte": since.isoformat()}}})

    if agent_id:
        filters.append({"term": {"agent_id": agent_id}})

    if event_type:
        filters.append({"term": {"event_type": event_type}})

    return filters


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

    es = _es_client_or_none()
    if es is not None:
        try:
            body: Dict[str, Any] = {
                "size": int(page_size) + 1,
                "sort": [
                    {"timestamp": {"order": "desc"}},
                    {"id": {"order": "desc"}},
                ],
                "query": {
                    "bool": {
                        "filter": _es_base_filters(agent_id=agent_id, event_type=event_type),
                    }
                },
            }

            if cursor:
                c_ts, c_id = parse_cursor_ts_id(cursor)
                # search_after values correspond to the 'sort' array.
                body["search_after"] = [c_ts.isoformat(), int(c_id)]

            res = es.search(
                index=_es_index_pattern(),
                body=body,
                ignore_unavailable=True,
                allow_no_indices=True,
                track_total_hits=False,
            )

            hits = (res.get("hits") or {}).get("hits") or []
            has_more = len(hits) > int(page_size)
            page_hits = hits[: int(page_size)]

            if not page_hits and _es_failover_allowed():
                raise LookupError("es_empty_page")

            items = [_hit_to_event(h) for h in page_hits]
            if items and _es_failover_allowed():
                if _pg_has_newer_event(latest_ts=items[0].timestamp, agent_id=agent_id, event_type=event_type):
                    raise LookupError("es_stale")

            next_cursor = None
            if has_more and page_hits:
                last_evt = items[-1]
                next_cursor = make_cursor_ts_id(last_evt.timestamp, last_evt.id)

            return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")
            # Fallback to Postgres.

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

        rows = db.execute(stmt.limit(int(page_size) + 1)).scalars().all()

        has_more = len(rows) > int(page_size)
        items = rows[: int(page_size)]

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
    feed_rows = fetch_recent_feed_events(limit=min(max(int(limit), 1), 200), agent_id=agent_id, event_type=event_type)
    feed_events = [ev for ev in (_feed_row_to_event(r) for r in feed_rows) if ev is not None]

    ch = _ch_client_or_none()
    if ch is not None:
        try:
            table = clickhouse_events_table_ref()
            where_sql, params = _ch_where(agent_id=agent_id, event_type=event_type)
            dedup_source_sql = _ch_deduped_events_source_sql(table=table, where_sql=where_sql)
            fetch_limit = min(max(int(limit) * 2, int(limit)), 5000)
            sql = (
                f"SELECT pg_event_id, agent_id, event_type, schema_version, timestamp, "
                f"src_ip, dst_ip, src_port, dst_port, proto, bytes, extra_json "
                f"FROM ({dedup_source_sql}) AS d "
                f"ORDER BY timestamp DESC, pg_event_id DESC, ingested_at DESC "
                f"LIMIT {int(fetch_limit)}"
            )
            rows = _ch_query_dicts(ch, sql, params)
            if rows:
                out: List[NetEventDB] = []
                for r in rows:
                    ev = _ch_row_to_event(r)
                    if ev is not None:
                        out.append(ev)
                        if len(out) >= int(limit):
                            break
                if out:
                    if _pg_has_newer_event(latest_ts=out[0].timestamp, agent_id=agent_id, event_type=event_type):
                        raise LookupError("clickhouse_stale_recent")
                    return _merge_recent_events(primary=feed_events, secondary=out, limit=int(limit))
        except Exception as e:
            log_event(logger, "warning", "events_recent_clickhouse_error", error_type=type(e).__name__)

    es = _es_client_or_none()
    if es is not None:
        try:
            body: Dict[str, Any] = {
                "size": int(limit),
                "sort": [
                    {"timestamp": {"order": "desc"}},
                    {"id": {"order": "desc"}},
                ],
                "query": {
                    "bool": {
                        "filter": _es_base_filters(agent_id=agent_id, event_type=event_type),
                    }
                },
            }

            res = es.search(
                index=_es_index_pattern(),
                body=body,
                ignore_unavailable=True,
                allow_no_indices=True,
                track_total_hits=False,
            )
            hits = (res.get("hits") or {}).get("hits") or []
            if not hits and _es_failover_allowed():
                raise LookupError("es_empty_recent")
            out = [_hit_to_event(h) for h in hits]
            if out and _es_failover_allowed():
                if _pg_has_newer_event(latest_ts=out[0].timestamp, agent_id=agent_id, event_type=event_type):
                    raise LookupError("es_stale_recent")
            return _merge_recent_events(primary=feed_events, secondary=out, limit=int(limit))
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")

    # Postgres fallback
    db = SessionLocal()
    try:
        # Deterministic ordering avoids flicker when many events share the same timestamp.
        stmt = select(NetEventModel).order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventModel.event_type == event_type)
        stmt = stmt.limit(int(limit))

        result = db.execute(stmt)
        rows = result.scalars().all()
        return _merge_recent_events(primary=feed_events, secondary=list(rows), limit=int(limit))
    finally:
        db.close()


@router.get("/rollups/1s", response_model=List[NetEventRollup1s])
def list_rollups_1s(
    minutes: int = Query(60, ge=1, le=24 * 60, description="Lookback window in minutes"),
    limit: int = Query(500, ge=1, le=5000, description="Max buckets to return"),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    event_type: Optional[str] = Query(None, min_length=1, max_length=32),
    dst_ip: Optional[str] = Query(None, min_length=1, max_length=45),
    dst_port: Optional[int] = Query(None, ge=0, le=65535),
):
    """1-second rollups for high-rate telemetry.

    This is especially useful during volumetric attacks when raw events may be sampled.
    """

    since = datetime.now(timezone.utc) - timedelta(minutes=int(minutes))

    db = SessionLocal()
    try:
        stmt = (
            select(
                NetEventRollup1sModel.bucket_ts,
                NetEventRollup1sModel.agent_id,
                NetEventRollup1sModel.event_type,
                NetEventRollup1sModel.dst_ip,
                NetEventRollup1sModel.dst_port,
                NetEventRollup1sModel.proto,
                NetEventRollup1sModel.count,
                NetEventRollup1sModel.bytes_sum,
            )
            .where(NetEventRollup1sModel.bucket_ts >= since)
            .order_by(NetEventRollup1sModel.bucket_ts.desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventRollup1sModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventRollup1sModel.event_type == event_type)
        if dst_ip:
            stmt = stmt.where(NetEventRollup1sModel.dst_ip == dst_ip)
        if dst_port is not None:
            stmt = stmt.where(NetEventRollup1sModel.dst_port == dst_port)
        rows = db.execute(stmt).mappings().all()

        return [NetEventRollup1s(**dict(r)) for r in rows]
    finally:
        db.close()


@router.get("/stats/ports")
def get_port_stats(
    limit: int = Query(20, ge=1, le=200, description="Maximum number of ports to return"),
):
    ch = _ch_client_or_none()
    if ch is not None:
        try:
            sql = (
                f"SELECT dst_port AS port, sum(total_count) AS count "
                f"FROM {clickhouse_events_1m_table_ref()} "
                f"WHERE dst_port IS NOT NULL "
                f"GROUP BY dst_port "
                f"ORDER BY count DESC "
                f"LIMIT {int(limit)}"
            )
            rows = _ch_query_dicts(ch, sql)
            if rows:
                return [{"port": int(r.get('port')), "count": int(r.get('count') or 0)} for r in rows if r.get("port") is not None]
        except Exception as e:
            log_event(logger, "warning", "events_ports_clickhouse_error", error_type=type(e).__name__)

    es = _es_client_or_none()
    if es is not None:
        try:
            body = {
                "size": 0,
                "query": {"bool": {"filter": [{"exists": {"field": "dst_port"}}]}},
                "aggs": {
                    "ports": {
                        "terms": {
                            "field": "dst_port",
                            "size": int(limit),
                            "order": {"_count": "desc"},
                        }
                    }
                },
            }
            res = es.search(
                index=_es_index_pattern(),
                body=body,
                ignore_unavailable=True,
                allow_no_indices=True,
                track_total_hits=False,
            )
            buckets = ((res.get("aggregations") or {}).get("ports") or {}).get("buckets") or []
            return [{"port": b.get("key"), "count": b.get("doc_count", 0)} for b in buckets]
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")

    # Postgres fallback
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
            .limit(int(limit))
        )

        rows = db.execute(stmt).all()
        return [{"port": row.port, "count": row.count} for row in rows]
    finally:
        db.close()


def _es_terms_top(
    es,
    *,
    field: str,
    size: int,
    base_filters: List[Dict[str, Any]],
) -> List[ProtoCount]:
    body = {
        "size": 0,
        "query": {"bool": {"filter": base_filters}},
        "aggs": {"top": {"terms": {"field": field, "size": int(size), "order": {"_count": "desc"}}}},
    }
    res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
    buckets = ((res.get("aggregations") or {}).get("top") or {}).get("buckets") or []
    out: List[ProtoCount] = []
    for b in buckets:
        k = b.get("key")
        if k is None:
            continue
        out.append(ProtoCount(key=str(k), count=int(b.get("doc_count", 0) or 0)))
    return out


@router.get("/ssh/summary", response_model=SshSummaryResponse)
def get_ssh_summary(
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(50, ge=1, le=500, description="Row limit for recent/raw SSH views and supporting aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
):
    """SSH summary with real auth.log-backed totals and recent raw events.

    The summary cards reflect the true event volume in the selected window.
    Aggregated Top-N views remain available for triage, but recent_auth_events
    exposes the latest raw ssh_auth entries so low-volume/manual probes are not
    hidden by heavy brute-force traffic.
    """

    started = time.perf_counter()
    since_ts = datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes))
    cache_key = f"netwatch:events:ssh_summary:v3:sm={int(since_minutes)}:l={int(limit)}:a={agent_id or '*'}"
    cached = _cache_get_json(cache_key)
    if cached is not None:
        incr_counter("api_cache_hit_total", route="/events/ssh/summary")
        return SshSummaryResponse(**cached)

    tracked_actions = ["accepted", "failed_password", "invalid_user"]

    ch = _ch_client_or_none()
    if ch is not None:
        try:
            table = clickhouse_events_table_ref()
            ssh_where_sql, ssh_params = _ch_where(since=since_ts, agent_id=agent_id, event_type="ssh_auth")
            ssh_source_sql = _ch_deduped_events_source_sql(table=table, where_sql=ssh_where_sql)
            sudo_where_sql, sudo_params = _ch_where(since=since_ts, agent_id=agent_id, event_type="sudo_cmd")
            sudo_source_sql = _ch_deduped_events_source_sql(table=table, where_sql=sudo_where_sql)

            def _top_ips(action: str) -> list[SshIpStat]:
                sql = (
                    "SELECT src_ip, count() AS count, "
                    "any(JSONExtractString(extra_json, 'geo_country')) AS geo_country, "
                    "any(JSONExtractString(extra_json, 'geo_org')) AS geo_org, "
                    "any(JSONExtractString(extra_json, 'asn')) AS asn, "
                    "any(JSONExtractString(extra_json, 'asn_org')) AS asn_org "
                    f"FROM ({ssh_source_sql}) "
                    "WHERE src_ip IS NOT NULL AND ifNull(ssh_action, '') = {action:String} "
                    "GROUP BY src_ip ORDER BY count DESC "
                    f"LIMIT {int(limit)}"
                )
                rows = _ch_query_dicts(ch, sql, {**ssh_params, "action": action})
                return [SshIpStat(**dict(r)) for r in rows]

            totals_sql = (
                "SELECT "
                "countIf(ifNull(ssh_action, '') = 'accepted') AS total_accepted, "
                "countIf(ifNull(ssh_action, '') = 'failed_password') AS total_failed_password, "
                "countIf(ifNull(ssh_action, '') = 'invalid_user') AS total_invalid_user, "
                "uniqExactIf(src_ip, src_ip IS NOT NULL AND ifNull(ssh_action, '') IN ('accepted','failed_password','invalid_user')) AS unique_source_ips, "
                "uniqExactIf(src_ip, src_ip IS NOT NULL AND ifNull(ssh_action, '') IN ('accepted','failed_password','invalid_user') AND ("
                "JSONExtractString(extra_json, 'geo_country') != '' OR "
                "JSONExtractString(extra_json, 'geo_org') != '' OR "
                "JSONExtractString(extra_json, 'asn') != '' OR "
                "JSONExtractString(extra_json, 'asn_org') != '')) AS enriched_source_ips "
                f"FROM ({ssh_source_sql})"
            )
            totals_row = (_ch_query_dicts(ch, totals_sql, ssh_params) or [{}])[0]
            total_accepted = int(totals_row.get("total_accepted", 0) or 0)
            total_failed_password = int(totals_row.get("total_failed_password", 0) or 0)
            total_invalid_user = int(totals_row.get("total_invalid_user", 0) or 0)
            unique_source_ips = int(totals_row.get("unique_source_ips", 0) or 0)
            enriched_source_ips = int(totals_row.get("enriched_source_ips", 0) or 0)

            recent_auth_sql = (
                "SELECT timestamp, agent_id, ifNull(ssh_action, '') AS action, src_ip, "
                "ifNull(ssh_username, '') AS username, "
                "JSONExtractString(extra_json, 'geo_country') AS geo_country, "
                "JSONExtractString(extra_json, 'geo_org') AS geo_org, "
                "JSONExtractString(extra_json, 'asn') AS asn, "
                "JSONExtractString(extra_json, 'asn_org') AS asn_org "
                f"FROM ({ssh_source_sql}) "
                "WHERE ifNull(ssh_action, '') IN ('accepted','failed_password','invalid_user') "
                "ORDER BY timestamp DESC "
                f"LIMIT {int(limit)}"
            )
            recent_auth_events = [SshAuthEvent(**dict(r)) for r in _ch_query_dicts(ch, recent_auth_sql, ssh_params)]

            successful_logins = _top_ips("accepted")
            failed_attempts = _top_ips("failed_password")
            invalid_user_attempts = _top_ips("invalid_user")

            active_sql = (
                "SELECT src_ip, count() AS count, "
                "any(JSONExtractString(extra_json, 'geo_country')) AS geo_country, "
                "any(JSONExtractString(extra_json, 'geo_org')) AS geo_org, "
                "any(JSONExtractString(extra_json, 'asn')) AS asn, "
                "any(JSONExtractString(extra_json, 'asn_org')) AS asn_org "
                f"FROM ({ssh_source_sql}) "
                "WHERE src_ip IS NOT NULL AND ifNull(ssh_action, '') IN ('accepted','failed_password','invalid_user') "
                "GROUP BY src_ip ORDER BY count DESC "
                f"LIMIT {int(limit)}"
            )
            most_active_ips = [SshIpStat(**dict(r)) for r in _ch_query_dicts(ch, active_sql, ssh_params)]

            root_sql = (
                "SELECT timestamp, agent_id, src_ip, "
                "ifNull(ssh_username, '') AS username, "
                "JSONExtractString(extra_json, 'geo_country') AS geo_country, "
                "JSONExtractString(extra_json, 'geo_org') AS geo_org, "
                "JSONExtractString(extra_json, 'asn') AS asn, "
                "JSONExtractString(extra_json, 'asn_org') AS asn_org "
                f"FROM ({ssh_source_sql}) "
                "WHERE ifNull(ssh_action, '') = 'accepted' "
                "AND ifNull(ssh_username, '') = 'root' "
                "ORDER BY timestamp DESC "
                f"LIMIT {int(limit)}"
            )
            root_logins = [SshLoginEvent(**dict(r)) for r in _ch_query_dicts(ch, root_sql, ssh_params)]

            users_sql = (
                "SELECT ssh_username AS username, count() AS count "
                f"FROM ({ssh_source_sql}) "
                "WHERE ifNull(ssh_action, '') IN ('failed_password','invalid_user') "
                "AND ifNull(ssh_username, '') != '' "
                "GROUP BY username ORDER BY count DESC "
                f"LIMIT {int(limit)}"
            )
            users_attempted = [SshUserStat(**dict(r)) for r in _ch_query_dicts(ch, users_sql, ssh_params)]

            sudo_sql = (
                "SELECT timestamp, agent_id, "
                "sudo_username AS username, "
                "sudo_target_user AS target_user, "
                "sudo_command AS command, "
                "sudo_tty AS tty, "
                "JSONExtractString(extra_json, 'pwd') AS pwd "
                f"FROM ({sudo_source_sql}) "
                "ORDER BY timestamp DESC "
                f"LIMIT {int(limit)}"
            )
            sudo_recent = [SudoEventSummary(**dict(r)) for r in _ch_query_dicts(ch, sudo_sql, sudo_params)]

            payload = SshSummaryResponse(
                generated_at=datetime.now(timezone.utc),
                since_minutes=int(since_minutes),
                agent_id=agent_id,
                total_accepted=total_accepted,
                total_failed_password=total_failed_password,
                total_invalid_user=total_invalid_user,
                total_actions=total_accepted + total_failed_password + total_invalid_user,
                unique_source_ips=unique_source_ips,
                enriched_source_ips=enriched_source_ips,
                recent_auth_events=recent_auth_events,
                successful_logins=successful_logins,
                failed_attempts=failed_attempts,
                invalid_user_attempts=invalid_user_attempts,
                most_active_ips=most_active_ips,
                root_logins=root_logins,
                users_attempted=users_attempted,
                sudo_recent=sudo_recent,
            )
            _cache_set_json(cache_key, payload.dict(), int(getattr(settings, "NETWATCH_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15))
            observe_hist("api_route_latency_seconds", time.perf_counter() - started, route="/events/ssh/summary", source="clickhouse")
            return payload
        except Exception as e:
            log_event(logger, "warning", "events_ssh_summary_clickhouse_error", error_type=type(e).__name__)

    es = _es_client_or_none()
    if es is not None:
        try:
            base = _es_base_filters(since=since_ts, agent_id=agent_id)

            def _top_ips(action: str) -> list[SshIpStat]:
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": base
                            + [
                                {"term": {"event_type": "ssh_auth"}},
                                {"term": {"ssh_action": action}},
                                {"exists": {"field": "src_ip"}},
                            ]
                        }
                    },
                    "aggs": {
                        "ips": {
                            "terms": {"field": "src_ip", "size": int(limit), "order": {"_count": "desc"}},
                            "aggs": {
                                "sample": {
                                    "top_hits": {
                                        "size": 1,
                                        "_source": {"includes": ["geo_country", "geo_org", "asn", "asn_org"]},
                                        "sort": [{"timestamp": {"order": "desc"}}],
                                    }
                                }
                            },
                        }
                    },
                }
                res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
                buckets = ((res.get("aggregations") or {}).get("ips") or {}).get("buckets") or []
                out: list[SshIpStat] = []
                for b in buckets:
                    sample_hits = (((b.get("sample") or {}).get("hits") or {}).get("hits") or [])
                    sample_src = (sample_hits[0].get("_source") if sample_hits else {}) or {}
                    out.append(
                        SshIpStat(
                            src_ip=str(b.get("key")),
                            count=int(b.get("doc_count", 0) or 0),
                            geo_country=sample_src.get("geo_country"),
                            geo_org=sample_src.get("geo_org"),
                            asn=sample_src.get("asn"),
                            asn_org=sample_src.get("asn_org"),
                        )
                    )
                return out

            totals_body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": base + [{"term": {"event_type": "ssh_auth"}}]
                    }
                },
                "aggs": {
                    "total_accepted": {"filter": {"term": {"ssh_action": "accepted"}}},
                    "total_failed_password": {"filter": {"term": {"ssh_action": "failed_password"}}},
                    "total_invalid_user": {"filter": {"term": {"ssh_action": "invalid_user"}}},
                    "unique_source_ips": {
                        "filter": {
                            "bool": {
                                "filter": [
                                    {"terms": {"ssh_action": tracked_actions}},
                                    {"exists": {"field": "src_ip"}},
                                ]
                            }
                        },
                        "aggs": {"value": {"cardinality": {"field": "src_ip"}}},
                    },
                    "enriched_source_ips": {
                        "filter": {
                            "bool": {
                                "filter": [
                                    {"terms": {"ssh_action": tracked_actions}},
                                    {"exists": {"field": "src_ip"}},
                                ],
                                "should": [
                                    {"exists": {"field": "geo_country"}},
                                    {"exists": {"field": "geo_org"}},
                                    {"exists": {"field": "asn"}},
                                    {"exists": {"field": "asn_org"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                        "aggs": {"value": {"cardinality": {"field": "src_ip"}}},
                    },
                },
            }
            totals_res = es.search(index=_es_index_pattern(), body=totals_body, ignore_unavailable=True, allow_no_indices=True)
            aggs = totals_res.get("aggregations") or {}
            total_accepted = int(((aggs.get("total_accepted") or {}).get("doc_count")) or 0)
            total_failed_password = int(((aggs.get("total_failed_password") or {}).get("doc_count")) or 0)
            total_invalid_user = int(((aggs.get("total_invalid_user") or {}).get("doc_count")) or 0)
            unique_source_ips = int((((aggs.get("unique_source_ips") or {}).get("value") or {}).get("value")) or 0)
            enriched_source_ips = int((((aggs.get("enriched_source_ips") or {}).get("value") or {}).get("value")) or 0)

            recent_auth_body = {
                "size": int(limit),
                "sort": [{"timestamp": {"order": "desc"}}, {"id": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": base + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"terms": {"ssh_action": tracked_actions}},
                        ]
                    }
                },
                "_source": {
                    "includes": [
                        "timestamp",
                        "agent_id",
                        "src_ip",
                        "ssh_action",
                        "ssh_username",
                        "geo_country",
                        "geo_org",
                        "asn",
                        "asn_org",
                    ]
                },
            }
            recent_auth_res = es.search(index=_es_index_pattern(), body=recent_auth_body, ignore_unavailable=True, allow_no_indices=True)
            recent_auth_events: list[SshAuthEvent] = []
            for h in ((recent_auth_res.get("hits") or {}).get("hits") or []):
                src = h.get("_source") or {}
                recent_auth_events.append(
                    SshAuthEvent(
                        timestamp=_parse_iso_dt(src.get("timestamp") if isinstance(src.get("timestamp"), str) else None),
                        agent_id=str(src.get("agent_id") or ""),
                        action=src.get("ssh_action"),
                        src_ip=src.get("src_ip"),
                        username=src.get("ssh_username"),
                        geo_country=src.get("geo_country"),
                        geo_org=src.get("geo_org"),
                        asn=src.get("asn"),
                        asn_org=src.get("asn_org"),
                    )
                )

            successful_logins = _top_ips("accepted")
            failed_attempts = _top_ips("failed_password")
            invalid_user_attempts = _top_ips("invalid_user")

            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": base
                        + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"terms": {"ssh_action": tracked_actions}},
                            {"exists": {"field": "src_ip"}},
                        ]
                    }
                },
                "aggs": {
                    "ips": {
                        "terms": {"field": "src_ip", "size": int(limit), "order": {"_count": "desc"}},
                        "aggs": {
                            "sample": {
                                "top_hits": {
                                    "size": 1,
                                    "_source": {"includes": ["geo_country", "geo_org", "asn", "asn_org"]},
                                    "sort": [{"timestamp": {"order": "desc"}}],
                                }
                            }
                        },
                    }
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            buckets = ((res.get("aggregations") or {}).get("ips") or {}).get("buckets") or []
            most_active_ips: list[SshIpStat] = []
            for b in buckets:
                sample_hits = (((b.get("sample") or {}).get("hits") or {}).get("hits") or [])
                sample_src = (sample_hits[0].get("_source") if sample_hits else {}) or {}
                most_active_ips.append(
                    SshIpStat(
                        src_ip=str(b.get("key")),
                        count=int(b.get("doc_count", 0) or 0),
                        geo_country=sample_src.get("geo_country"),
                        geo_org=sample_src.get("geo_org"),
                        asn=sample_src.get("asn"),
                        asn_org=sample_src.get("asn_org"),
                    )
                )

            body = {
                "size": int(limit),
                "sort": [{"timestamp": {"order": "desc"}}, {"id": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": base
                        + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"term": {"ssh_action": "accepted"}},
                            {"term": {"ssh_username": "root"}},
                        ]
                    }
                },
                "_source": {
                    "includes": [
                        "timestamp",
                        "agent_id",
                        "src_ip",
                        "ssh_username",
                        "geo_country",
                        "geo_org",
                        "asn",
                        "asn_org",
                    ]
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            root_logins: list[SshLoginEvent] = []
            for h in ((res.get("hits") or {}).get("hits") or []):
                src = h.get("_source") or {}
                root_logins.append(
                    SshLoginEvent(
                        timestamp=_parse_iso_dt(src.get("timestamp") if isinstance(src.get("timestamp"), str) else None),
                        agent_id=str(src.get("agent_id") or ""),
                        src_ip=src.get("src_ip"),
                        username=src.get("ssh_username"),
                        geo_country=src.get("geo_country"),
                        geo_org=src.get("geo_org"),
                        asn=src.get("asn"),
                        asn_org=src.get("asn_org"),
                    )
                )

            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": base
                        + [
                            {"term": {"event_type": "ssh_auth"}},
                            {"terms": {"ssh_action": ["failed_password", "invalid_user"]}},
                            {"exists": {"field": "ssh_username"}},
                        ]
                    }
                },
                "aggs": {
                    "users": {
                        "terms": {"field": "ssh_username", "size": int(limit), "order": {"_count": "desc"}}
                    }
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            buckets = ((res.get("aggregations") or {}).get("users") or {}).get("buckets") or []
            users_attempted = [SshUserStat(username=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in buckets]

            body = {
                "size": int(limit),
                "sort": [{"timestamp": {"order": "desc"}}, {"id": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": base + [{"term": {"event_type": "sudo_cmd"}}]
                    }
                },
                "_source": {
                    "includes": [
                        "timestamp",
                        "agent_id",
                        "sudo_username",
                        "sudo_target_user",
                        "sudo_command",
                        "sudo_tty",
                        "sudo_pwd",
                    ]
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            sudo_recent: list[SudoEventSummary] = []
            for h in ((res.get("hits") or {}).get("hits") or []):
                src = h.get("_source") or {}
                sudo_recent.append(
                    SudoEventSummary(
                        timestamp=_parse_iso_dt(src.get("timestamp") if isinstance(src.get("timestamp"), str) else None),
                        agent_id=str(src.get("agent_id") or ""),
                        username=src.get("sudo_username"),
                        target_user=src.get("sudo_target_user"),
                        command=src.get("sudo_command"),
                        tty=src.get("sudo_tty"),
                        pwd=src.get("sudo_pwd"),
                    )
                )

            payload = SshSummaryResponse(
                generated_at=datetime.now(timezone.utc),
                since_minutes=int(since_minutes),
                agent_id=agent_id,
                total_accepted=total_accepted,
                total_failed_password=total_failed_password,
                total_invalid_user=total_invalid_user,
                total_actions=total_accepted + total_failed_password + total_invalid_user,
                unique_source_ips=unique_source_ips,
                enriched_source_ips=enriched_source_ips,
                recent_auth_events=recent_auth_events,
                successful_logins=successful_logins,
                failed_attempts=failed_attempts,
                invalid_user_attempts=invalid_user_attempts,
                most_active_ips=most_active_ips,
                root_logins=root_logins,
                users_attempted=users_attempted,
                sudo_recent=sudo_recent,
            )
            _cache_set_json(cache_key, payload.dict(), int(getattr(settings, "NETWATCH_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15))
            observe_hist("api_route_latency_seconds", time.perf_counter() - started, route="/events/ssh/summary", source="elasticsearch")
            return payload
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")

    db = SessionLocal()
    try:
        ssh_action = func.coalesce(NetEventModel.ssh_action, NetEventModel.extra["action"].astext)
        ssh_user = func.coalesce(NetEventModel.ssh_username, NetEventModel.extra["username"].astext)
        geo_country = NetEventModel.extra["geo_country"].astext
        geo_org = NetEventModel.extra["geo_org"].astext
        asn = NetEventModel.extra["asn"].astext
        asn_org = NetEventModel.extra["asn_org"].astext
        has_enrichment = or_(
            func.coalesce(geo_country, "") != "",
            func.coalesce(geo_org, "") != "",
            func.coalesce(asn, "") != "",
            func.coalesce(asn_org, "") != "",
        )

        def _top_ips(action: str) -> list[SshIpStat]:
            stmt = (
                select(
                    NetEventModel.src_ip.label("src_ip"),
                    func.count().label("count"),
                    func.max(geo_country).label("geo_country"),
                    func.max(geo_org).label("geo_org"),
                    func.max(asn).label("asn"),
                    func.max(asn_org).label("asn_org"),
                )
                .where(
                    NetEventModel.event_type == "ssh_auth",
                    ssh_action == action,
                    NetEventModel.timestamp >= since_ts,
                    NetEventModel.src_ip.is_not(None),
                )
                .group_by(NetEventModel.src_ip)
                .order_by(func.count().desc())
                .limit(int(limit))
            )
            if agent_id:
                stmt = stmt.where(NetEventModel.agent_id == agent_id)
            rows = db.execute(stmt).mappings().all()
            return [SshIpStat(**dict(r)) for r in rows]

        totals_stmt = (
            select(
                func.count().filter(ssh_action == "accepted").label("total_accepted"),
                func.count().filter(ssh_action == "failed_password").label("total_failed_password"),
                func.count().filter(ssh_action == "invalid_user").label("total_invalid_user"),
                func.count(func.distinct(NetEventModel.src_ip))
                .filter(
                    NetEventModel.src_ip.is_not(None),
                    ssh_action.in_(tracked_actions),
                )
                .label("unique_source_ips"),
                func.count(func.distinct(NetEventModel.src_ip))
                .filter(
                    NetEventModel.src_ip.is_not(None),
                    ssh_action.in_(tracked_actions),
                    has_enrichment,
                )
                .label("enriched_source_ips"),
            )
            .where(
                NetEventModel.event_type == "ssh_auth",
                NetEventModel.timestamp >= since_ts,
            )
        )
        if agent_id:
            totals_stmt = totals_stmt.where(NetEventModel.agent_id == agent_id)
        totals_row = db.execute(totals_stmt).mappings().one()
        total_accepted = int(totals_row.get("total_accepted", 0) or 0)
        total_failed_password = int(totals_row.get("total_failed_password", 0) or 0)
        total_invalid_user = int(totals_row.get("total_invalid_user", 0) or 0)
        unique_source_ips = int(totals_row.get("unique_source_ips", 0) or 0)
        enriched_source_ips = int(totals_row.get("enriched_source_ips", 0) or 0)

        recent_stmt = (
            select(
                NetEventModel.timestamp.label("timestamp"),
                NetEventModel.agent_id.label("agent_id"),
                ssh_action.label("action"),
                NetEventModel.src_ip.label("src_ip"),
                ssh_user.label("username"),
                geo_country.label("geo_country"),
                geo_org.label("geo_org"),
                asn.label("asn"),
                asn_org.label("asn_org"),
            )
            .where(
                NetEventModel.event_type == "ssh_auth",
                ssh_action.in_(tracked_actions),
                NetEventModel.timestamp >= since_ts,
            )
            .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
            .limit(int(limit))
        )
        if agent_id:
            recent_stmt = recent_stmt.where(NetEventModel.agent_id == agent_id)
        recent_auth_events = [SshAuthEvent(**dict(r)) for r in db.execute(recent_stmt).mappings().all()]

        successful_logins = _top_ips("accepted")
        failed_attempts = _top_ips("failed_password")
        invalid_user_attempts = _top_ips("invalid_user")

        stmt = (
            select(
                NetEventModel.src_ip.label("src_ip"),
                func.count().label("count"),
                func.max(geo_country).label("geo_country"),
                func.max(geo_org).label("geo_org"),
                func.max(asn).label("asn"),
                func.max(asn_org).label("asn_org"),
            )
            .where(
                NetEventModel.event_type == "ssh_auth",
                ssh_action.in_(tracked_actions),
                NetEventModel.timestamp >= since_ts,
                NetEventModel.src_ip.is_not(None),
            )
            .group_by(NetEventModel.src_ip)
            .order_by(func.count().desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = db.execute(stmt).mappings().all()
        most_active_ips = [SshIpStat(**dict(r)) for r in rows]

        stmt = (
            select(
                NetEventModel.timestamp.label("timestamp"),
                NetEventModel.agent_id.label("agent_id"),
                NetEventModel.src_ip.label("src_ip"),
                ssh_user.label("username"),
                geo_country.label("geo_country"),
                geo_org.label("geo_org"),
                asn.label("asn"),
                asn_org.label("asn_org"),
            )
            .where(
                NetEventModel.event_type == "ssh_auth",
                ssh_action == "accepted",
                ssh_user == "root",
                NetEventModel.timestamp >= since_ts,
            )
            .order_by(NetEventModel.timestamp.desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = db.execute(stmt).mappings().all()
        root_logins = [SshLoginEvent(**dict(r)) for r in rows]

        stmt = (
            select(
                ssh_user.label("username"),
                func.count().label("count"),
            )
            .where(
                NetEventModel.event_type == "ssh_auth",
                ssh_action.in_(["failed_password", "invalid_user"]),
                NetEventModel.timestamp >= since_ts,
                ssh_user.is_not(None),
            )
            .group_by(ssh_user)
            .order_by(func.count().desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = db.execute(stmt).mappings().all()
        users_attempted = [SshUserStat(**dict(r)) for r in rows]

        stmt = (
            select(
                NetEventModel.timestamp.label("timestamp"),
                NetEventModel.agent_id.label("agent_id"),
                ssh_user.label("username"),
                NetEventModel.extra["target_user"].astext.label("target_user"),
                NetEventModel.extra["command"].astext.label("command"),
                NetEventModel.extra["tty"].astext.label("tty"),
                NetEventModel.extra["pwd"].astext.label("pwd"),
            )
            .where(
                NetEventModel.event_type == "sudo_cmd",
                NetEventModel.timestamp >= since_ts,
            )
            .order_by(NetEventModel.timestamp.desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = db.execute(stmt).mappings().all()
        sudo_recent = [SudoEventSummary(**dict(r)) for r in rows]

        payload = SshSummaryResponse(
            generated_at=datetime.now(timezone.utc),
            since_minutes=int(since_minutes),
            agent_id=agent_id,
            total_accepted=total_accepted,
            total_failed_password=total_failed_password,
            total_invalid_user=total_invalid_user,
            total_actions=total_accepted + total_failed_password + total_invalid_user,
            unique_source_ips=unique_source_ips,
            enriched_source_ips=enriched_source_ips,
            recent_auth_events=recent_auth_events,
            successful_logins=successful_logins,
            failed_attempts=failed_attempts,
            invalid_user_attempts=invalid_user_attempts,
            most_active_ips=most_active_ips,
            root_logins=root_logins,
            users_attempted=users_attempted,
            sudo_recent=sudo_recent,
        )
        _cache_set_json(cache_key, payload.dict(), int(getattr(settings, "NETWATCH_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15))
        observe_hist("api_route_latency_seconds", time.perf_counter() - started, route="/events/ssh/summary", source="postgres")
        return payload
    finally:
        db.close()


@router.get("/network/summary", response_model=ProtocolIntelSummaryResponse)
def get_protocol_intel_summary(
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(25, ge=1, le=200, description="Top-N limit for aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
):
    """Protocol Intelligence summary.

    Aggregates protocol-aware metadata produced by the protocol_intel worker.

    Note: when Elasticsearch is available, this endpoint uses ES aggregations
    to reduce load on Postgres.
    """

    started = time.perf_counter()
    since_ts = datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes))
    cache_key = (
        "netwatch:events:network_summary:v4:"
        f"sb={search_backend_mode()}:sm={int(since_minutes)}:l={int(limit)}:a={agent_id or '*'}"
    )
    cached = _cache_get_json(cache_key)
    if cached is not None:
        incr_counter("api_cache_hit_total", route="/events/network/summary")
        return ProtocolIntelSummaryResponse(**cached)

    ch = _ch_client_or_none()
    if ch is not None:
        try:
            table = clickhouse_events_table_ref()
            where_sql, params = _ch_where(since=since_ts, agent_id=agent_id)
            dedup_source_sql = _ch_deduped_events_source_sql(table=table, where_sql=where_sql)

            overview_sql = (
                f"SELECT "
                f"count() AS total_events, "
                f"countIf("
                f"ifNull(d.app_proto, '') != '' OR "
                f"ifNull(d.dns_qname, '') != '' OR "
                f"ifNull(d.http_host, '') != '' OR "
                f"ifNull(d.http_method, '') != '' OR "
                f"ifNull(d.ja4, '') != '' OR "
                f"ifNull(d.ja3, '') != '' OR "
                f"ifNull(d.tls_sni, '') != ''"
                f") AS with_proto_metadata, "
                f"countIf(ifNull(d.dns_qname, '') != '') AS dns_events, "
                f"countIf(ifNull(d.http_host, '') != '' OR ifNull(d.http_method, '') != '') AS http_events, "
                f"countIf(ifNull(d.ja4, '') != '' OR ifNull(d.ja3, '') != '' OR ifNull(d.tls_sni, '') != '') AS tls_events "
                f"FROM ({dedup_source_sql}) AS d"
            )
            ov = (_ch_query_dicts(ch, overview_sql, params) or [{}])[0]
            ch_total_events = int(ov.get("total_events") or 0)
            if ch_total_events <= 0:
                raise LookupError("clickhouse_empty")
            if int(ov.get("with_proto_metadata") or 0) <= 0 and _pg_has_protocol_metadata(since=since_ts, agent_id=agent_id):
                raise LookupError("clickhouse_proto_metadata_stale")

            last_ts_sql = f"SELECT max(timestamp) AS last_ts FROM ({dedup_source_sql}) AS d"
            last_ts_row = (_ch_query_dicts(ch, last_ts_sql, params) or [{}])[0]
            ch_last_ts = _parse_iso_dt_or_none(last_ts_row.get("last_ts"))
            if ch_last_ts is None:
                raise LookupError("clickhouse_no_last_ts")
            if _pg_has_newer_event(latest_ts=ch_last_ts, agent_id=agent_id):
                raise LookupError("clickhouse_stale")

            app_protocols = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="ifNull(d.app_proto, '')", limit=int(limit),
            )
            transport_protocols = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="lowerUTF8(ifNull(d.proto, ''))", limit=int(limit),
            )
            top_dst_ports = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="toString(d.dst_port)", limit=int(limit),
            )
            top_src_ports = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="toString(d.src_port)", limit=int(limit),
            )
            if not app_protocols and ch_total_events > 0:
                guess_sql = (
                    "SELECT "
                    "multiIf("
                    "d.dst_port IN (53,5353), 'dns', "
                    "d.dst_port IN (80,8080,8000,8888), 'http', "
                    "d.dst_port IN (443,8443), 'tls', "
                    "d.dst_port = 22, 'ssh', "
                    "ifNull(lowerUTF8(d.proto), '') != '', lowerUTF8(d.proto), "
                    "'unknown'"
                    ") AS k, "
                    "count() AS c "
                    f"FROM ({dedup_source_sql}) AS d "
                    "GROUP BY k "
                    "ORDER BY c DESC "
                    f"LIMIT {int(limit)}"
                )
                guess_rows = _ch_query_dicts(ch, guess_sql, params)
                app_protocols = [ProtoCount(key=str(r.get("k")), count=int(r.get("c") or 0)) for r in guess_rows if r.get("k")]
            app_proto_reasons = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="ifNull(d.app_proto_reason, '')", limit=int(limit),
            )
            app_proto_conf_bands = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="ifNull(d.app_proto_conf_band, '')", limit=int(limit),
            )
            ja4_ptypes = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="if(ifNull(d.ja4_ptype, '') = '', 't', d.ja4_ptype)",
                limit=int(limit), nonempty=False,
            )
            http_methods = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="upperUTF8(ifNull(d.http_method, ''))", limit=int(limit),
            )

            dns_sql = (
                f"SELECT d.dns_qname AS qname, "
                f"max(toInt32OrZero(JSONExtractString(d.extra_json, 'dns_risk'))) AS risk, "
                f"count() AS c "
                f"FROM ({dedup_source_sql}) AS d "
                f"GROUP BY qname HAVING qname != '' "
                f"ORDER BY c DESC LIMIT {int(limit)}"
            )
            dns_rows = _ch_query_dicts(ch, dns_sql, params)
            top_dns_queries = [
                ProtoDnsQueryStat(qname=str(r.get("qname")), risk=int(r.get("risk") or 0), count=int(r.get("c") or 0))
                for r in dns_rows if r.get("qname")
            ]

            top_http_hosts = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="lowerUTF8(ifNull(d.http_host, ''))", limit=int(limit),
            )
            top_tls_sni = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="lowerUTF8(ifNull(d.tls_sni, ''))", limit=int(limit),
            )
            top_alpn = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="lowerUTF8(ifNull(d.tls_alpn_first, ''))", limit=int(limit),
            )

            ja4_sql = (
                f"SELECT "
                f"ja4, any(ptype) AS ptype, count() AS c "
                f"FROM ("
                f"SELECT ifNull(d.ja4, '') AS ja4, "
                f"if(ifNull(d.ja4_ptype, '') = '', 't', d.ja4_ptype) AS ptype "
                f"FROM ({dedup_source_sql}) AS d"
                f") "
                f"GROUP BY ja4 HAVING ja4 != '' "
                f"ORDER BY c DESC LIMIT {int(limit)}"
            )
            ja4_rows = _ch_query_dicts(ch, ja4_sql, params)
            top_ja4 = [
                ProtoJa4Stat(ja4=str(r.get("ja4")), ptype=str(r.get("ptype") or "t"), count=int(r.get("c") or 0))
                for r in ja4_rows if r.get("ja4")
            ]

            top_ja3 = _ch_top_counts(
                ch, source_sql=dedup_source_sql, params=params,
                key_expr="ifNull(d.ja3, '')", limit=int(limit),
            )

            payload = ProtocolIntelSummaryResponse(
                generated_at=datetime.now(timezone.utc),
                since_minutes=int(since_minutes),
                agent_id=agent_id,
                total_events=ch_total_events,
                with_proto_metadata=int(ov.get("with_proto_metadata") or 0),
                dns_events=int(ov.get("dns_events") or 0),
                http_events=int(ov.get("http_events") or 0),
                tls_events=int(ov.get("tls_events") or 0),
                app_protocols=app_protocols,
                transport_protocols=transport_protocols,
                top_dst_ports=top_dst_ports,
                top_src_ports=top_src_ports,
                app_proto_reasons=app_proto_reasons,
                app_proto_conf_bands=app_proto_conf_bands,
                ja4_ptypes=ja4_ptypes,
                http_methods=http_methods,
                top_dns_queries=top_dns_queries,
                top_http_hosts=top_http_hosts,
                top_tls_sni=top_tls_sni,
                top_alpn=top_alpn,
                top_ja4=top_ja4,
                top_ja3=top_ja3,
            )
            _cache_set_json(cache_key, payload.dict(), int(getattr(settings, "NETWATCH_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15))
            observe_hist("api_route_latency_seconds", time.perf_counter() - started, route="/events/network/summary", source="clickhouse")
            return payload
        except Exception as e:
            if not isinstance(e, LookupError):
                log_event(logger, "warning", "events_network_summary_clickhouse_error", error_type=type(e).__name__)

    es = _es_client_or_none()
    if es is not None:
        try:
            base = _es_base_filters(since=since_ts, agent_id=agent_id)

            # Single query with filter aggs + terms aggs (efficient on ES).
            body: Dict[str, Any] = {
                "size": 0,
                "query": {"bool": {"filter": base}},
                "aggs": {
                    "with_proto_metadata": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"exists": {"field": "app_proto"}},
                                    {"exists": {"field": "dns_qname"}},
                                    {"exists": {"field": "http_host"}},
                                    {"exists": {"field": "http_method"}},
                                    {"exists": {"field": "ja4"}},
                                    {"exists": {"field": "ja3"}},
                                    {"exists": {"field": "tls_sni"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "dns_events": {"filter": {"exists": {"field": "dns_qname"}}},
                    "http_events": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"exists": {"field": "http_host"}},
                                    {"exists": {"field": "http_method"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "tls_events": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"exists": {"field": "ja4"}},
                                    {"exists": {"field": "ja3"}},
                                    {"exists": {"field": "tls_sni"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "app_protocols": {"terms": {"field": "app_proto", "size": int(limit), "order": {"_count": "desc"}}},
                    "transport_protocols": {"terms": {"field": "proto", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_dst_ports": {"terms": {"field": "dst_port", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_src_ports": {"terms": {"field": "src_port", "size": int(limit), "order": {"_count": "desc"}}},
                    "app_proto_reasons": {"terms": {"field": "app_proto_reason", "size": int(limit), "order": {"_count": "desc"}}},
                    "app_proto_conf_bands": {
                        "terms": {"field": "app_proto_conf_band", "size": int(limit), "order": {"_count": "desc"}}
                    },
                    "ja4_ptypes": {"terms": {"field": "ja4_ptype", "size": int(limit), "order": {"_count": "desc"}}},
                    "http_methods": {"terms": {"field": "http_method", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_dns_queries": {
                        "terms": {"field": "dns_qname", "size": int(limit), "order": {"_count": "desc"}},
                        "aggs": {"risk": {"max": {"field": "dns_risk"}}},
                    },
                    "top_http_hosts": {"terms": {"field": "http_host", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_tls_sni": {"terms": {"field": "tls_sni", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_alpn": {"terms": {"field": "tls_alpn_first", "size": int(limit), "order": {"_count": "desc"}}},
                    "top_ja4": {
                        "terms": {"field": "ja4", "size": int(limit), "order": {"_count": "desc"}},
                        "aggs": {"ptype": {"terms": {"field": "ja4_ptype", "size": 1, "order": {"_count": "desc"}}}},
                    },
                    "top_ja3": {"terms": {"field": "ja3", "size": int(limit), "order": {"_count": "desc"}}},
                    "latest_ts": {"max": {"field": "timestamp"}},
                },
            }

            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)

            total_events = int(((res.get("hits") or {}).get("total") or {}).get("value", 0) or 0)
            # When track_total_hits=False, total may be missing. Use count API for correctness.
            if total_events == 0:
                total_events = int(
                    es.count(
                        index=_es_index_pattern(),
                        body={"query": {"bool": {"filter": base}}},
                        ignore_unavailable=True,
                        allow_no_indices=True,
                    ).get("count", 0)
                )

            aggs = res.get("aggregations") or {}

            with_proto_metadata = int(((aggs.get("with_proto_metadata") or {}).get("doc_count", 0)) or 0)
            dns_events = int(((aggs.get("dns_events") or {}).get("doc_count", 0)) or 0)
            http_events = int(((aggs.get("http_events") or {}).get("doc_count", 0)) or 0)
            tls_events = int(((aggs.get("tls_events") or {}).get("doc_count", 0)) or 0)
            es_latest_ts: datetime | None = None
            latest_ts_value = (aggs.get("latest_ts") or {}).get("value")
            if latest_ts_value is not None:
                try:
                    es_latest_ts = datetime.fromtimestamp(float(latest_ts_value) / 1000.0, tz=timezone.utc)
                except Exception:
                    es_latest_ts = None

            if _es_failover_allowed():
                if total_events <= 0:
                    raise LookupError("es_empty_summary")
                if with_proto_metadata <= 0 and _pg_has_protocol_metadata(since=since_ts, agent_id=agent_id):
                    raise LookupError("es_proto_metadata_stale")
                if es_latest_ts is not None and _pg_has_newer_event(latest_ts=es_latest_ts, agent_id=agent_id):
                    raise LookupError("es_stale_summary")

            def _buckets(name: str) -> list[dict]:
                return ((aggs.get(name) or {}).get("buckets") or [])

            app_protocols = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("app_protocols") if b.get("key") is not None]
            transport_protocols = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("transport_protocols") if b.get("key") is not None]
            top_dst_ports = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_dst_ports") if b.get("key") is not None]
            top_src_ports = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_src_ports") if b.get("key") is not None]
            if not app_protocols and total_events > 0:
                app_protocols = _guess_app_protocols_from_port_counts(top_dst_ports)
                if not app_protocols:
                    app_protocols = [ProtoCount(key=str(x.key), count=int(x.count or 0)) for x in transport_protocols]
            app_proto_reasons = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("app_proto_reasons") if b.get("key") is not None]
            app_proto_conf_bands = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("app_proto_conf_bands") if b.get("key") is not None]
            ja4_ptypes = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("ja4_ptypes") if b.get("key") is not None]
            http_methods = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("http_methods") if b.get("key") is not None]

            top_dns_queries: list[ProtoDnsQueryStat] = []
            for b in _buckets("top_dns_queries"):
                k = b.get("key")
                if k is None:
                    continue
                risk_val = ((b.get("risk") or {}).get("value") or 0) or 0
                top_dns_queries.append(ProtoDnsQueryStat(qname=str(k), risk=int(risk_val), count=int(b.get("doc_count", 0) or 0)))

            top_http_hosts = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_http_hosts") if b.get("key") is not None]
            top_tls_sni = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_tls_sni") if b.get("key") is not None]
            top_alpn = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_alpn") if b.get("key") is not None]

            top_ja4: list[ProtoJa4Stat] = []
            for b in _buckets("top_ja4"):
                k = b.get("key")
                if k is None:
                    continue
                ptype_buckets = ((b.get("ptype") or {}).get("buckets") or [])
                ptype = str(ptype_buckets[0].get("key")) if ptype_buckets else "t"
                top_ja4.append(ProtoJa4Stat(ja4=str(k), ptype=ptype, count=int(b.get("doc_count", 0) or 0)))

            top_ja3 = [ProtoCount(key=str(b.get("key")), count=int(b.get("doc_count", 0) or 0)) for b in _buckets("top_ja3") if b.get("key") is not None]

            payload = ProtocolIntelSummaryResponse(
                generated_at=datetime.now(timezone.utc),
                since_minutes=int(since_minutes),
                agent_id=agent_id,
                total_events=total_events,
                with_proto_metadata=with_proto_metadata,
                dns_events=dns_events,
                http_events=http_events,
                tls_events=tls_events,
                app_protocols=app_protocols,
                transport_protocols=transport_protocols,
                top_dst_ports=top_dst_ports,
                top_src_ports=top_src_ports,
                app_proto_reasons=app_proto_reasons,
                app_proto_conf_bands=app_proto_conf_bands,
                ja4_ptypes=ja4_ptypes,
                http_methods=http_methods,
                top_dns_queries=top_dns_queries,
                top_http_hosts=top_http_hosts,
                top_tls_sni=top_tls_sni,
                top_alpn=top_alpn,
                top_ja4=top_ja4,
                top_ja3=top_ja3,
            )
            _cache_set_json(cache_key, payload.dict(), int(getattr(settings, "NETWATCH_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15))
            observe_hist("api_route_latency_seconds", time.perf_counter() - started, route="/events/network/summary", source="elasticsearch")
            return payload
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")

    # Postgres fallback (original implementation)
    db = SessionLocal()
    try:
        app_proto_expr = func.coalesce(NetEventModel.app_proto, NetEventModel.extra["app_proto"].astext)
        app_proto_reason_expr = func.coalesce(NetEventModel.app_proto_reason, NetEventModel.extra["app_proto_reason"].astext)
        app_proto_conf_expr = func.coalesce(NetEventModel.app_proto_conf_band, NetEventModel.extra["app_proto_conf_band"].astext)
        dns_qname_expr = func.coalesce(NetEventModel.dns_qname, NetEventModel.extra["dns_qname"].astext)
        http_host_expr = func.coalesce(NetEventModel.http_host, NetEventModel.extra["http_host"].astext)
        http_method_expr = func.coalesce(NetEventModel.http_method, NetEventModel.extra["http_method"].astext)
        tls_sni_expr = func.coalesce(NetEventModel.tls_sni, NetEventModel.extra["tls_sni"].astext)
        tls_alpn_expr = func.coalesce(NetEventModel.tls_alpn_first, NetEventModel.extra["tls_alpn_first"].astext)
        ja4_expr = func.coalesce(NetEventModel.ja4, NetEventModel.extra["ja4"].astext)
        ja4_ptype_expr = func.coalesce(NetEventModel.ja4_ptype, NetEventModel.extra["ja4_ptype"].astext, "t")
        ja3_expr = func.coalesce(NetEventModel.ja3, NetEventModel.extra["ja3"].astext)

        base_conds = [NetEventModel.timestamp >= since_ts]
        if agent_id:
            base_conds.append(NetEventModel.agent_id == agent_id)

        counts = db.execute(
            select(
                func.count().label("total_events"),
                func.count().filter(
                    or_(
                        func.nullif(app_proto_expr, "").is_not(None),
                        func.nullif(dns_qname_expr, "").is_not(None),
                        func.nullif(http_host_expr, "").is_not(None),
                        func.nullif(http_method_expr, "").is_not(None),
                        func.nullif(ja4_expr, "").is_not(None),
                        func.nullif(ja3_expr, "").is_not(None),
                        func.nullif(tls_sni_expr, "").is_not(None),
                    )
                ).label("with_proto_metadata"),
                func.count().filter(func.nullif(dns_qname_expr, "").is_not(None)).label("dns_events"),
                func.count().filter(or_(func.nullif(http_host_expr, "").is_not(None), func.nullif(http_method_expr, "").is_not(None))).label("http_events"),
                func.count().filter(or_(func.nullif(ja4_expr, "").is_not(None), func.nullif(ja3_expr, "").is_not(None), func.nullif(tls_sni_expr, "").is_not(None))).label("tls_events"),
            ).where(*base_conds)
        ).mappings().one()

        total_events = int(counts.get("total_events") or 0)
        with_proto_metadata = int(counts.get("with_proto_metadata") or 0)
        dns_events = int(counts.get("dns_events") or 0)
        http_events = int(counts.get("http_events") or 0)
        tls_events = int(counts.get("tls_events") or 0)

        def _top_k(expr, *, nonempty: bool = True) -> list[ProtoCount]:
            stmt = select(expr.label("key"), func.count().label("count")).where(*base_conds)
            if nonempty:
                stmt = stmt.where(expr.is_not(None), expr != "")
            stmt = stmt.group_by(expr).order_by(func.count().desc()).limit(int(limit))
            rows = db.execute(stmt).all()
            return [ProtoCount(key=str(r.key), count=int(r.count or 0)) for r in rows if r.key is not None]

        app_protocols = _top_k(app_proto_expr)
        transport_protocols = _top_k(func.lower(NetEventModel.proto))
        top_dst_ports = _top_k(cast(NetEventModel.dst_port, String))
        top_src_ports = _top_k(cast(NetEventModel.src_port, String))
        if not app_protocols and total_events > 0:
            app_protocols = _guess_app_protocols_from_port_counts(top_dst_ports)
            if not app_protocols:
                app_protocols = [ProtoCount(key=str(x.key), count=int(x.count or 0)) for x in transport_protocols]
        app_proto_reasons = _top_k(app_proto_reason_expr)
        app_proto_conf_bands = _top_k(app_proto_conf_expr)
        ja4_ptypes = _top_k(
            func.coalesce(func.nullif(ja4_ptype_expr, ""), "t"),
            nonempty=False,
        )
        http_methods = _top_k(func.upper(http_method_expr))

        dns_qname = dns_qname_expr
        dns_risk_txt = NetEventModel.extra["dns_risk"].astext
        dns_risk_int = cast(
            func.coalesce(
                func.nullif(
                    func.regexp_replace(func.coalesce(dns_risk_txt, ""), r"[^0-9-]", "", "g"),
                    "",
                ),
                "0",
            ),
            Integer,
        )
        dns_rows = db.execute(
            select(
                dns_qname.label("qname"),
                func.coalesce(func.max(dns_risk_int), 0).label("risk"),
                func.count().label("count"),
            )
            .where(*base_conds, dns_qname.is_not(None), dns_qname != "")
            .group_by(dns_qname)
            .order_by(func.count().desc())
            .limit(int(limit))
        ).all()
        top_dns_queries = [ProtoDnsQueryStat(qname=str(r.qname), risk=int(r.risk or 0), count=int(r.count or 0)) for r in dns_rows]

        top_http_hosts = _top_k(func.lower(http_host_expr))
        top_tls_sni = _top_k(func.lower(tls_sni_expr))
        top_alpn = _top_k(func.lower(tls_alpn_expr))

        ja4_rows = db.execute(
            select(
                ja4_expr.label("ja4"),
                func.coalesce(func.nullif(func.max(ja4_ptype_expr), ""), "t").label("ptype"),
                func.count().label("count"),
            )
            .where(*base_conds, ja4_expr.is_not(None), ja4_expr != "")
            .group_by(ja4_expr)
            .order_by(func.count().desc())
            .limit(int(limit))
        ).all()
        top_ja4 = [ProtoJa4Stat(ja4=str(r.ja4), ptype=str(r.ptype or "t"), count=int(r.count or 0)) for r in ja4_rows]

        top_ja3 = _top_k(ja3_expr)

        # If raw events are absent in the window (common under aggressive shedding),
        # fallback to ingest 1s rollups so L4 protocol/port panels still show activity.
        if total_events <= 0:
            r_total, r_transport, r_dst_ports = _pg_rollup_l4_snapshot(
                db,
                since_ts=since_ts,
                limit=int(limit),
                agent_id=agent_id,
            )
            if r_total > 0:
                total_events = int(r_total)
                if not transport_protocols:
                    transport_protocols = r_transport
                if not top_dst_ports:
                    top_dst_ports = r_dst_ports
                if not app_protocols:
                    app_protocols = _guess_app_protocols_from_port_counts(top_dst_ports)
                    if not app_protocols:
                        app_protocols = [ProtoCount(key=str(x.key), count=int(x.count or 0)) for x in transport_protocols]

        payload = ProtocolIntelSummaryResponse(
            generated_at=datetime.now(timezone.utc),
            since_minutes=int(since_minutes),
            agent_id=agent_id,
            total_events=total_events,
            with_proto_metadata=with_proto_metadata,
            dns_events=dns_events,
            http_events=http_events,
            tls_events=tls_events,
            app_protocols=app_protocols,
            transport_protocols=transport_protocols,
            top_dst_ports=top_dst_ports,
            top_src_ports=top_src_ports,
            app_proto_reasons=app_proto_reasons,
            app_proto_conf_bands=app_proto_conf_bands,
            ja4_ptypes=ja4_ptypes,
            http_methods=http_methods,
            top_dns_queries=top_dns_queries,
            top_http_hosts=top_http_hosts,
            top_tls_sni=top_tls_sni,
            top_alpn=top_alpn,
            top_ja4=top_ja4,
            top_ja3=top_ja3,
        )
        _cache_set_json(cache_key, payload.dict(), int(getattr(settings, "NETWATCH_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15))
        observe_hist("api_route_latency_seconds", time.perf_counter() - started, route="/events/network/summary", source="postgres")
        return payload
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
    log_event(
        logger,
        "info",
        "protocol_intel_samples_requested",
        kind=kind,
        value_len=len(value or ""),
        since_minutes=int(since_minutes),
        limit=int(limit),
        agent_id=agent_id or "",
    )

    # Whitelist (avoid field injection)
    kind_map = {
        "app_proto": "app_proto",
        "transport": "proto",
        "dst_port": "dst_port",
        "src_port": "src_port",
        "app_proto_reason": "app_proto_reason",
        "app_proto_conf_band": "app_proto_conf_band",
        "dns_qname": "dns_qname",
        "http_host": "http_host",
        "http_method": "http_method",
        "tls_sni": "tls_sni",
        "tls_alpn_first": "tls_alpn_first",
        "ja4": "ja4",
        "ja4_ptype": "ja4_ptype",
        "ja3": "ja3",
    }
    es_field = kind_map.get(kind)
    if not es_field:
        return []

    value_norm: Any = value
    if kind in {"http_host", "tls_sni", "tls_alpn_first", "dns_qname"}:
        value_norm = value.lower()
    elif kind == "http_method":
        value_norm = value.upper()
    elif kind == "transport":
        value_norm = value.lower()
    elif kind in {"dst_port", "src_port"}:
        try:
            value_norm = int(value)
        except Exception:
            return []
        if int(value_norm) < 0 or int(value_norm) > 65535:
            return []

    ch = _ch_client_or_none()
    if ch is not None:
        try:
            table = clickhouse_events_table_ref()
            where_sql, params = _ch_where(since=since_ts, agent_id=agent_id)
            dedup_source_sql = _ch_deduped_events_source_sql(table=table, where_sql=where_sql)
            expr_map = {
                "app_proto": "ifNull(d.app_proto, '')",
                "transport": "lowerUTF8(ifNull(d.proto, ''))",
                "dst_port": "d.dst_port",
                "src_port": "d.src_port",
                "app_proto_reason": "ifNull(d.app_proto_reason, '')",
                "app_proto_conf_band": "ifNull(d.app_proto_conf_band, '')",
                "dns_qname": "lowerUTF8(ifNull(d.dns_qname, ''))",
                "http_host": "lowerUTF8(ifNull(d.http_host, ''))",
                "http_method": "upperUTF8(ifNull(d.http_method, ''))",
                "tls_sni": "lowerUTF8(ifNull(d.tls_sni, ''))",
                "tls_alpn_first": "lowerUTF8(ifNull(d.tls_alpn_first, ''))",
                "ja4": "ifNull(d.ja4, '')",
                "ja4_ptype": "if(ifNull(d.ja4_ptype, '') = '', 't', d.ja4_ptype)",
                "ja3": "ifNull(d.ja3, '')",
            }
            filter_expr = expr_map.get(kind)
            if not filter_expr:
                return []

            if kind in {"dst_port", "src_port"}:
                params["indicator_u16"] = int(value_norm)
                filter_sql = f"{filter_expr} = {{indicator_u16:UInt16}}"
            else:
                params["indicator_str"] = str(value_norm)
                filter_sql = f"{filter_expr} = {{indicator_str:String}}"

            sql = (
                "SELECT pg_event_id, agent_id, event_type, schema_version, timestamp, "
                "src_ip, dst_ip, src_port, dst_port, proto, bytes, extra_json "
                f"FROM ({dedup_source_sql}) AS d "
                f"WHERE {filter_sql} "
                "ORDER BY timestamp DESC, pg_event_id DESC, ingested_at DESC "
                f"LIMIT {int(limit)}"
            )
            rows = _ch_query_dicts(ch, sql, params)
            out: list[NetEventDB] = []
            for row in rows:
                item = _ch_row_to_event(row)
                if item is None:
                    continue
                item.extra = _strip_large_extra(item.extra)
                out.append(item)
            if out:
                log_event(
                    logger,
                    "info",
                    "protocol_intel_samples_ok",
                    kind=kind,
                    matched=len(out),
                    source="clickhouse",
                )
                return out
        except Exception as e:
            log_event(
                logger,
                "warning",
                "protocol_intel_samples_clickhouse_error",
                kind=kind,
                error_type=type(e).__name__,
                error=str(e)[:300],
            )

    es = _es_client_or_none()
    if es is not None:
        try:
            base = _es_base_filters(since=since_ts, agent_id=agent_id)
            body = {
                "size": int(limit),
                "sort": [
                    {"timestamp": {"order": "desc", "unmapped_type": "date"}},
                    {"id": {"order": "desc", "unmapped_type": "long"}},
                ],
                "query": {
                    "bool": {
                        "filter": base + [{"term": {es_field: value_norm}}],
                    }
                },
            }
            res = es.search(index=_es_index_pattern(), body=body, ignore_unavailable=True, allow_no_indices=True)
            hits = (res.get("hits") or {}).get("hits") or []
            out: list[NetEventDB] = []
            for h in hits:
                try:
                    item = _hit_to_event(h)
                except Exception:
                    continue
                item.extra = _strip_large_extra(item.extra)
                out.append(item)
            if not out and _es_failover_allowed():
                raise LookupError("es_empty_samples")
            log_event(
                logger,
                "info",
                "protocol_intel_samples_ok",
                kind=kind,
                matched=len(out),
                source="elasticsearch",
            )
            return out
        except Exception as e:
            log_event(
                logger,
                "warning",
                "protocol_intel_samples_es_error",
                kind=kind,
                error_type=type(e).__name__,
                error=str(e)[:300],
            )
            # ES fallback: some indices may miss secondary sort fields (ex: id).
            # Retry with a timestamp-only sort and in-Python ordering stability.
            try:
                base = _es_base_filters(since=since_ts, agent_id=agent_id)
                body2 = {
                    "size": int(limit),
                    "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
                    "query": {
                        "bool": {
                            "filter": base + [{"term": {es_field: value_norm}}],
                        }
                    },
                }
                res2 = es.search(index=_es_index_pattern(), body=body2, ignore_unavailable=True, allow_no_indices=True)
                hits2 = (res2.get("hits") or {}).get("hits") or []
                out2: list[NetEventDB] = []
                for h in hits2:
                    try:
                        item = _hit_to_event(h)
                    except Exception:
                        continue
                    item.extra = _strip_large_extra(item.extra)
                    out2.append(item)
                out2.sort(key=lambda x: (x.timestamp, x.id), reverse=True)
                if not out2 and _es_failover_allowed():
                    raise LookupError("es_empty_samples_fallback")
                log_event(
                    logger,
                    "warning",
                    "protocol_intel_samples_es_fallback_ok",
                    kind=kind,
                    matched=len(out2),
                )
                return out2
            except Exception as e2:
                log_event(
                    logger,
                    "error",
                    "protocol_intel_samples_es_fallback_error",
                    kind=kind,
                    error_type=type(e2).__name__,
                    error=str(e2)[:300],
                )
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}")

    # Postgres fallback (ORM/expressions)
    kind_map_pg = {
        "app_proto": func.coalesce(NetEventModel.app_proto, NetEventModel.extra["app_proto"].astext),
        "transport": func.lower(NetEventModel.proto),
        "dst_port": NetEventModel.dst_port,
        "src_port": NetEventModel.src_port,
        "app_proto_reason": func.coalesce(NetEventModel.app_proto_reason, NetEventModel.extra["app_proto_reason"].astext),
        "app_proto_conf_band": func.coalesce(NetEventModel.app_proto_conf_band, NetEventModel.extra["app_proto_conf_band"].astext),
        "dns_qname": func.coalesce(NetEventModel.dns_qname, NetEventModel.extra["dns_qname"].astext),
        "http_host": func.lower(func.coalesce(NetEventModel.http_host, NetEventModel.extra["http_host"].astext)),
        "http_method": func.upper(func.coalesce(NetEventModel.http_method, NetEventModel.extra["http_method"].astext)),
        "tls_sni": func.lower(func.coalesce(NetEventModel.tls_sni, NetEventModel.extra["tls_sni"].astext)),
        "tls_alpn_first": func.lower(func.coalesce(NetEventModel.tls_alpn_first, NetEventModel.extra["tls_alpn_first"].astext)),
        "ja4": func.coalesce(NetEventModel.ja4, NetEventModel.extra["ja4"].astext),
        "ja4_ptype": func.coalesce(func.nullif(func.coalesce(NetEventModel.ja4_ptype, NetEventModel.extra["ja4_ptype"].astext), ""), "t"),
        "ja3": func.coalesce(NetEventModel.ja3, NetEventModel.extra["ja3"].astext),
    }
    expr = kind_map_pg.get(kind)
    if expr is None:
        return []
    uses_extra_json = kind in {
        "app_proto",
        "app_proto_reason",
        "app_proto_conf_band",
        "dns_qname",
        "http_host",
        "http_method",
        "tls_sni",
        "tls_alpn_first",
        "ja4",
        "ja4_ptype",
        "ja3",
    }

    db = SessionLocal()
    try:
        conds = [
            NetEventModel.timestamp >= since_ts,
            expr == value_norm,
        ]
        # Legacy safety: some rows can have JSON scalar/array in `extra`.
        # Guard key extraction with jsonb_typeof(extra)='object' to avoid PG runtime errors.
        if uses_extra_json:
            conds.append(func.jsonb_typeof(NetEventModel.extra) == "object")

        stmt = (
            select(
                NetEventModel.id,
                NetEventModel.agent_id,
                NetEventModel.event_type,
                NetEventModel.schema_version,
                NetEventModel.timestamp,
                NetEventModel.src_ip,
                NetEventModel.dst_ip,
                NetEventModel.src_port,
                NetEventModel.dst_port,
                NetEventModel.proto,
                NetEventModel.bytes,
                NetEventModel.extra,
            )
            .where(*conds)
            .order_by(NetEventModel.timestamp.desc())
            .limit(int(limit))
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        rows = db.execute(stmt).mappings().all()

        out: list[NetEventDB] = []
        for r in rows:
            item = _row_to_event_safe(dict(r))
            if item is None:
                continue
            out.append(item)
        log_event(
            logger,
            "info",
            "protocol_intel_samples_ok",
            kind=kind,
            matched=len(out),
            source="postgres",
        )
        return out
    except Exception as e:
        log_event(
            logger,
            "error",
            "protocol_intel_samples_pg_error",
            kind=kind,
            error_type=type(e).__name__,
            error=str(e)[:300],
        )
        return []
    finally:
        db.close()
