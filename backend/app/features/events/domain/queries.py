from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy import String, and_, cast, func, or_, select, text
from sqlalchemy.orm import Session

from app.core.api.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.config import settings
from app.core.integrations.clickhouse import (
    clickhouse_events_1m_table_ref,
    clickhouse_events_table_ref,
    clickhouse_is_available,
    clickhouse_is_enabled,
    get_clickhouse_client,
)
from app.core.integrations.es import es_is_available, get_es_client, search_backend_mode
from app.core.observability import log_event
from app.features.events import repository
from app.features.events.domain.eql import eql_response_is_incomplete
from app.features.events.domain.field_catalog import HUNT_FREE_TEXT_FIELDS
from app.features.events.domain.filters import _ch_where, _es_base_filters
from app.features.events.domain.hunt_dialects import HuntQueryError, translate_es_query_error
from app.features.events.domain.normalizers import (
    _ch_row_to_event,
    _hit_to_event,
    _row_to_event_safe,
    _strip_large_extra,
)
from app.features.events.models import NetEventModel, NetEventRollup1sModel
from app.features.events.schemas import NetEventDB, NetEventRollup1s, ProtoCount

logger = logging.getLogger("seagull.api.events")


def _es_index_pattern() -> str:
    prefix = (getattr(settings, "SEAGULL_ES_INDEX_PREFIX", "seagull-events") or "seagull-events").strip()
    return f"{prefix}-*"


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


def _es_with_request_timeout(es: Any, timeout_seconds: float | None) -> Any:
    if not timeout_seconds or float(timeout_seconds) <= 0:
        return es
    options = getattr(es, "options", None)
    if not callable(options):
        return es
    try:
        return options(request_timeout=float(timeout_seconds))
    except TypeError:
        return es


def _ch_timeout_settings(timeout_seconds: float | None) -> Dict[str, Any]:
    if not timeout_seconds or float(timeout_seconds) <= 0:
        return {}
    return {"max_execution_time": round(float(timeout_seconds), 3)}


def _pg_apply_statement_timeout(db: Session, timeout_seconds: float | None) -> None:
    if not timeout_seconds or float(timeout_seconds) <= 0:
        return
    try:
        bind = db.get_bind()
    except Exception:
        return
    if getattr(getattr(bind, "dialect", None), "name", "") != "postgresql":
        return
    db.execute(text(f"SET LOCAL statement_timeout = {max(1, int(float(timeout_seconds) * 1000.0))}"))


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


def _ch_client_or_none() -> Any | None:
    if not clickhouse_is_enabled():
        return None
    if not clickhouse_is_available():
        return None
    try:
        return get_clickhouse_client()
    except Exception:
        return None


def _ch_query_dicts(
    ch: Any,
    sql: str,
    params: Optional[Dict[str, Any]] = None,
    ch_settings: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    if ch_settings:
        res = ch.query(sql, parameters=(params or {}), settings=dict(ch_settings))
    else:
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
        "SELECT timestamp, pg_event_id, agent_id, event_type, schema_version, severity, "
        "src_ip, dst_ip, src_port, dst_port, proto, bytes, app_proto, app_proto_reason, "
        "app_proto_conf_band, dns_qname, http_host, http_method, tls_sni, tls_alpn_first, "
        "ja3, ja4, ja4_ptype, ssh_action, ssh_username, sudo_username, sudo_target_user, "
        "sudo_command, sudo_tty, extra_json, ingested_at "
        "FROM ("
        "SELECT "
        "timestamp, pg_event_id, agent_id, event_type, schema_version, severity, "
        "src_ip, dst_ip, src_port, dst_port, proto, bytes, app_proto, app_proto_reason, "
        "app_proto_conf_band, dns_qname, http_host, http_method, tls_sni, tls_alpn_first, "
        "ja3, ja4, ja4_ptype, ssh_action, ssh_username, sudo_username, sudo_target_user, "
        "sudo_command, sudo_tty, extra_json, ingested_at, "
        f"{dedup_key} AS dedup_key "
        f"FROM {table} "
        f"WHERE {where_sql} "
        "ORDER BY dedup_key, ingested_at DESC, timestamp DESC, pg_event_id DESC "
        "LIMIT 1 BY dedup_key"
        ")"
    )


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


def _ch_hunt_query(
    *,
    ch,
    page_size: int,
    cursor: str | None,
    agent_id: str | None,
    event_type: str | None,
    start_ts: datetime | None,
    end_ts: datetime | None,
    search: str | None,
    timeout_seconds: float | None = None,
) -> tuple[list[NetEventDB], str | None, bool]:
    where_sql, params = _ch_where(since=start_ts, agent_id=agent_id, event_type=event_type)
    if end_ts is not None:
        where_sql = f"{where_sql} AND timestamp <= {{end_ts:DateTime64(3)}}"
        params["end_ts"] = end_ts

    if cursor:
        c_ts, c_id = parse_cursor_ts_id(cursor)
        where_sql = (
            f"{where_sql} AND (timestamp < {{cursor_ts:DateTime64(3)}} OR "
            f"(timestamp = {{cursor_ts:DateTime64(3)}} AND pg_event_id < {{cursor_id:UInt64}}))"
        )
        params["cursor_ts"] = c_ts
        params["cursor_id"] = int(c_id)

    if search and search.strip():
        params["search"] = str(search).lower()
        where_sql = (
            f"{where_sql} AND ("
            "positionCaseInsensitiveUTF8(ifNull(agent_id, ''), {search:String}) > 0 OR "
            "positionCaseInsensitiveUTF8(ifNull(event_type, ''), {search:String}) > 0 OR "
            "positionCaseInsensitiveUTF8(ifNull(src_ip, ''), {search:String}) > 0 OR "
            "positionCaseInsensitiveUTF8(ifNull(dst_ip, ''), {search:String}) > 0 OR "
            "positionCaseInsensitiveUTF8(ifNull(proto, ''), {search:String}) > 0 OR "
            "positionCaseInsensitiveUTF8(ifNull(extra_json, ''), {search:String}) > 0)"
        )

    source_sql = _ch_deduped_events_source_sql(table=clickhouse_events_table_ref(), where_sql=where_sql)
    sql = (
        "SELECT pg_event_id, agent_id, event_type, schema_version, timestamp, "
        "src_ip, dst_ip, src_port, dst_port, proto, bytes, extra_json "
        f"FROM ({source_sql}) AS d "
        "ORDER BY timestamp DESC, pg_event_id DESC, ingested_at DESC "
        f"LIMIT {int(page_size) + 1}"
    )
    rows = _ch_query_dicts(ch, sql, params, ch_settings=_ch_timeout_settings(timeout_seconds))
    out: list[NetEventDB] = []
    for r in rows[: int(page_size) + 1]:
        ev = _ch_row_to_event(r)
        if ev is not None:
            out.append(ev)

    has_more = len(out) > int(page_size)
    items = out[: int(page_size)]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = make_cursor_ts_id(last.timestamp, int(last.id or 0))
    return items, next_cursor, has_more


def _es_hunt_query(
    *,
    es,
    page_size: int,
    cursor: str | None,
    agent_id: str | None,
    event_type: str | None,
    start_ts: datetime | None,
    end_ts: datetime | None,
    search: str | None,
    timeout_seconds: float | None = None,
) -> tuple[list[NetEventDB], str | None, bool]:
    es = _es_with_request_timeout(es, timeout_seconds)
    filters = _es_base_filters(since=start_ts, agent_id=agent_id, event_type=event_type)
    if end_ts is not None:
        filters.append({"range": {"timestamp": {"lte": end_ts.isoformat()}}})

    query: Dict[str, Any] = {"bool": {"filter": filters}}
    if search and search.strip():
        query["bool"]["must"] = [
            {
                "simple_query_string": {
                    "query": str(search),
                    "fields": list(HUNT_FREE_TEXT_FIELDS),
                    "default_operator": "and",
                    "lenient": True,
                }
            }
        ]

    body: Dict[str, Any] = {
        "size": int(page_size) + 1,
        "sort": [
            {"timestamp": {"order": "desc", "unmapped_type": "date"}},
            {"id": {"order": "desc", "unmapped_type": "long"}},
        ],
        "query": query,
    }
    if cursor:
        c_ts, c_id = parse_cursor_ts_id(cursor)
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
    items = [_hit_to_event(h) for h in page_hits]
    next_cursor = None
    if has_more and items:
        last_evt = items[-1]
        next_cursor = make_cursor_ts_id(last_evt.timestamp, last_evt.id)
    return items, next_cursor, has_more


def _es_kql_hunt_query(
    *,
    es: Any,
    compiled_query: Dict[str, Any],
    page_size: int,
    cursor: str | None,
    agent_id: str | None,
    event_type: str | None,
    start_ts: datetime | None,
    end_ts: datetime | None,
    timeout_seconds: float | None = None,
    terminate_after: int | None = None,
) -> tuple[list[NetEventDB], str | None, bool]:
    scoped = _es_with_request_timeout(es, timeout_seconds)
    filters = _es_base_filters(since=start_ts, agent_id=agent_id, event_type=event_type)
    if end_ts is not None:
        filters.append({"range": {"timestamp": {"lte": end_ts.isoformat()}}})

    body: Dict[str, Any] = {
        "size": int(page_size) + 1,
        "sort": [
            {"timestamp": {"order": "desc", "unmapped_type": "date"}},
            {"id": {"order": "desc", "unmapped_type": "long"}},
        ],
        "query": {"bool": {"filter": [*filters, compiled_query]}},
    }
    if timeout_seconds and float(timeout_seconds) > 0:
        body["timeout"] = f"{max(100, int(float(timeout_seconds) * 1000.0))}ms"
    if terminate_after and int(terminate_after) > 0:
        body["terminate_after"] = int(terminate_after)
    if cursor:
        c_ts, c_id = parse_cursor_ts_id(cursor)
        body["search_after"] = [c_ts.isoformat(), int(c_id)]

    try:
        res = scoped.search(
            index=_es_index_pattern(),
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
            track_total_hits=False,
        )
    except Exception as exc:
        raise translate_es_query_error(exc, dialect="kql") from exc
    if bool(res.get("timed_out")):
        raise HuntQueryError("KQL query timed out against Elasticsearch", reason="timeout")

    hits = (res.get("hits") or {}).get("hits") or []
    has_more = len(hits) > int(page_size)
    page_hits = hits[: int(page_size)]
    items = [_hit_to_event(h) for h in page_hits]
    next_cursor = None
    if has_more and items:
        last_evt = items[-1]
        next_cursor = make_cursor_ts_id(last_evt.timestamp, last_evt.id)
    return items, next_cursor, has_more


def _eql_delete_quietly(es: Any, search_id: str) -> None:
    try:
        es.eql.delete(id=search_id)
    except Exception:
        pass


def _es_eql_query(
    *,
    es: Any,
    query: str,
    filters: List[Dict[str, Any]],
    size: int,
    fetch_size: int,
    timeout_seconds: float,
) -> Dict[str, Any]:
    scoped = _es_with_request_timeout(es, float(timeout_seconds) + 1.0)
    wait = f"{max(100, int(float(timeout_seconds) * 1000.0))}ms"
    try:
        res = scoped.eql.search(
            index=_es_index_pattern(),
            query=query,
            filter={"bool": {"filter": filters}},
            size=int(size),
            fetch_size=int(fetch_size),
            timestamp_field="timestamp",
            event_category_field="event_type",
            wait_for_completion_timeout=wait,
            keep_on_completion=False,
            allow_no_indices=True,
            ignore_unavailable=True,
        )
    except Exception as exc:
        raise translate_es_query_error(exc, dialect="eql") from exc

    data: Dict[str, Any] = res if isinstance(res, dict) else dict(res)
    search_id = data.get("id")
    if search_id and (data.get("is_running") or data.get("is_partial")):
        _eql_delete_quietly(es, str(search_id))
    if eql_response_is_incomplete(data):
        raise HuntQueryError("EQL query timed out against Elasticsearch", reason="timeout")
    return data


def _pg_hunt_query(
    db: Session,
    *,
    page_size: int,
    cursor: str | None,
    agent_id: str | None,
    event_type: str | None,
    start_ts: datetime | None,
    end_ts: datetime | None,
    tokens: list[str],
    timeout_seconds: float | None = None,
) -> tuple[list[NetEventDB], str | None, bool]:
    _pg_apply_statement_timeout(db, timeout_seconds)
    stmt = select(NetEventModel).order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())

    if agent_id:
        stmt = stmt.where(NetEventModel.agent_id == agent_id)
    if event_type:
        stmt = stmt.where(NetEventModel.event_type == event_type)
    if start_ts is not None:
        stmt = stmt.where(NetEventModel.timestamp >= start_ts)
    if end_ts is not None:
        stmt = stmt.where(NetEventModel.timestamp <= end_ts)

    if tokens:
        for tok in tokens:
            like = f"%{tok}%"
            stmt = stmt.where(
                or_(
                    cast(NetEventModel.id, String).ilike(like),
                    NetEventModel.agent_id.ilike(like),
                    NetEventModel.event_type.ilike(like),
                    cast(NetEventModel.src_ip, String).ilike(like),
                    cast(NetEventModel.dst_ip, String).ilike(like),
                    cast(NetEventModel.src_port, String).ilike(like),
                    cast(NetEventModel.dst_port, String).ilike(like),
                    cast(NetEventModel.proto, String).ilike(like),
                    cast(NetEventModel.extra, String).ilike(like),
                )
            )

    if cursor:
        c_ts, c_id = parse_cursor_ts_id(cursor)
        stmt = stmt.where(
            or_(
                NetEventModel.timestamp < c_ts,
                and_(NetEventModel.timestamp == c_ts, NetEventModel.id < c_id),
            )
        )

    requested = max(1, int(page_size))
    target = requested + 1
    # Read a bounded cushion to absorb occasional malformed legacy rows.
    scan_limit = min(max(target + 32, target * 2), 512)

    stmt = stmt.with_only_columns(
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
    rows = repository.run(db, stmt.limit(scan_limit)).mappings().all()

    items_plus_one: list[NetEventDB] = []
    skipped_rows = 0
    for row in rows:
        item = _row_to_event_safe(dict(row))
        if item is None:
            skipped_rows += 1
            continue
        items_plus_one.append(item)
        if len(items_plus_one) >= target:
            break

    if skipped_rows:
        log_event(
            logger,
            "warning",
            "events_hunt_pg_rows_skipped",
            skipped_rows=skipped_rows,
            fetched_rows=len(rows),
            page_size=requested,
        )

    has_more = len(items_plus_one) > requested
    items = items_plus_one[:requested]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = make_cursor_ts_id(last.timestamp, last.id)
    return items, next_cursor, has_more


def _pg_has_newer_event(
    db: Session,
    *,
    latest_ts: datetime,
    agent_id: str | None = None,
    event_type: str | None = None,
    margin_s: int | None = None,
) -> bool:
    try:
        stmt = select(func.max(NetEventModel.timestamp))
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        if event_type:
            stmt = stmt.where(NetEventModel.event_type == event_type)
        pg_ts = repository.run(db, stmt).scalar()
        if not isinstance(pg_ts, datetime):
            return False
        if pg_ts.tzinfo is None:
            pg_ts = pg_ts.replace(tzinfo=timezone.utc)
        ref = latest_ts if latest_ts.tzinfo else latest_ts.replace(tzinfo=timezone.utc)
        threshold = int(margin_s or getattr(settings, "SEAGULL_EVENTS_ES_STALE_MARGIN_SECONDS", 60) or 60)
        return (pg_ts - ref).total_seconds() > float(max(1, threshold))
    except Exception:
        return False


def _pg_has_protocol_metadata(db: Session, *, since: datetime, agent_id: str | None = None) -> bool:
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
        return int(repository.run(db, stmt).scalar() or 0) > 0
    except Exception:
        return False


def _pg_protocol_field_expr(kind: str):
    field_exprs = {
        "app_proto": func.coalesce(NetEventModel.app_proto, NetEventModel.extra["app_proto"].astext),
        "app_proto_reason": func.coalesce(NetEventModel.app_proto_reason, NetEventModel.extra["app_proto_reason"].astext),
        "app_proto_conf_band": func.coalesce(NetEventModel.app_proto_conf_band, NetEventModel.extra["app_proto_conf_band"].astext),
        "dns_qname": func.coalesce(NetEventModel.dns_qname, NetEventModel.extra["dns_qname"].astext),
        "http_host": func.coalesce(NetEventModel.http_host, NetEventModel.extra["http_host"].astext),
        "http_method": func.coalesce(NetEventModel.http_method, NetEventModel.extra["http_method"].astext),
        "tls_sni": func.coalesce(NetEventModel.tls_sni, NetEventModel.extra["tls_sni"].astext),
        "tls_alpn_first": func.coalesce(NetEventModel.tls_alpn_first, NetEventModel.extra["tls_alpn_first"].astext),
        "ja3": func.coalesce(NetEventModel.ja3, NetEventModel.extra["ja3"].astext),
        "ja4": func.coalesce(NetEventModel.ja4, NetEventModel.extra["ja4"].astext),
        "ja4_ptype": func.coalesce(NetEventModel.ja4_ptype, NetEventModel.extra["ja4_ptype"].astext, "t"),
    }
    return field_exprs.get(kind)


def _pg_has_protocol_field(db: Session, *, kind: str, since: datetime, agent_id: str | None = None) -> bool:
    expr = _pg_protocol_field_expr(kind)
    if expr is None:
        return False
    try:
        stmt = select(func.count()).where(
            NetEventModel.timestamp >= since,
            func.nullif(expr, "").is_not(None),
        )
        if agent_id:
            stmt = stmt.where(NetEventModel.agent_id == agent_id)
        return int(repository.run(db, stmt).scalar() or 0) > 0
    except Exception:
        return False


def _missing_protocol_summary_field(
    db: Session,
    *,
    since: datetime,
    agent_id: str | None,
    field_presence: dict[str, bool],
) -> str | None:
    for kind, present in field_presence.items():
        if present:
            continue
        if _pg_has_protocol_field(db, kind=kind, since=since, agent_id=agent_id):
            return kind
    return None


def _pg_rollup_l4_snapshot(
    db: Session,
    *,
    since_ts: datetime,
    limit: int,
    agent_id: str | None,
) -> tuple[int, list[ProtoCount], list[ProtoCount]]:
    total_stmt = select(func.coalesce(func.sum(NetEventRollup1sModel.count), 0)).where(NetEventRollup1sModel.bucket_ts >= since_ts)
    if agent_id:
        total_stmt = total_stmt.where(NetEventRollup1sModel.agent_id == agent_id)
    total_events = int(repository.run(db, total_stmt).scalar() or 0)

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
    transport_rows = repository.run(db, transport_stmt).all()
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
    dst_rows = repository.run(db, dst_stmt).all()
    top_dst_ports = [ProtoCount(key=str(r.k), count=int(r.c or 0)) for r in dst_rows if r.k is not None]

    return total_events, transport_protocols, top_dst_ports


def _next_cursor_for_rows(rows: List[NetEventDB], *, limit: int) -> tuple[str | None, bool]:
    if len(rows) < max(1, int(limit)):
        return None, False
    tail = rows[-1]
    return make_cursor_ts_id(tail.timestamp, int(tail.id or 0)), True


def list_rollups_1s(
    db: Session,
    *,
    minutes: int = 60,
    limit: int = 500,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
) -> List[NetEventRollup1s]:
    since = datetime.now(timezone.utc) - timedelta(minutes=int(minutes))

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
    rows = repository.run(db, stmt).mappings().all()

    return [NetEventRollup1s(**dict(row)) for row in rows]


def get_port_stats(
    db: Session,
    *,
    limit: int = 20,
) -> List[Dict[str, Any]]:
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
                return [
                    {"port": int(row.get("port")), "count": int(row.get("count") or 0)}
                    for row in rows
                    if row.get("port") is not None
                ]
        except Exception as exc:
            log_event(logger, "warning", "events_ports_clickhouse_error", error_type=type(exc).__name__)

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
            return [{"port": bucket.get("key"), "count": bucket.get("doc_count", 0)} for bucket in buckets]
        except Exception as exc:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(exc).__name__}") from None

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

    rows = repository.run(db, stmt).all()
    return [{"port": row.port, "count": row.count} for row in rows]


def get_protocol_intel_samples(
    db: Session,
    *,
    kind: str,
    value: str,
    since_minutes: int = 60 * 12,
    limit: int = 50,
    agent_id: Optional[str] = None,
) -> List[NetEventDB]:
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
        except Exception as exc:
            log_event(
                logger,
                "warning",
                "protocol_intel_samples_clickhouse_error",
                kind=kind,
                error_type=type(exc).__name__,
                error=str(exc)[:300],
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
            for hit in hits:
                try:
                    item = _hit_to_event(hit)
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
        except Exception as exc:
            log_event(
                logger,
                "warning",
                "protocol_intel_samples_es_error",
                kind=kind,
                error_type=type(exc).__name__,
                error=str(exc)[:300],
            )
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
                for hit in hits2:
                    try:
                        item = _hit_to_event(hit)
                    except Exception:
                        continue
                    item.extra = _strip_large_extra(item.extra)
                    out2.append(item)
                out2.sort(key=lambda item: (item.timestamp, item.id), reverse=True)
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
            except Exception as fallback_exc:
                log_event(
                    logger,
                    "error",
                    "protocol_intel_samples_es_fallback_error",
                    kind=kind,
                    error_type=type(fallback_exc).__name__,
                    error=str(fallback_exc)[:300],
                )
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(exc).__name__}") from None

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

    conds = [
        NetEventModel.timestamp >= since_ts,
        expr == value_norm,
    ]
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
    try:
        rows = repository.run(db, stmt).mappings().all()
        out: list[NetEventDB] = []
        for row in rows:
            item = _row_to_event_safe(dict(row))
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
    except Exception as exc:
        log_event(
            logger,
            "error",
            "protocol_intel_samples_pg_error",
            kind=kind,
            error_type=type(exc).__name__,
            error=str(exc)[:300],
        )
        return []
