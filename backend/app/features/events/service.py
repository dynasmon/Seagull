from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.clickhouse import clickhouse_events_1m_table_ref, clickhouse_events_table_ref
from app.core.config import settings
from app.core.es import search_backend_mode
from app.core.observability import incr_counter, log_event, observe_hist
from app.core.recent_feed import fetch_recent_events as fetch_recent_feed_events, recent_feed_health
from app.features.events import repository
from app.features.events.domain import cache as event_cache
from app.features.events.domain import live_feed as event_live_feed
from app.features.events.domain import normalizers as event_normalizers
from app.features.events.domain import queries as event_queries
from app.features.events.domain import summaries as event_summaries
from app.features.events.domain.filters import _search_tokens
from app.features.events.schemas import (
    DdosLiveSnapshotResponse,
    EventHuntResponse,
    EventStreamSnapshotResponse,
    NetEventDB,
    NetEventRollup1s,
    ProtocolIntelSummaryResponse,
    ProtoCount,
    ProtoDnsQueryStat,
    ProtoJa4Stat,
    QueryProvenanceMeta,
    QuerySource,
    SshAuthEvent,
    SshIpStat,
    SshLoginEvent,
    SshSummaryResponse,
    SshUserStat,
    SudoEventSummary,
)
from app.shared.schemas import CursorPage

logger = logging.getLogger("seagull.api.events")

_cache_get_json = event_cache._cache_get_json
_cache_set_json = event_cache._cache_set_json
_cache_delete_prefixes = event_cache._cache_delete_prefixes
invalidate_live_event_summary_caches = event_cache.invalidate_live_event_summary_caches

_coerce_utc_iso = event_normalizers._coerce_utc_iso
_now_utc = event_normalizers._now_utc
_freshness_seconds = event_normalizers._freshness_seconds
_meta = event_normalizers._meta
_parse_iso_dt = event_normalizers._parse_iso_dt
_parse_iso_dt_or_none = event_normalizers._parse_iso_dt_or_none
_strip_large_extra = event_normalizers._strip_large_extra
_merge_protocol_fields_into_extra = event_normalizers._merge_protocol_fields_into_extra
_row_to_event_safe = event_normalizers._row_to_event_safe
_event_obj_to_event_safe = event_normalizers._event_obj_to_event_safe
_hit_to_event = event_normalizers._hit_to_event
_ch_row_to_event = event_normalizers._ch_row_to_event
_feed_row_to_event = event_normalizers._feed_row_to_event
_guess_app_proto_from_port = event_normalizers._guess_app_proto_from_port
_guess_app_protocols_from_port_counts = event_normalizers._guess_app_protocols_from_port_counts

_es_base_filters = event_queries._es_base_filters
_ch_where = event_queries._ch_where
_next_cursor_for_rows = event_queries._next_cursor_for_rows

_merge_recent_events = event_live_feed._merge_recent_events
_ddos_events_only = event_live_feed._ddos_events_only
_build_recent_feed_meta = event_live_feed._build_recent_feed_meta
_empty_ddos_summary = event_live_feed._empty_ddos_summary
_summarize_ddos_rows = event_live_feed._summarize_ddos_rows


def _bind_query_module() -> None:
    event_queries.repository = repository
    event_queries.logger = logger
    event_queries.log_event = log_event
    event_queries.search_backend_mode = search_backend_mode
    event_queries.clickhouse_events_table_ref = clickhouse_events_table_ref
    event_queries.clickhouse_events_1m_table_ref = clickhouse_events_1m_table_ref


def _bind_live_feed_module() -> None:
    event_live_feed.repository = repository
    event_live_feed.logger = logger
    event_live_feed.log_event = log_event
    event_live_feed.fetch_recent_feed_events = fetch_recent_feed_events
    event_live_feed.recent_feed_health = recent_feed_health
    event_live_feed.clickhouse_events_table_ref = clickhouse_events_table_ref
    event_live_feed._ch_client_or_none = _ch_client_or_none
    event_live_feed._ch_deduped_events_source_sql = _ch_deduped_events_source_sql
    event_live_feed._ch_query_dicts = _ch_query_dicts
    event_live_feed._ch_row_to_event = _ch_row_to_event
    event_live_feed._ch_where = _ch_where
    event_live_feed._es_base_filters = _es_base_filters
    event_live_feed._es_client_or_none = _es_client_or_none
    event_live_feed._es_failover_allowed = _es_failover_allowed
    event_live_feed._es_index_pattern = _es_index_pattern
    event_live_feed._event_obj_to_event_safe = _event_obj_to_event_safe
    event_live_feed._feed_row_to_event = _feed_row_to_event
    event_live_feed._freshness_seconds = _freshness_seconds
    event_live_feed._hit_to_event = _hit_to_event
    event_live_feed._meta = _meta
    event_live_feed._pg_has_newer_event = _pg_has_newer_event


def _bind_summary_module() -> None:
    event_summaries.repository = repository
    event_summaries.logger = logger
    event_summaries.incr_counter = incr_counter
    event_summaries.log_event = log_event
    event_summaries.observe_hist = observe_hist
    event_summaries.search_backend_mode = search_backend_mode
    event_summaries.clickhouse_events_table_ref = clickhouse_events_table_ref
    event_summaries._cache_get_json = _cache_get_json
    event_summaries._cache_set_json = _cache_set_json
    event_summaries._ch_client_or_none = _ch_client_or_none
    event_summaries._ch_deduped_events_source_sql = _ch_deduped_events_source_sql
    event_summaries._ch_query_dicts = _ch_query_dicts
    event_summaries._ch_top_counts = _ch_top_counts
    event_summaries._ch_where = _ch_where
    event_summaries._es_base_filters = _es_base_filters
    event_summaries._es_client_or_none = _es_client_or_none
    event_summaries._es_failover_allowed = _es_failover_allowed
    event_summaries._es_index_pattern = _es_index_pattern
    event_summaries._freshness_seconds = _freshness_seconds
    event_summaries._guess_app_protocols_from_port_counts = _guess_app_protocols_from_port_counts
    event_summaries._meta = _meta
    event_summaries._missing_protocol_summary_field = _missing_protocol_summary_field
    event_summaries._now_utc = _now_utc
    event_summaries._parse_iso_dt = _parse_iso_dt
    event_summaries._parse_iso_dt_or_none = _parse_iso_dt_or_none
    event_summaries._pg_has_newer_event = _pg_has_newer_event
    event_summaries._pg_has_protocol_metadata = _pg_has_protocol_metadata
    event_summaries._pg_rollup_l4_snapshot = _pg_rollup_l4_snapshot


def _es_index_pattern() -> str:
    _bind_query_module()
    return event_queries._es_index_pattern()


def _ch_client_or_none() -> Any | None:
    _bind_query_module()
    return event_queries._ch_client_or_none()


def _ch_query_dicts(ch: Any, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    _bind_query_module()
    return event_queries._ch_query_dicts(ch, sql, params)


def _ch_dedup_key_expr(alias: str = "") -> str:
    _bind_query_module()
    return event_queries._ch_dedup_key_expr(alias)


def _ch_deduped_events_source_sql(*, table: str, where_sql: str) -> str:
    _bind_query_module()
    return event_queries._ch_deduped_events_source_sql(table=table, where_sql=where_sql)


def _ch_top_counts(
    ch: Any,
    *,
    source_sql: str,
    params: Optional[Dict[str, Any]],
    key_expr: str,
    limit: int,
    nonempty: bool = True,
) -> List[ProtoCount]:
    _bind_query_module()
    return event_queries._ch_top_counts(
        ch,
        source_sql=source_sql,
        params=params,
        key_expr=key_expr,
        limit=limit,
        nonempty=nonempty,
    )


def _es_client_or_none() -> Any | None:
    _bind_query_module()
    return event_queries._es_client_or_none()


def _es_failover_allowed() -> bool:
    _bind_query_module()
    return event_queries._es_failover_allowed()


def _es_terms_top(
    es,
    *,
    field: str,
    size: int,
    base_filters: List[Dict[str, Any]],
) -> List[ProtoCount]:
    _bind_query_module()
    return event_queries._es_terms_top(es, field=field, size=size, base_filters=base_filters)


def _pg_has_newer_event(
    db: Session,
    *,
    latest_ts: datetime,
    agent_id: str | None = None,
    event_type: str | None = None,
    margin_s: int | None = None,
) -> bool:
    _bind_query_module()
    return event_queries._pg_has_newer_event(
        db,
        latest_ts=latest_ts,
        agent_id=agent_id,
        event_type=event_type,
        margin_s=margin_s,
    )


def _pg_has_protocol_metadata(db: Session, *, since: datetime, agent_id: str | None = None) -> bool:
    _bind_query_module()
    return event_queries._pg_has_protocol_metadata(db, since=since, agent_id=agent_id)


def _pg_protocol_field_expr(kind: str):
    _bind_query_module()
    return event_queries._pg_protocol_field_expr(kind)


def _pg_has_protocol_field(db: Session, *, kind: str, since: datetime, agent_id: str | None = None) -> bool:
    _bind_query_module()
    return event_queries._pg_has_protocol_field(db, kind=kind, since=since, agent_id=agent_id)


def _missing_protocol_summary_field(
    db: Session,
    *,
    since: datetime,
    agent_id: str | None,
    field_presence: dict[str, bool],
) -> str | None:
    _bind_query_module()
    return event_queries._missing_protocol_summary_field(
        db,
        since=since,
        agent_id=agent_id,
        field_presence=field_presence,
    )


def _pg_rollup_l4_snapshot(
    db: Session,
    *,
    since_ts: datetime,
    limit: int,
    agent_id: str | None,
) -> tuple[int, list[ProtoCount], list[ProtoCount]]:
    _bind_query_module()
    return event_queries._pg_rollup_l4_snapshot(db, since_ts=since_ts, limit=limit, agent_id=agent_id)


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
) -> tuple[list[NetEventDB], str | None, bool]:
    _bind_query_module()
    return event_queries._pg_hunt_query(
        db,
        page_size=page_size,
        cursor=cursor,
        agent_id=agent_id,
        event_type=event_type,
        start_ts=start_ts,
        end_ts=end_ts,
        tokens=tokens,
    )


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
) -> tuple[list[NetEventDB], str | None, bool]:
    _bind_query_module()
    return event_queries._es_hunt_query(
        es=es,
        page_size=page_size,
        cursor=cursor,
        agent_id=agent_id,
        event_type=event_type,
        start_ts=start_ts,
        end_ts=end_ts,
        search=search,
    )


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
) -> tuple[list[NetEventDB], str | None, bool]:
    _bind_query_module()
    return event_queries._ch_hunt_query(
        ch=ch,
        page_size=page_size,
        cursor=cursor,
        agent_id=agent_id,
        event_type=event_type,
        start_ts=start_ts,
        end_ts=end_ts,
        search=search,
    )


def _select_hunt_chain(*, has_search: bool, window_minutes: int | None) -> list[str]:
    if has_search:
        return ["elasticsearch", "postgres"]

    ch_min_minutes = max(15, int(getattr(settings, "SEAGULL_EVENTS_HUNT_CLICKHOUSE_MINUTES", 240) or 240))
    if window_minutes is not None and int(window_minutes) >= int(ch_min_minutes):
        chain = ["clickhouse", "postgres"]
    else:
        chain = ["postgres", "clickhouse"]

    if search_backend_mode() != "postgres":
        chain.append("elasticsearch")

    out: list[str] = []
    for source in chain:
        if source not in out:
            out.append(source)
    return out


def hunt_events(
    db: Session,
    *,
    page_size: int = 50,
    cursor: Optional[str] = None,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    since_minutes: Optional[int] = None,
    start_ts_iso: Optional[str] = None,
    end_ts_iso: Optional[str] = None,
    search: Optional[str] = None,
) -> EventHuntResponse:
    started = time.perf_counter()
    now = _now_utc()
    size = max(1, min(int(page_size), 1000))

    start_ts = _coerce_utc_iso(start_ts_iso)
    end_ts = _coerce_utc_iso(end_ts_iso)
    if since_minutes is not None and start_ts is not None:
        raise HTTPException(status_code=422, detail="Use either since_minutes or start_ts, not both")
    if since_minutes is not None and end_ts is not None and start_ts is None:
        start_ts = end_ts - timedelta(minutes=max(1, int(since_minutes)))
    elif since_minutes is not None and start_ts is None:
        start_ts = now - timedelta(minutes=max(1, int(since_minutes)))
    if end_ts is None:
        end_ts = now
    if start_ts is not None and end_ts is not None and start_ts > end_ts:
        raise HTTPException(status_code=422, detail="start_ts must be less than or equal to end_ts")

    tokens = _search_tokens(search)
    has_search = bool(tokens)
    if search is not None and not str(search).strip():
        raise HTTPException(status_code=422, detail="search must contain non-whitespace characters")

    window_minutes = None
    if start_ts is not None and end_ts is not None:
        window_minutes = int(max(1, (end_ts - start_ts).total_seconds() // 60))
    elif since_minutes is not None:
        window_minutes = int(max(1, int(since_minutes)))

    chain = _select_hunt_chain(has_search=has_search, window_minutes=window_minutes)
    attempted: list[str] = []
    degraded_reason: str | None = None
    items: list[NetEventDB] = []
    next_cursor: str | None = None
    has_more = False
    succeeded = False
    selected_source: QuerySource = "postgres"

    for candidate in chain:
        attempted.append(candidate)
        try:
            if candidate == "elasticsearch":
                es = _es_client_or_none()
                if es is None:
                    raise LookupError("elasticsearch_unavailable")
                items, next_cursor, has_more = _es_hunt_query(
                    es=es,
                    page_size=size,
                    cursor=cursor,
                    agent_id=agent_id,
                    event_type=event_type,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    search=search,
                )
                if items and _es_failover_allowed():
                    if _pg_has_newer_event(db, latest_ts=items[0].timestamp, agent_id=agent_id, event_type=event_type):
                        raise LookupError("elasticsearch_stale")
                selected_source = "elasticsearch"
                succeeded = True
                break

            if candidate == "clickhouse":
                ch = _ch_client_or_none()
                if ch is None:
                    raise LookupError("clickhouse_unavailable")
                items, next_cursor, has_more = _ch_hunt_query(
                    ch=ch,
                    page_size=size,
                    cursor=cursor,
                    agent_id=agent_id,
                    event_type=event_type,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    search=search,
                )
                if items and _pg_has_newer_event(
                    db,
                    latest_ts=items[0].timestamp,
                    agent_id=agent_id,
                    event_type=event_type,
                ):
                    raise LookupError("clickhouse_stale")
                selected_source = "clickhouse"
                succeeded = True
                break

            items, next_cursor, has_more = _pg_hunt_query(
                db,
                page_size=size,
                cursor=cursor,
                agent_id=agent_id,
                event_type=event_type,
                start_ts=start_ts,
                end_ts=end_ts,
                tokens=tokens,
            )
            selected_source = "postgres"
            succeeded = True
            break
        except HTTPException:
            raise
        except Exception as exc:
            reason = type(exc).__name__
            if isinstance(exc, LookupError):
                reason = str(exc)
            degraded_reason = f"{candidate}_fallback:{reason}"[:200]

    if not attempted:
        attempted = ["postgres"]
    if not succeeded:
        raise HTTPException(status_code=503, detail="No analytics backend is currently available for event hunt")

    meta = _meta(
        source=selected_source,
        fallback_chain=attempted,
        degraded_reason=degraded_reason,
        source_freshness_seconds=_freshness_seconds(now, items[0].timestamp if items else None),
        query_latency_ms=(time.perf_counter() - started) * 1000.0,
        cache_hit=False,
        approximate=False,
        query_window_start=start_ts,
        query_window_end=end_ts,
    )
    return EventHuntResponse(items=items, next_cursor=next_cursor, has_more=has_more, meta=meta)


def list_events(
    db: Session,
    *,
    page_size: int = 50,
    cursor: Optional[str] = None,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
) -> CursorPage[NetEventDB]:
    out = hunt_events(
        db,
        page_size=page_size,
        cursor=cursor,
        agent_id=agent_id,
        event_type=event_type,
    )
    return CursorPage(items=out.items, next_cursor=out.next_cursor, has_more=out.has_more)


def get_recent_events(
    db: Session,
    *,
    limit: int = 50,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    since_minutes: Optional[int] = None,
) -> List[NetEventDB]:
    _bind_live_feed_module()
    return event_live_feed.get_recent_events(
        db,
        limit=limit,
        agent_id=agent_id,
        event_type=event_type,
        since_minutes=since_minutes,
    )


def get_recent_events_view(
    db: Session,
    *,
    limit: int = 50,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    search: Optional[str] = None,
    since_minutes: Optional[int] = None,
    window_minutes: Optional[int] = None,
) -> List[NetEventDB]:
    _bind_live_feed_module()
    return event_live_feed.get_recent_events_view(
        db,
        limit=limit,
        agent_id=agent_id,
        event_type=event_type,
        search=search,
        since_minutes=since_minutes,
        window_minutes=window_minutes,
    )


def get_event_stream_snapshot(
    db: Session,
    *,
    limit: int = 200,
    agent_id: str | None = None,
    event_type: str | None = None,
    search: str | None = None,
    since_minutes: int | None = None,
) -> EventStreamSnapshotResponse:
    _bind_live_feed_module()
    return event_live_feed.get_event_stream_snapshot(
        db,
        limit=limit,
        agent_id=agent_id,
        event_type=event_type,
        search=search,
        since_minutes=since_minutes,
    )


def get_ddos_live_snapshot(
    db: Session,
    *,
    limit: int = 200,
    agent_id: str | None = None,
    since_minutes: int = 60 * 12,
) -> DdosLiveSnapshotResponse:
    _bind_live_feed_module()
    return event_live_feed.get_ddos_live_snapshot(
        db,
        limit=limit,
        agent_id=agent_id,
        since_minutes=since_minutes,
    )


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
    _bind_query_module()
    return event_queries.list_rollups_1s(
        db,
        minutes=minutes,
        limit=limit,
        agent_id=agent_id,
        event_type=event_type,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )


def get_port_stats(
    db: Session,
    *,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    _bind_query_module()
    return event_queries.get_port_stats(db, limit=limit)


def get_ssh_summary(
    db: Session,
    *,
    since_minutes: int = 60 * 24,
    limit: int = 50,
    agent_id: Optional[str] = None,
) -> SshSummaryResponse:
    _bind_summary_module()
    return event_summaries.get_ssh_summary(
        db,
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )


def get_protocol_intel_summary(
    db: Session,
    *,
    since_minutes: int = 60 * 12,
    limit: int = 25,
    agent_id: Optional[str] = None,
) -> ProtocolIntelSummaryResponse:
    _bind_summary_module()
    return event_summaries.get_protocol_intel_summary(
        db,
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )


def get_protocol_intel_samples(
    db: Session,
    *,
    kind: str,
    value: str,
    since_minutes: int = 60 * 12,
    limit: int = 50,
    agent_id: Optional[str] = None,
) -> List[NetEventDB]:
    _bind_query_module()
    return event_queries.get_protocol_intel_samples(
        db,
        kind=kind,
        value=value,
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )
