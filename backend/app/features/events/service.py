from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.integrations.clickhouse import (
    clickhouse_events_1m_table_ref,
    clickhouse_events_table_ref,
    clickhouse_proto_intel_overview_table_ref,
    clickhouse_proto_intel_table_ref,
)
from app.core.integrations.es import search_backend_mode
from app.core.observability import incr_counter, log_event, observe_hist
from app.features.events import repository
from app.features.events.domain import cache as event_cache
from app.features.events.domain import live_feed as event_live_feed
from app.features.events.domain import normalizers as event_normalizers
from app.features.events.domain import queries as event_queries
from app.features.events.domain import summaries as event_summaries
from app.features.events.domain.eql import eql_sequences_from_response, normalize_eql_query
from app.features.events.domain.field_catalog import (
    HUNT_FREE_TEXT_FIELDS,
    hunt_field_listing,
    hunt_field_types,
)
from app.features.events.domain.filters import _search_tokens
from app.features.events.domain.hunt_dialects import (
    EQL_ENDPOINT_HINT,
    HuntDialect,
    HuntQueryError,
    resolve_hunt_dialect,
)
from app.features.events.domain.kql import compile_kql
from app.features.events.domain.routing import (
    BackendCircuitBreaker,
    QuerySignals,
    RouteDecision,
    classify_backend_failure,
    decide_backend_chain,
    failure_counts_toward_breaker,
    is_wide_window,
    route_trusts_es,
)
from app.features.events.recent_feed import fetch_recent_events as fetch_recent_feed_events
from app.features.events.recent_feed import recent_feed_health
from app.features.events.schemas import (
    DdosLiveSnapshotResponse,
    EqlHuntResponse,
    EventHuntResponse,
    EventStreamSnapshotResponse,
    HuntFieldSpec,
    HuntFieldsResponse,
    HuntRouteCircuitState,
    HuntRouteExplainResponse,
    HuntRouteSignals,
    NetEventDB,
    NetEventRollup1s,
    ProtocolIntelSummaryResponse,
    ProtoCount,
    QuerySource,
    SshSummaryResponse,
)
from app.shared.analytics import (
    AnalyticalReadModel,
    WarmSpec,
    register_read_model,
    register_warm_set,
    serve_read_model,
)
from app.shared.indexing.watermark import (
    clickhouse_watermark_lag_seconds,
    read_proto_intel_materialization_floor,
)

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
    event_summaries.clickhouse_proto_intel_table_ref = clickhouse_proto_intel_table_ref
    event_summaries.clickhouse_proto_intel_overview_table_ref = clickhouse_proto_intel_overview_table_ref
    event_summaries.clickhouse_watermark_lag_seconds = clickhouse_watermark_lag_seconds
    event_summaries.read_proto_intel_materialization_floor = read_proto_intel_materialization_floor
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
    timeout_seconds: float | None = None,
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
        timeout_seconds=timeout_seconds,
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
    timeout_seconds: float | None = None,
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
        timeout_seconds=timeout_seconds,
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
    timeout_seconds: float | None = None,
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
        timeout_seconds=timeout_seconds,
    )


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
    _bind_query_module()
    return event_queries._es_kql_hunt_query(
        es=es,
        compiled_query=compiled_query,
        page_size=page_size,
        cursor=cursor,
        agent_id=agent_id,
        event_type=event_type,
        start_ts=start_ts,
        end_ts=end_ts,
        timeout_seconds=timeout_seconds,
        terminate_after=terminate_after,
    )


def _es_eql_query(
    *,
    es: Any,
    query: str,
    filters: List[Dict[str, Any]],
    size: int,
    fetch_size: int,
    timeout_seconds: float,
) -> Dict[str, Any]:
    _bind_query_module()
    return event_queries._es_eql_query(
        es=es,
        query=query,
        filters=filters,
        size=size,
        fetch_size=fetch_size,
        timeout_seconds=timeout_seconds,
    )


def _build_hunt_breaker() -> BackendCircuitBreaker:
    return BackendCircuitBreaker(
        failure_threshold=int(getattr(settings, "SEAGULL_ROUTE_BREAKER_FAILURE_THRESHOLD", 5) or 5),
        window_seconds=float(getattr(settings, "SEAGULL_ROUTE_BREAKER_WINDOW_SECONDS", 30.0) or 30.0),
        cooldown_seconds=float(getattr(settings, "SEAGULL_ROUTE_BREAKER_COOLDOWN_SECONDS", 30.0) or 30.0),
    )


_hunt_breaker = _build_hunt_breaker()

_WILDCARD_MARKERS = ("*", "?")


def _route_decision(signals: QuerySignals) -> RouteDecision:
    return decide_backend_chain(
        signals,
        es_enabled=search_backend_mode() != "postgres",
        wide_window_minutes=int(getattr(settings, "SEAGULL_EVENTS_HUNT_CLICKHOUSE_MINUTES", 240) or 240),
        many_clauses_threshold=int(getattr(settings, "SEAGULL_ROUTE_MANY_CLAUSES_THRESHOLD", 5) or 5),
    )


def _hunt_backend_timeout_seconds(backend: str, signals: QuerySignals) -> float:
    if backend == "elasticsearch":
        if signals.dialect == "kql":
            return float(getattr(settings, "SEAGULL_HUNT_KQL_TIMEOUT_SECONDS", 3.0) or 3.0)
        if signals.has_search or signals.has_wildcard:
            return float(getattr(settings, "SEAGULL_ROUTE_ES_SEARCH_TIMEOUT_SECONDS", 2.0) or 2.0)
        return float(getattr(settings, "SEAGULL_ROUTE_ES_TERM_TIMEOUT_SECONDS", 0.5) or 0.5)
    if backend == "clickhouse":
        scan_shaped = (
            signals.aggregate
            or signals.has_search
            or signals.has_wildcard
            or is_wide_window(
                signals,
                wide_window_minutes=int(getattr(settings, "SEAGULL_EVENTS_HUNT_CLICKHOUSE_MINUTES", 240) or 240),
            )
        )
        if scan_shaped:
            return float(getattr(settings, "SEAGULL_ROUTE_CH_AGGREGATE_TIMEOUT_SECONDS", 3.0) or 3.0)
        return float(getattr(settings, "SEAGULL_ROUTE_CH_KEYED_TIMEOUT_SECONDS", 0.5) or 0.5)
    return float(getattr(settings, "SEAGULL_ROUTE_PG_TIMEOUT_SECONDS", 0.5) or 0.5)


def _resolve_hunt_window(
    *,
    now: datetime,
    since_minutes: int | None,
    start_ts_iso: str | None,
    end_ts_iso: str | None,
) -> tuple[datetime | None, datetime, int | None]:
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
    if start_ts is not None and start_ts > end_ts:
        raise HTTPException(status_code=422, detail="start_ts must be less than or equal to end_ts")

    window_minutes: int | None = None
    if start_ts is not None:
        window_minutes = int(max(1, (end_ts - start_ts).total_seconds() // 60))
    elif since_minutes is not None:
        window_minutes = int(max(1, int(since_minutes)))
    return start_ts, end_ts, window_minutes


def _build_hunt_signals(
    *,
    search: str | None,
    tokens: list[str],
    agent_id: str | None,
    event_type: str | None,
    start_ts: datetime | None,
    window_minutes: int | None,
    aggregate: bool = False,
    transactional_join: bool = False,
) -> QuerySignals:
    raw_search = str(search or "")
    filter_clauses = len(tokens)
    if agent_id:
        filter_clauses += 1
    if event_type:
        filter_clauses += 1
    if start_ts is not None:
        filter_clauses += 1
    return QuerySignals(
        has_search=bool(tokens),
        has_wildcard=any(marker in raw_search for marker in _WILDCARD_MARKERS),
        filter_clauses=filter_clauses,
        window_minutes=window_minutes,
        aggregate=bool(aggregate),
        transactional_join=bool(transactional_join),
    )


_HUNT_QUERY_ERROR_STATUS: Dict[str, int] = {
    "timeout": 504,
    "es_unavailable": 503,
    "circuit_open": 503,
}


def _hunt_query_http_error(error: HuntQueryError, dialect: str) -> HTTPException:
    incr_counter("hunt_query_error_total", dialect=dialect, reason=error.reason)
    return HTTPException(
        status_code=_HUNT_QUERY_ERROR_STATUS.get(error.reason, 400),
        detail=str(error),
    )


def _resolve_hunt_dialect_or_http(
    search: Optional[str],
    search_dialect: Optional[str],
) -> tuple[HuntDialect, Optional[str]]:
    try:
        dialect, search_text = resolve_hunt_dialect(search=search, search_dialect=search_dialect)
    except HuntQueryError as err:
        raise _hunt_query_http_error(err, "invalid") from err
    if dialect == "eql":
        raise _hunt_query_http_error(HuntQueryError(EQL_ENDPOINT_HINT, reason="eql_endpoint"), "eql")
    return dialect, search_text


def _default_hunt_window_minutes() -> int:
    return int(getattr(settings, "SEAGULL_HUNT_DEFAULT_WINDOW_MINUTES", 1440) or 1440)


def _prepare_kql_hunt(
    search_text: str | None,
    *,
    end_ts: datetime,
    start_ts: datetime | None,
    window_minutes: int | None,
    agent_id: str | None,
    event_type: str | None,
) -> tuple[Dict[str, Any], QuerySignals, datetime | None, int | None]:
    try:
        if not (search_text or "").strip():
            raise HuntQueryError("KQL dialect requires a non-empty search query", reason="syntax")
        if search_backend_mode() == "postgres":
            raise HuntQueryError("KQL requires the Elasticsearch search backend", reason="es_unavailable")
        compiled = compile_kql(
            str(search_text),
            field_types=hunt_field_types(),
            free_text_fields=HUNT_FREE_TEXT_FIELDS,
            max_clauses=int(getattr(settings, "SEAGULL_HUNT_MAX_QUERY_CLAUSES", 32) or 32),
        )
    except HuntQueryError as err:
        raise _hunt_query_http_error(err, "kql") from err

    if start_ts is None and not compiled.has_timestamp_range:
        start_ts = end_ts - timedelta(minutes=_default_hunt_window_minutes())
        window_minutes = int(max(1, (end_ts - start_ts).total_seconds() // 60))

    filter_clauses = compiled.clause_count
    if agent_id:
        filter_clauses += 1
    if event_type:
        filter_clauses += 1
    if start_ts is not None:
        filter_clauses += 1
    signals = QuerySignals(
        has_search=True,
        has_wildcard=compiled.has_wildcard,
        filter_clauses=filter_clauses,
        window_minutes=window_minutes,
        dialect="kql",
    )
    return compiled.query, signals, start_ts, window_minutes


def _rollback_quietly(db: Session) -> None:
    rollback = getattr(db, "rollback", None)
    if not callable(rollback):
        return
    try:
        rollback()
    except Exception:
        pass


def _record_hunt_failure(backend: str, reason: str) -> None:
    if _hunt_breaker.record_failure(backend):
        incr_counter("hunt_backend_circuit_open_total", backend=backend)
        log_event(logger, "warning", "hunt_backend_circuit_opened", backend=backend, reason=reason)


def _execute_hunt_backend(
    db: Session,
    backend: str,
    *,
    signals: QuerySignals,
    page_size: int,
    cursor: str | None,
    agent_id: str | None,
    event_type: str | None,
    start_ts: datetime | None,
    end_ts: datetime,
    search: str | None,
    tokens: list[str],
    kql_query: Dict[str, Any] | None = None,
) -> tuple[list[NetEventDB], str | None, bool]:
    timeout_seconds = _hunt_backend_timeout_seconds(backend, signals)

    if backend == "elasticsearch":
        es = _es_client_or_none()
        if es is None:
            raise LookupError("elasticsearch_unavailable")
        if kql_query is not None:
            try:
                return _es_kql_hunt_query(
                    es=es,
                    compiled_query=kql_query,
                    page_size=page_size,
                    cursor=cursor,
                    agent_id=agent_id,
                    event_type=event_type,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    timeout_seconds=timeout_seconds,
                    terminate_after=int(getattr(settings, "SEAGULL_HUNT_TERMINATE_AFTER", 10000) or 10000),
                )
            except HuntQueryError as err:
                raise _hunt_query_http_error(err, "kql") from err
        items, next_cursor, has_more = _es_hunt_query(
            es=es,
            page_size=page_size,
            cursor=cursor,
            agent_id=agent_id,
            event_type=event_type,
            start_ts=start_ts,
            end_ts=end_ts,
            search=search,
            timeout_seconds=timeout_seconds,
        )
        if items and _es_failover_allowed() and not route_trusts_es():
            if _pg_has_newer_event(db, latest_ts=items[0].timestamp, agent_id=agent_id, event_type=event_type):
                raise LookupError("elasticsearch_stale")
        return items, next_cursor, has_more

    if backend == "clickhouse":
        ch = _ch_client_or_none()
        if ch is None:
            raise LookupError("clickhouse_unavailable")
        items, next_cursor, has_more = _ch_hunt_query(
            ch=ch,
            page_size=page_size,
            cursor=cursor,
            agent_id=agent_id,
            event_type=event_type,
            start_ts=start_ts,
            end_ts=end_ts,
            search=search,
            timeout_seconds=timeout_seconds,
        )
        if items and _pg_has_newer_event(db, latest_ts=items[0].timestamp, agent_id=agent_id, event_type=event_type):
            raise LookupError("clickhouse_stale")
        return items, next_cursor, has_more

    try:
        return _pg_hunt_query(
            db,
            page_size=page_size,
            cursor=cursor,
            agent_id=agent_id,
            event_type=event_type,
            start_ts=start_ts,
            end_ts=end_ts,
            tokens=tokens,
            timeout_seconds=timeout_seconds,
        )
    except Exception:
        _rollback_quietly(db)
        raise


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
    search_dialect: Optional[str] = None,
) -> EventHuntResponse:
    started = time.perf_counter()
    now = _now_utc()
    size = max(1, min(int(page_size), 1000))

    dialect, search_text = _resolve_hunt_dialect_or_http(search, search_dialect)
    incr_counter("hunt_query_dialect_total", dialect=dialect)

    start_ts, end_ts, window_minutes = _resolve_hunt_window(
        now=now,
        since_minutes=since_minutes,
        start_ts_iso=start_ts_iso,
        end_ts_iso=end_ts_iso,
    )

    tokens: list[str] = []
    kql_query: Dict[str, Any] | None = None
    if dialect == "kql":
        kql_query, signals, start_ts, window_minutes = _prepare_kql_hunt(
            search_text,
            end_ts=end_ts,
            start_ts=start_ts,
            window_minutes=window_minutes,
            agent_id=agent_id,
            event_type=event_type,
        )
    else:
        tokens = _search_tokens(search_text)
        if search_text is not None and not str(search_text).strip():
            raise HTTPException(status_code=422, detail="search must contain non-whitespace characters")
        signals = _build_hunt_signals(
            search=search_text,
            tokens=tokens,
            agent_id=agent_id,
            event_type=event_type,
            start_ts=start_ts,
            window_minutes=window_minutes,
        )
    decision = _route_decision(signals)

    attempted: list[str] = []
    pending_fallbacks: list[tuple[str, str]] = []
    degraded_reason: str | None = None
    items: list[NetEventDB] = []
    next_cursor: str | None = None
    has_more = False
    succeeded = False
    selected_source: QuerySource = "postgres"

    for candidate in decision.chain:
        if not _hunt_breaker.allow(candidate):
            pending_fallbacks.append((candidate, "circuit_open"))
            degraded_reason = f"{candidate}_skipped:circuit_open"[:200]
            continue

        for from_backend, fallback_reason in pending_fallbacks:
            incr_counter(
                "hunt_backend_fallback_total",
                from_backend=from_backend,
                to_backend=candidate,
                reason=fallback_reason,
            )
        pending_fallbacks.clear()

        if not attempted:
            chosen_reason = decision.reason if candidate == decision.chain[0] else "fallback"
            incr_counter("hunt_backend_chosen_total", backend=candidate, reason=chosen_reason)
        attempted.append(candidate)

        attempt_started = time.perf_counter()
        try:
            items, next_cursor, has_more = _execute_hunt_backend(
                db,
                candidate,
                signals=signals,
                page_size=size,
                cursor=cursor,
                agent_id=agent_id,
                event_type=event_type,
                start_ts=start_ts,
                end_ts=end_ts,
                search=search_text,
                tokens=tokens,
                kql_query=kql_query,
            )
        except HTTPException as exc:
            observe_hist("hunt_backend_query_seconds", time.perf_counter() - attempt_started, backend=candidate)
            if int(getattr(exc, "status_code", 500) or 500) >= 500:
                _record_hunt_failure(candidate, "required_unavailable")
            else:
                _hunt_breaker.record_success(candidate)
            raise
        except Exception as exc:
            observe_hist("hunt_backend_query_seconds", time.perf_counter() - attempt_started, backend=candidate)
            reason = classify_backend_failure(exc)
            degraded_reason = f"{candidate}_fallback:{reason}"[:200]
            pending_fallbacks.append((candidate, reason))
            if failure_counts_toward_breaker(reason):
                _record_hunt_failure(candidate, reason)
            else:
                _hunt_breaker.record_success(candidate)
        else:
            observe_hist("hunt_backend_query_seconds", time.perf_counter() - attempt_started, backend=candidate)
            _hunt_breaker.record_success(candidate)
            selected_source = candidate
            succeeded = True
            break

    if not succeeded:
        if dialect == "kql":
            raise _hunt_query_http_error(
                HuntQueryError(
                    "KQL hunt is unavailable: Elasticsearch is unreachable or its circuit is open",
                    reason="es_unavailable",
                ),
                "kql",
            )
        raise HTTPException(
            status_code=503,
            detail="Event hunt is temporarily unavailable: all backends failed or have an open circuit",
        )

    observe_hist("hunt_query_seconds", time.perf_counter() - started, dialect=dialect)
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


def explain_hunt_route(
    *,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    since_minutes: Optional[int] = None,
    start_ts_iso: Optional[str] = None,
    end_ts_iso: Optional[str] = None,
    search: Optional[str] = None,
    search_dialect: Optional[str] = None,
    aggregate: bool = False,
) -> HuntRouteExplainResponse:
    now = _now_utc()
    dialect, search_text = _resolve_hunt_dialect_or_http(search, search_dialect)
    start_ts, end_ts, window_minutes = _resolve_hunt_window(
        now=now,
        since_minutes=since_minutes,
        start_ts_iso=start_ts_iso,
        end_ts_iso=end_ts_iso,
    )

    if dialect == "kql":
        _kql_query, signals, start_ts, window_minutes = _prepare_kql_hunt(
            search_text,
            end_ts=end_ts,
            start_ts=start_ts,
            window_minutes=window_minutes,
            agent_id=agent_id,
            event_type=event_type,
        )
    else:
        tokens = _search_tokens(search_text)
        if search_text is not None and not str(search_text).strip():
            raise HTTPException(status_code=422, detail="search must contain non-whitespace characters")
        signals = _build_hunt_signals(
            search=search_text,
            tokens=tokens,
            agent_id=agent_id,
            event_type=event_type,
            start_ts=start_ts,
            window_minutes=window_minutes,
            aggregate=aggregate,
        )
    decision = _route_decision(signals)
    circuit = {backend: _hunt_breaker.state(backend) for backend in decision.chain}
    return HuntRouteExplainResponse(
        generated_at=now,
        decision_backend=decision.chain[0],
        decision_reason=decision.reason,
        chain=list(decision.chain),
        attempt_plan=[backend for backend in decision.chain if circuit[backend].state != "open"],
        signals=HuntRouteSignals(
            has_search=signals.has_search,
            has_wildcard=signals.has_wildcard,
            filter_clauses=signals.filter_clauses,
            window_minutes=signals.window_minutes,
            aggregate=signals.aggregate,
            transactional_join=signals.transactional_join,
            dialect=dialect,
        ),
        timeouts_seconds={
            backend: _hunt_backend_timeout_seconds(backend, signals) for backend in decision.chain
        },
        circuit={
            backend: HuntRouteCircuitState(
                state=state.state,
                recent_failures=state.recent_failures,
                open_remaining_seconds=state.open_remaining_seconds,
                probe_in_flight=state.probe_in_flight,
            )
            for backend, state in circuit.items()
        },
        trust_es=route_trusts_es(),
        search_backend_mode=search_backend_mode(),
        query_window_start=start_ts,
        query_window_end=end_ts,
    )


def hunt_events_eql(
    *,
    query: str,
    since_minutes: Optional[int] = None,
    start_ts_iso: Optional[str] = None,
    end_ts_iso: Optional[str] = None,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    size: Optional[int] = None,
) -> EqlHuntResponse:
    started = time.perf_counter()
    now = _now_utc()
    incr_counter("hunt_query_dialect_total", dialect="eql")

    try:
        query_text = normalize_eql_query(query)
        if search_backend_mode() == "postgres":
            raise HuntQueryError("EQL requires the Elasticsearch search backend", reason="es_unavailable")
    except HuntQueryError as err:
        raise _hunt_query_http_error(err, "eql") from err

    start_ts, end_ts, _window_minutes = _resolve_hunt_window(
        now=now,
        since_minutes=since_minutes,
        start_ts_iso=start_ts_iso,
        end_ts_iso=end_ts_iso,
    )
    if start_ts is None:
        start_ts = end_ts - timedelta(minutes=_default_hunt_window_minutes())

    es = _es_client_or_none()
    if es is None:
        raise _hunt_query_http_error(
            HuntQueryError("Elasticsearch is unavailable for EQL queries", reason="es_unavailable"),
            "eql",
        )
    if not _hunt_breaker.allow("elasticsearch"):
        raise _hunt_query_http_error(
            HuntQueryError(
                "Elasticsearch circuit is open; EQL queries are temporarily rejected",
                reason="circuit_open",
            ),
            "eql",
        )

    max_sequences = int(getattr(settings, "SEAGULL_HUNT_EQL_MAX_SEQUENCES", 50) or 50)
    effective_size = min(int(size), max_sequences) if size else max_sequences
    filters = _es_base_filters(since=start_ts, agent_id=agent_id, event_type=event_type)
    filters.append({"range": {"timestamp": {"lte": end_ts.isoformat()}}})

    attempt_started = time.perf_counter()
    try:
        data = _es_eql_query(
            es=es,
            query=query_text,
            filters=filters,
            size=effective_size,
            fetch_size=int(getattr(settings, "SEAGULL_HUNT_EQL_FETCH_SIZE", 512) or 512),
            timeout_seconds=float(getattr(settings, "SEAGULL_HUNT_EQL_TIMEOUT_SECONDS", 5.0) or 5.0),
        )
    except HuntQueryError as err:
        observe_hist("hunt_backend_query_seconds", time.perf_counter() - attempt_started, backend="elasticsearch")
        if err.reason in ("timeout", "es_unavailable"):
            _record_hunt_failure("elasticsearch", err.reason)
        else:
            _hunt_breaker.record_success("elasticsearch")
        raise _hunt_query_http_error(err, "eql") from err

    observe_hist("hunt_backend_query_seconds", time.perf_counter() - attempt_started, backend="elasticsearch")
    _hunt_breaker.record_success("elasticsearch")

    sequences, total = eql_sequences_from_response(data)
    observe_hist("hunt_eql_sequences_returned", float(len(sequences)))
    observe_hist("hunt_query_seconds", time.perf_counter() - started, dialect="eql")
    meta = _meta(
        source="elasticsearch",
        fallback_chain=["elasticsearch"],
        degraded_reason=None,
        source_freshness_seconds=None,
        query_latency_ms=(time.perf_counter() - started) * 1000.0,
        cache_hit=False,
        approximate=False,
        query_window_start=start_ts,
        query_window_end=end_ts,
    )
    return EqlHuntResponse(generated_at=now, total=total, sequences=sequences, meta=meta)


def hunt_field_catalog() -> HuntFieldsResponse:
    return HuntFieldsResponse(
        generated_at=_now_utc(),
        fields=[HuntFieldSpec(name=name, type=field_type) for name, field_type in hunt_field_listing()],
    )


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


def resolve_protocol_intel_summary(
    db: Session,
    *,
    since_minutes: int = 60 * 12,
    limit: int = 25,
    agent_id: Optional[str] = None,
) -> ProtocolIntelSummaryResponse:
    _bind_summary_module()
    return event_summaries.resolve_protocol_intel_summary(
        db,
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )


_PROTOCOL_INTEL_MAX_SINCE_MINUTES = 60 * 24 * 30


def _protocol_intel_cache_key(params: Dict[str, Any]) -> str:
    agent = str(params.get("agent_id") or "").strip() or "*"
    widen = 1 if params.get("widen_if_empty") else 0
    return (
        "seagull:events:network_summary:v6:"
        f"sb={search_backend_mode()}:sm={int(params['since_minutes'])}:l={int(params['limit'])}"
        f":a={agent}:w={widen}"
    )


def _resolve_protocol_intel_blocking(
    *, since_minutes: int, limit: int, agent_id: Optional[str]
) -> ProtocolIntelSummaryResponse:
    db = SessionLocal()
    try:
        return resolve_protocol_intel_summary(db, since_minutes=since_minutes, limit=limit, agent_id=agent_id)
    finally:
        db.close()


async def _compute_protocol_intel(params: Dict[str, Any]) -> dict:
    since_minutes = int(params["since_minutes"])
    limit = int(params["limit"])
    agent_id = params.get("agent_id") or None
    widen = bool(params.get("widen_if_empty"))

    payload = await asyncio.to_thread(
        _resolve_protocol_intel_blocking, since_minutes=since_minutes, limit=limit, agent_id=agent_id
    )
    if payload.total_events <= 0 and widen and since_minutes < _PROTOCOL_INTEL_MAX_SINCE_MINUTES:
        widened = min(max(since_minutes * 6, since_minutes + 60), _PROTOCOL_INTEL_MAX_SINCE_MINUTES)
        widened_payload = await asyncio.to_thread(
            _resolve_protocol_intel_blocking, since_minutes=widened, limit=limit, agent_id=agent_id
        )
        if widened_payload.total_events > 0:
            widened_payload.effective_since_minutes = widened
            return widened_payload.dict()
    return payload.dict()


PROTOCOL_INTEL_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="protocol_intel",
        schema_version=6,
        fresh_s=int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_FRESH_SECONDS", 240) or 240),
        stale_s=int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_STALE_SECONDS", 1800) or 1800),
        key_builder=_protocol_intel_cache_key,
        compute=_compute_protocol_intel,
    )
)


async def get_protocol_intel_summary_async(
    *,
    since_minutes: int = 60 * 12,
    limit: int = 25,
    agent_id: Optional[str] = None,
    widen_if_empty: bool = False,
) -> tuple[dict, str, str]:
    started = time.perf_counter()
    params = {
        "since_minutes": int(since_minutes),
        "limit": int(limit),
        "agent_id": agent_id or None,
        "widen_if_empty": bool(widen_if_empty),
    }
    payload, etag, outcome = await serve_read_model(PROTOCOL_INTEL_READ_MODEL, params)
    payload = dict(payload)
    meta = dict(payload.get("meta") or {})
    meta["cache_hit"] = outcome != "miss"
    meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    payload["meta"] = meta
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/events/network/summary",
        source=str(meta.get("source") or "clickhouse"),
    )
    return payload, etag, outcome


_SSH_SUMMARY_MAX_SINCE_MINUTES = 60 * 24 * 30


def _ssh_summary_cache_key(params: Dict[str, Any]) -> str:
    agent = str(params.get("agent_id") or "").strip() or "*"
    widen = 1 if params.get("widen_if_empty") else 0
    return (
        "seagull:events:ssh_summary:swr:v5:"
        f"sb={search_backend_mode()}:sm={int(params['since_minutes'])}:l={int(params['limit'])}"
        f":a={agent}:w={widen}"
    )


def _resolve_ssh_summary_blocking(*, since_minutes: int, limit: int, agent_id: Optional[str]) -> SshSummaryResponse:
    db = SessionLocal()
    try:
        return get_ssh_summary(db, since_minutes=since_minutes, limit=limit, agent_id=agent_id)
    finally:
        db.close()


def _ssh_summary_is_empty(payload: SshSummaryResponse) -> bool:
    return int(payload.total_actions or 0) <= 0 and not payload.sudo_recent


async def _compute_ssh_summary(params: Dict[str, Any]) -> dict:
    since_minutes = int(params["since_minutes"])
    limit = int(params["limit"])
    agent_id = params.get("agent_id") or None
    widen = bool(params.get("widen_if_empty"))

    payload = await asyncio.to_thread(
        _resolve_ssh_summary_blocking, since_minutes=since_minutes, limit=limit, agent_id=agent_id
    )
    if _ssh_summary_is_empty(payload) and widen and since_minutes < _SSH_SUMMARY_MAX_SINCE_MINUTES:
        widened_payload = await asyncio.to_thread(
            _resolve_ssh_summary_blocking,
            since_minutes=_SSH_SUMMARY_MAX_SINCE_MINUTES,
            limit=limit,
            agent_id=agent_id,
        )
        if not _ssh_summary_is_empty(widened_payload):
            widened_payload.effective_since_minutes = _SSH_SUMMARY_MAX_SINCE_MINUTES
            return widened_payload.dict()
    return payload.dict()


SSH_SUMMARY_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="ssh_summary",
        schema_version=5,
        fresh_s=int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_FRESH_SECONDS", 240) or 240),
        stale_s=int(getattr(settings, "SEAGULL_EVENTS_SUMMARY_STALE_SECONDS", 1800) or 1800),
        key_builder=_ssh_summary_cache_key,
        compute=_compute_ssh_summary,
    )
)


async def get_ssh_summary_async(
    *,
    since_minutes: int = 60 * 24,
    limit: int = 50,
    agent_id: Optional[str] = None,
    widen_if_empty: bool = False,
) -> tuple[dict, str, str]:
    started = time.perf_counter()
    params = {
        "since_minutes": int(since_minutes),
        "limit": int(limit),
        "agent_id": agent_id or None,
        "widen_if_empty": bool(widen_if_empty),
    }
    payload, etag, outcome = await serve_read_model(SSH_SUMMARY_READ_MODEL, params)
    payload = dict(payload)
    meta = dict(payload.get("meta") or {})
    meta["cache_hit"] = outcome != "miss"
    meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    payload["meta"] = meta
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/events/ssh/summary",
        source=str(meta.get("source") or "clickhouse"),
    )
    return payload, etag, outcome


def _prewarm_top_agents(limit: int) -> List[str]:
    if int(limit) <= 0:
        return []
    ch = _ch_client_or_none()
    if ch is None:
        return []
    try:
        ref = clickhouse_events_1m_table_ref()
        rows = _ch_query_dicts(
            ch,
            f"SELECT agent_id, sum(total_count) AS c FROM {ref} "
            "WHERE bucket_ts >= now() - INTERVAL 1 DAY GROUP BY agent_id ORDER BY c DESC "
            f"LIMIT {int(limit)}",
        )
        return [str(r.get("agent_id")) for r in rows if str(r.get("agent_id") or "").strip()]
    except Exception:
        return []


def _protocol_intel_warm_specs() -> List[WarmSpec]:
    top = int(getattr(settings, "SEAGULL_ANALYTICS_PREWARM_TOP_AGENTS", 3) or 3)
    agents: List[Optional[str]] = [None] + _prewarm_top_agents(top)
    specs: List[WarmSpec] = []
    for since_minutes in (60, 720, 1440, 10080):
        for agent_id in agents:
            specs.append(
                WarmSpec(
                    feature="protocol_intel",
                    params={
                        "since_minutes": since_minutes,
                        "limit": 25,
                        "agent_id": agent_id,
                        "widen_if_empty": True,
                    },
                )
            )
    return specs


def _ssh_summary_warm_specs() -> List[WarmSpec]:
    top = int(getattr(settings, "SEAGULL_ANALYTICS_PREWARM_TOP_AGENTS", 3) or 3)
    agents: List[Optional[str]] = [None] + _prewarm_top_agents(top)
    specs: List[WarmSpec] = []
    for since_minutes in (1440, 10080):
        for agent_id in agents:
            specs.append(
                WarmSpec(
                    feature="ssh_summary",
                    params={
                        "since_minutes": since_minutes,
                        "limit": 50,
                        "agent_id": agent_id,
                        "widen_if_empty": True,
                    },
                )
            )
    return specs


register_warm_set(_protocol_intel_warm_specs)
register_warm_set(_ssh_summary_warm_specs)


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
