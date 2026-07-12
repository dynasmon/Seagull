from __future__ import annotations

import json
from typing import Any, AsyncIterator, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.api.conditional import maybe_not_modified
from app.core.db import SessionLocal, get_db
from app.core.db.session import managed_session
from app.core.observability import incr_counter
from app.features.auth.session import PortalPrincipal, get_current_user, require_admin
from app.features.events import service as events_service
from app.features.events.schemas import (
    DdosLiveSnapshotResponse,
    EqlHuntRequest,
    EqlHuntResponse,
    EventHuntResponse,
    EventStreamSnapshotResponse,
    HuntFieldsResponse,
    HuntRouteExplainResponse,
    NetEventDB,
    NetEventRollup1s,
    ProtocolIntelSummaryResponse,
    SshSummaryResponse,
)
from app.features.events.service import (
    _cache_get_json,
    _cache_set_json,
    _ch_client_or_none,
    _es_client_or_none,
    get_ddos_live_snapshot,
    get_event_stream_snapshot,
    get_port_stats,
    get_recent_events,
    hunt_events,
    list_rollups_1s,
)
from app.features.events.service import (
    get_protocol_intel_samples as _get_protocol_intel_samples_service,
)
from app.features.events.service import (
    get_protocol_intel_summary as _get_protocol_intel_summary_service,
)
from app.features.events.service import (
    get_ssh_summary as _get_ssh_summary_service,
)

router = APIRouter(
    prefix="/events",
    tags=["events"],
    dependencies=[Depends(get_current_user)],
)


def _with_service_overrides(fn, *args, **kwargs):
    originals = {
        "_cache_get_json": events_service._cache_get_json,
        "_cache_set_json": events_service._cache_set_json,
        "_ch_client_or_none": events_service._ch_client_or_none,
        "_es_client_or_none": events_service._es_client_or_none,
    }
    try:
        events_service._cache_get_json = _cache_get_json
        events_service._cache_set_json = _cache_set_json
        events_service._ch_client_or_none = _ch_client_or_none
        events_service._es_client_or_none = _es_client_or_none
        return fn(*args, **kwargs)
    finally:
        events_service._cache_get_json = originals["_cache_get_json"]
        events_service._cache_set_json = originals["_cache_set_json"]
        events_service._ch_client_or_none = originals["_ch_client_or_none"]
        events_service._es_client_or_none = originals["_es_client_or_none"]


def get_ssh_summary(
    since_minutes: int = 60 * 24,
    limit: int = 50,
    agent_id: Optional[str] = None,
    db: Session | None = None,
) -> SshSummaryResponse:
    if db is None:
        db = SessionLocal()
        try:
            return _with_service_overrides(
                _get_ssh_summary_service,
                db,
                since_minutes=since_minutes,
                limit=limit,
                agent_id=agent_id,
            )
        finally:
            db.close()
    return _with_service_overrides(
        _get_ssh_summary_service,
        db,
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )


def get_protocol_intel_summary(
    since_minutes: int = 60 * 12,
    limit: int = 25,
    agent_id: Optional[str] = None,
    db: Session | None = None,
) -> ProtocolIntelSummaryResponse:
    if db is None:
        db = SessionLocal()
        try:
            return _get_protocol_intel_summary_service(
                db,
                since_minutes=since_minutes,
                limit=limit,
                agent_id=agent_id,
            )
        finally:
            db.close()
    return _get_protocol_intel_summary_service(
        db,
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )


def get_protocol_intel_samples(
    kind: str,
    value: str,
    since_minutes: int = 60 * 12,
    limit: int = 50,
    agent_id: Optional[str] = None,
    db: Session | None = None,
) -> List[NetEventDB]:
    if db is None:
        db = SessionLocal()
        try:
            return _get_protocol_intel_samples_service(
                db,
                kind=kind,
                value=value,
                since_minutes=since_minutes,
                limit=limit,
                agent_id=agent_id,
            )
        finally:
            db.close()
    return _get_protocol_intel_samples_service(
        db,
        kind=kind,
        value=value,
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )


@router.get("", response_model=EventHuntResponse)
def list_events_endpoint(
    page_size: int = Query(50, ge=1, le=500, description="Page size (max 500)"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, min_length=1, max_length=32, description="Filter by event type"),
    since_minutes: Optional[int] = Query(None, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    start_ts: Optional[str] = Query(None, description="Optional explicit start timestamp (ISO-8601)"),
    end_ts: Optional[str] = Query(None, description="Optional explicit end timestamp (ISO-8601)"),
    search: Optional[str] = Query(None, min_length=1, max_length=512, description="Server-side hunt query"),
    search_dialect: Optional[Literal["simple", "kql", "eql"]] = Query(
        None,
        description="Query dialect for search; defaults to simple, kql:/eql: prefixes apply when omitted",
    ),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return hunt_events(
            db_session,
            page_size=page_size,
            cursor=cursor,
            agent_id=agent_id,
            event_type=event_type,
            since_minutes=since_minutes,
            start_ts_iso=start_ts,
            end_ts_iso=end_ts,
            search=search,
            search_dialect=search_dialect,
        )


@router.get("/hunt/explain", response_model=HuntRouteExplainResponse)
def explain_hunt_route_endpoint(
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, min_length=1, max_length=32, description="Filter by event type"),
    since_minutes: Optional[int] = Query(None, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    start_ts: Optional[str] = Query(None, description="Optional explicit start timestamp (ISO-8601)"),
    end_ts: Optional[str] = Query(None, description="Optional explicit end timestamp (ISO-8601)"),
    search: Optional[str] = Query(None, min_length=1, max_length=512, description="Server-side hunt query"),
    search_dialect: Optional[Literal["simple", "kql", "eql"]] = Query(
        None,
        description="Query dialect for search; defaults to simple, kql:/eql: prefixes apply when omitted",
    ),
    aggregate: bool = Query(False, description="Simulate an aggregation-shaped query"),
    _: PortalPrincipal = Depends(require_admin),
):
    return events_service.explain_hunt_route(
        agent_id=agent_id,
        event_type=event_type,
        since_minutes=since_minutes,
        start_ts_iso=start_ts,
        end_ts_iso=end_ts,
        search=search,
        search_dialect=search_dialect,
        aggregate=aggregate,
    )


@router.post("/hunt/eql", response_model=EqlHuntResponse)
def hunt_events_eql_endpoint(payload: EqlHuntRequest) -> EqlHuntResponse:
    return events_service.hunt_events_eql(
        query=payload.query,
        since_minutes=payload.since_minutes,
        start_ts_iso=payload.start_ts,
        end_ts_iso=payload.end_ts,
        agent_id=payload.agent_id,
        event_type=payload.event_type,
        size=payload.size,
    )


@router.get("/hunt/fields", response_model=HuntFieldsResponse)
def hunt_fields_endpoint() -> HuntFieldsResponse:
    return events_service.hunt_field_catalog()


@router.get("/recent", response_model=List[NetEventDB])
def get_recent_events_endpoint(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of events to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    search: Optional[str] = Query(None, min_length=1, max_length=256, description="Optional server-side search"),
    since_minutes: Optional[int] = Query(None, ge=1, le=60 * 24 * 30, description="Optional lookback window in minutes"),
    window_minutes: Optional[int] = Query(None, ge=1, le=60 * 24 * 30, description="Backward-compatible alias for since_minutes"),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        lookback_minutes = since_minutes if since_minutes is not None else window_minutes
        if search:
            page = hunt_events(
                db_session,
                page_size=limit,
                cursor=None,
                agent_id=agent_id,
                event_type=event_type,
                since_minutes=lookback_minutes,
                start_ts_iso=None,
                end_ts_iso=None,
                search=search,
            )
            return page.items
        return get_recent_events(
            db_session,
            limit=limit,
            agent_id=agent_id,
            event_type=event_type,
            since_minutes=lookback_minutes,
        )


@router.get("/live/stream", response_model=EventStreamSnapshotResponse)
def get_event_stream_snapshot_endpoint(
    limit: int = Query(200, ge=10, le=500, description="Maximum number of live rows to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    search: Optional[str] = Query(None, min_length=1, max_length=256, description="Optional server-side search"),
    since_minutes: int = Query(60, ge=1, le=60 * 24 * 30, description="Recent live window in minutes"),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return get_event_stream_snapshot(
            db_session,
            limit=limit,
            agent_id=agent_id,
            event_type=event_type,
            search=search,
            since_minutes=since_minutes,
        )


@router.get("/live/ddos", response_model=DdosLiveSnapshotResponse)
def get_ddos_live_snapshot_endpoint(
    limit: int = Query(200, ge=25, le=500, description="Maximum number of live DDoS rows to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Recent live window in minutes"),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return get_ddos_live_snapshot(
            db_session,
            limit=limit,
            agent_id=agent_id,
            since_minutes=since_minutes,
        )


@router.get("/rollups/1s", response_model=List[NetEventRollup1s])
def list_rollups_1s_endpoint(
    minutes: int = Query(60, ge=1, le=24 * 60, description="Lookback window in minutes"),
    limit: int = Query(500, ge=1, le=5000, description="Max buckets to return"),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    event_type: Optional[str] = Query(None, min_length=1, max_length=32),
    dst_ip: Optional[str] = Query(None, min_length=1, max_length=45),
    dst_port: Optional[int] = Query(None, ge=0, le=65535),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return list_rollups_1s(
            db_session,
            minutes=minutes,
            limit=limit,
            agent_id=agent_id,
            event_type=event_type,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )


@router.get("/stats/ports")
def get_port_stats_endpoint(
    limit: int = Query(20, ge=1, le=200, description="Maximum number of ports to return"),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    with managed_session(db) as db_session:
        return get_port_stats(db_session, limit=limit)


@router.get("/ssh/summary", response_model=SshSummaryResponse)
async def get_ssh_summary_endpoint(
    request: Request,
    response: Response,
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(50, ge=1, le=500, description="Row limit for recent/raw SSH views and supporting aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
):
    payload, etag, outcome = await events_service.get_ssh_summary_async(
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )
    response.headers["X-Cache-Outcome"] = outcome
    incr_counter("api_cache_outcome_total", route="/events/ssh/summary", outcome=outcome)
    not_modified = maybe_not_modified(response, request.headers.get("If-None-Match"), etag, outcome=outcome)
    if not_modified is not None:
        incr_counter("api_304_total", route="/events/ssh/summary")
        return not_modified
    return payload


@router.get("/network/summary", response_model=ProtocolIntelSummaryResponse)
async def get_protocol_intel_summary_endpoint(
    request: Request,
    response: Response,
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(25, ge=1, le=200, description="Top-N limit for aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    widen_if_empty: bool = Query(False, description="Widen the window once server-side when empty"),
):
    payload, etag, outcome = await events_service.get_protocol_intel_summary_async(
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
        widen_if_empty=widen_if_empty,
    )
    response.headers["X-Cache-Outcome"] = outcome
    incr_counter("api_cache_outcome_total", route="/events/network/summary", outcome=outcome)
    not_modified = maybe_not_modified(response, request.headers.get("If-None-Match"), etag, outcome=outcome)
    if not_modified is not None:
        incr_counter("api_304_total", route="/events/network/summary")
        return not_modified
    return payload


_PROTOCOL_INTEL_FACET_KEYS = (
    "app_protocols",
    "transport_protocols",
    "top_dst_ports",
    "top_src_ports",
    "app_proto_reasons",
    "app_proto_conf_bands",
    "ja4_ptypes",
    "http_methods",
    "top_dns_queries",
    "top_http_hosts",
    "top_tls_sni",
    "top_alpn",
    "top_ja4",
    "top_ja3",
)

_PROTOCOL_INTEL_OVERVIEW_KEYS = (
    "generated_at",
    "since_minutes",
    "agent_id",
    "total_events",
    "with_proto_metadata",
    "dns_events",
    "http_events",
    "tls_events",
    "effective_since_minutes",
    "meta",
)


def _sse_frame(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str, separators=(',', ':'))}\n\n"


@router.get("/network/summary/stream")
async def get_protocol_intel_summary_stream_endpoint(
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(25, ge=1, le=200, description="Top-N limit for aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    widen_if_empty: bool = Query(False, description="Widen the window once server-side when empty"),
):
    payload, etag, _outcome = await events_service.get_protocol_intel_summary_async(
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
        widen_if_empty=widen_if_empty,
    )

    async def _stream() -> AsyncIterator[str]:
        overview = {key: payload.get(key) for key in _PROTOCOL_INTEL_OVERVIEW_KEYS}
        overview["etag"] = etag
        yield _sse_frame("overview", overview)
        for key in _PROTOCOL_INTEL_FACET_KEYS:
            yield _sse_frame("facet", {"name": key, "items": payload.get(key) or []})
        yield _sse_frame("done", {"etag": etag})

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "ETag": etag},
    )


@router.get("/network/samples", response_model=List[NetEventDB])
def get_protocol_intel_samples_endpoint(
    kind: str = Query(..., min_length=2, max_length=32, description="Which field to filter on"),
    value: str = Query(..., min_length=1, max_length=512, description="Exact value for the selected field"),
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of events to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return get_protocol_intel_samples(
            kind=kind,
            value=value,
            since_minutes=since_minutes,
            limit=limit,
            agent_id=agent_id,
            db=db_session,
        )
