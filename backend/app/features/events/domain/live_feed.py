from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.observability import log_event
from app.features.events import repository
from app.features.events.domain.normalizers import (
    _ch_row_to_event,
    _event_obj_to_event_safe,
    _feed_row_to_event,
    _hit_to_event,
    _meta,
)
from app.features.events.domain.queries import (
    _ch_client_or_none,
    _ch_deduped_events_source_sql,
    _ch_query_dicts,
    _ch_where,
    _es_base_filters,
    _es_client_or_none,
    _es_failover_allowed,
    _es_index_pattern,
    _next_cursor_for_rows,
    _pg_has_newer_event,
    clickhouse_events_table_ref,
)
from app.features.events.domain.routing import route_trusts_es
from app.features.events.models import NetEventModel
from app.features.events.recent_feed import fetch_recent_events as fetch_recent_feed_events
from app.features.events.recent_feed import recent_feed_health
from app.features.events.schemas import (
    DdosLiveSnapshotResponse,
    EventStreamSnapshotResponse,
    NetEventDB,
)
from app.features.ingest.control.service import get_storm_status

logger = logging.getLogger("seagull.api.events")


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


def _ddos_events_only(rows: List[NetEventDB]) -> List[NetEventDB]:
    return [row for row in rows if str(row.event_type or "").strip().lower() in {"dos_attack", "ddos_telemetry"}]


def _build_recent_feed_meta(
    *,
    agent_id: str | None,
    started: float,
    window_minutes: int,
    degraded_reason: str | None = None,
) -> Any:
    now = datetime.now(timezone.utc)
    health = recent_feed_health(agent_id=agent_id)
    freshness = health.get("freshness_seconds") if isinstance(health, dict) else None
    if isinstance(freshness, bool):
        freshness = None
    if freshness is not None:
        try:
            freshness = int(freshness)
        except Exception:
            freshness = None
    return _meta(
        source="recent_feed",
        fallback_chain=["recent_feed"],
        degraded_reason=degraded_reason,
        source_freshness_seconds=freshness,
        query_latency_ms=(time.perf_counter() - started) * 1000.0,
        cache_hit=False,
        approximate=False,
        query_window_start=now - timedelta(minutes=max(1, int(window_minutes))),
        query_window_end=now,
    )


def _empty_ddos_summary() -> dict[str, Any]:
    return {
        "ddos_packets_estimated": 0,
        "ddos_samples": 0,
        "ddos_peak_pps": 0.0,
        "ddos_peak_bps": 0.0,
        "ddos_peak_syn_ratio": 0.0,
        "ddos_peak_flow_rps": 0.0,
    }


def _summarize_ddos_rows(rows: List[NetEventDB]) -> dict[str, Any]:
    summary = _empty_ddos_summary()
    samples = 0
    packets = 0
    peak_pps = 0.0
    peak_bps = 0.0
    peak_syn = 0.0
    peak_flow_rps = 0.0

    for row in rows:
        extra = dict(row.extra or {})
        pps = float(extra.get("pps") or 0.0)
        bps = float(extra.get("bps") or 0.0)
        syn_ratio = float(extra.get("tcp_syn_ratio") or 0.0)
        flow_rps = float(extra.get("http_rps") or extra.get("tls_handshake_rps") or 0.0)
        packet_count = int(extra.get("packets") or row.bytes or 0)
        packets += max(0, packet_count)
        peak_pps = max(peak_pps, max(0.0, pps))
        peak_bps = max(peak_bps, max(0.0, bps))
        peak_syn = max(peak_syn, max(0.0, syn_ratio))
        peak_flow_rps = max(peak_flow_rps, max(0.0, flow_rps))
        if any(value > 0 for value in (pps, bps, syn_ratio, flow_rps, packet_count)):
            samples += 1

    summary["ddos_packets_estimated"] = int(max(0, packets))
    summary["ddos_samples"] = int(max(0, samples))
    summary["ddos_peak_pps"] = float(max(0.0, peak_pps))
    summary["ddos_peak_bps"] = float(max(0.0, peak_bps))
    summary["ddos_peak_syn_ratio"] = float(max(0.0, peak_syn))
    summary["ddos_peak_flow_rps"] = float(max(0.0, peak_flow_rps))
    return summary


def get_recent_events(
    db: Session,
    *,
    limit: int = 50,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    since_minutes: Optional[int] = None,
) -> List[NetEventDB]:
    since_ts = None
    if since_minutes is not None:
        since_ts = datetime.now(timezone.utc) - timedelta(minutes=max(1, int(since_minutes)))

    feed_rows = fetch_recent_feed_events(limit=min(max(int(limit), 1), 200), agent_id=agent_id, event_type=event_type)
    feed_events = [ev for ev in (_feed_row_to_event(r) for r in feed_rows) if ev is not None]
    if since_ts is not None:
        feed_events = [ev for ev in feed_events if ev.timestamp >= since_ts]

    ch = _ch_client_or_none()
    if ch is not None:
        try:
            table = clickhouse_events_table_ref()
            where_sql, params = _ch_where(since=since_ts, agent_id=agent_id, event_type=event_type)
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
                    if _pg_has_newer_event(db, latest_ts=out[0].timestamp, agent_id=agent_id, event_type=event_type):
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
                        "filter": _es_base_filters(since=since_ts, agent_id=agent_id, event_type=event_type),
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
            if out and _es_failover_allowed() and not route_trusts_es():
                if _pg_has_newer_event(db, latest_ts=out[0].timestamp, agent_id=agent_id, event_type=event_type):
                    raise LookupError("es_stale_recent")
            return _merge_recent_events(primary=feed_events, secondary=out, limit=int(limit))
        except Exception as e:
            if not _es_failover_allowed():
                raise HTTPException(status_code=503, detail=f"Elasticsearch error: {type(e).__name__}") from None

    # Postgres fallback
    # Deterministic ordering avoids flicker when many events share the same timestamp.
    stmt = select(NetEventModel).order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
    if agent_id:
        stmt = stmt.where(NetEventModel.agent_id == agent_id)
    if event_type:
        stmt = stmt.where(NetEventModel.event_type == event_type)
    if since_ts is not None:
        stmt = stmt.where(NetEventModel.timestamp >= since_ts)
    stmt = stmt.limit(int(limit))

    result = repository.run(db, stmt)
    rows = result.scalars().all()
    pg_events: List[NetEventDB] = []
    for row in rows:
        event = _event_obj_to_event_safe(row)
        if event is None:
            continue
        if since_ts is not None and event.timestamp < since_ts:
            continue
        pg_events.append(event)
    return _merge_recent_events(primary=feed_events, secondary=pg_events, limit=int(limit))


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
    # Deferred import to avoid circular dependency with service.py.
    from app.features.events.service import hunt_events

    lookback_minutes = since_minutes if since_minutes is not None else window_minutes
    if search:
        page = hunt_events(
            db,
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
        db,
        limit=limit,
        agent_id=agent_id,
        event_type=event_type,
        since_minutes=lookback_minutes,
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
    # Deferred import to avoid circular dependency with service.py.
    from app.features.events.service import hunt_events

    started = time.perf_counter()
    window_minutes = max(1, int(since_minutes or 60))

    if search and str(search).strip():
        page = hunt_events(
            db,
            page_size=limit,
            cursor=None,
            agent_id=agent_id,
            event_type=event_type,
            since_minutes=window_minutes,
            start_ts_iso=None,
            end_ts_iso=None,
            search=search,
        )
        return EventStreamSnapshotResponse(
            generated_at=datetime.now(timezone.utc),
            window_minutes=window_minutes,
            agent_id=agent_id,
            event_type=event_type,
            search=search,
            items=page.items,
            next_cursor=page.next_cursor,
            has_more=page.has_more,
            meta=page.meta,
        )

    rows = get_recent_events_view(
        db,
        limit=limit,
        agent_id=agent_id,
        event_type=event_type,
        search=None,
        since_minutes=window_minutes,
        window_minutes=None,
    )
    next_cursor, has_more = _next_cursor_for_rows(rows, limit=limit)
    return EventStreamSnapshotResponse(
        generated_at=datetime.now(timezone.utc),
        window_minutes=window_minutes,
        agent_id=agent_id,
        event_type=event_type,
        search=None,
        items=rows,
        next_cursor=next_cursor,
        has_more=has_more,
        meta=_build_recent_feed_meta(agent_id=agent_id, started=started, window_minutes=window_minutes),
    )


def get_ddos_live_snapshot(
    db: Session,
    *,
    limit: int = 200,
    agent_id: str | None = None,
    since_minutes: int = 60 * 12,
) -> DdosLiveSnapshotResponse:
    started = time.perf_counter()
    lookback_minutes = max(1, int(since_minutes))

    live_rows = _ddos_events_only(
        get_recent_events(
            db,
            limit=max(limit * 2, limit),
            agent_id=agent_id,
            event_type=None,
            since_minutes=lookback_minutes,
        )
    )

    rows = live_rows[: max(1, int(limit))]
    next_cursor, has_more = _next_cursor_for_rows(rows, limit=limit)

    try:
        pressure = get_storm_status()
    except Exception:
        pressure = None

    pressure_payload: dict[str, Any] = {}
    if isinstance(pressure, dict):
        pressure_payload = {
            "active": bool(pressure.get("active")),
            "protection_active": bool(pressure.get("active")),
            "phase": str(pressure.get("phase") or "ok"),
            "reason": str(pressure.get("reason") or "ok"),
            "backlog_events": int(max(0, int(pressure.get("backlog_events") or 0))),
            "backlog_messages": int(max(0, int(pressure.get("backlog_messages") or 0))),
        }

    return DdosLiveSnapshotResponse(
        generated_at=datetime.now(timezone.utc),
        since_minutes=lookback_minutes,
        agent_id=agent_id,
        items=rows,
        next_cursor=next_cursor,
        has_more=has_more,
        meta=_build_recent_feed_meta(agent_id=agent_id, started=started, window_minutes=lookback_minutes),
        live_summary=_summarize_ddos_rows(rows),
        pressure=pressure_payload,
    )
