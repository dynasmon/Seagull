from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from app.core.messaging import EVENTS_INDEX_TOPIC, get_producer
from app.core.observability import incr_counter, log_event
from app.features.ingest.event_log import (
    dual_write_enabled,
    dual_write_result_callback,
    record_producer_unavailable,
)

from .config import WorkerConfig

logger = logging.getLogger("seagull.worker.ingest")

_DOC_KEYS = (
    "agent_id",
    "event_type",
    "schema_version",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "bytes",
)


def _row_to_stream_event(row: Dict[str, Any], pg_event_id: int) -> Dict[str, Any]:
    ts = row.get("timestamp")
    ts_out = ts.isoformat() if isinstance(ts, datetime) else (str(ts) if ts is not None else None)
    extra = row.get("extra")
    if not isinstance(extra, dict):
        extra = {}
    event: Dict[str, Any] = {"id": int(pg_event_id), "timestamp": ts_out, "extra": extra}
    for key in _DOC_KEYS:
        event[key] = row.get(key)
    return event


def _publish_redis_stream(r: Any, events: List[Dict[str, Any]], cfg: WorkerConfig) -> bool:
    try:
        pipe = r.pipeline()
        for event in events:
            pipe.xadd(
                cfg.es_stream_key,
                {"event": json.dumps(event, ensure_ascii=False, default=str)},
                maxlen=cfg.es_stream_maxlen,
                approximate=True,
            )
        pipe.execute()
        return True
    except Exception as exc:
        incr_counter(
            "ingest_optional_sink_dropped_total",
            value=float(len(events)),
            sink="es_stream",
            reason="xadd_error",
        )
        log_event(
            logger,
            "warning",
            "ingest_es_stream_publish_error",
            error_type=type(exc).__name__,
            rows=len(events),
        )
        return False


def _publish_redpanda(events: List[Dict[str, Any]], *, redis_ok: bool) -> int:
    if not dual_write_enabled() or not events:
        return 0

    producer = get_producer()
    if producer is None:
        record_producer_unavailable(stream="events_index", redis_ok=redis_ok, count=len(events))
        return 0

    on_result = dual_write_result_callback(stream="events_index", redis_ok=redis_ok)
    published = 0
    for event in events:
        if producer.publish(
            EVENTS_INDEX_TOPIC,
            key=str(event.get("agent_id") or ""),
            event=event,
            on_result=on_result,
        ):
            published += 1
    return published


def publish_index_events(r: Any, rows: List[Dict[str, Any]], cfg: WorkerConfig) -> int:
    if not rows:
        return 0

    events: List[Dict[str, Any]] = []
    for row in rows:
        pg_event_id = row.get("pg_event_id")
        if not pg_event_id:
            continue
        events.append(_row_to_stream_event(row, int(pg_event_id)))

    if not events:
        return 0

    redis_ok = r is not None and _publish_redis_stream(r, events, cfg)
    _publish_redpanda(events, redis_ok=redis_ok)
    return len(events) if redis_ok else 0
