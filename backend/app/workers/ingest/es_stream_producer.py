from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from app.core.observability import incr_counter, log_event

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


def publish_index_events(r: Any, rows: List[Dict[str, Any]], cfg: WorkerConfig) -> int:
    if r is None or not rows:
        return 0

    published = 0
    try:
        pipe = r.pipeline()
        for row in rows:
            pg_event_id = row.get("pg_event_id")
            if not pg_event_id:
                continue
            event = _row_to_stream_event(row, int(pg_event_id))
            pipe.xadd(
                cfg.es_stream_key,
                {"event": json.dumps(event, ensure_ascii=False, default=str)},
                maxlen=cfg.es_stream_maxlen,
                approximate=True,
            )
            published += 1
        if published:
            pipe.execute()
        return published
    except Exception as exc:
        incr_counter("ingest_optional_sink_dropped_total", value=float(len(rows)), sink="es_stream", reason="xadd_error")
        log_event(
            logger,
            "warning",
            "ingest_es_stream_publish_error",
            error_type=type(exc).__name__,
            rows=len(rows),
        )
        return 0
