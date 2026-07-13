from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Sequence

from app.core.config import settings
from app.core.messaging import EVENTS_RAW_TOPIC, get_producer
from app.core.observability import incr_counter, init_counter, log_event

logger = logging.getLogger("seagull.ingest.event_log")

for _stream in ("events_raw", "events_index"):
    for _reason in ("redis_write_failed", "redpanda_write_failed", "producer_unavailable"):
        init_counter("ingest_dual_write_discrepancy_total", stream=_stream, reason=_reason)

_WIRE_FIELDS = (
    "agent_id",
    "event_type",
    "schema_version",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "bytes",
    "extra",
)


def dual_write_enabled() -> bool:
    return bool(settings.SEAGULL_REDPANDA_ENABLED and settings.SEAGULL_REDPANDA_DUAL_WRITE_ENABLED)


def dual_write_result_callback(*, stream: str, redis_ok: bool) -> Callable[[bool], None]:
    def _on_result(delivered: bool) -> None:
        if delivered and not redis_ok:
            incr_counter("ingest_dual_write_discrepancy_total", stream=stream, reason="redis_write_failed")
        elif redis_ok and not delivered:
            incr_counter("ingest_dual_write_discrepancy_total", stream=stream, reason="redpanda_write_failed")

    return _on_result


def record_producer_unavailable(*, stream: str, redis_ok: bool, count: int) -> None:
    if redis_ok and count > 0:
        incr_counter(
            "ingest_dual_write_discrepancy_total",
            value=float(count),
            stream=stream,
            reason="producer_unavailable",
        )


def wire_row_to_event(row: Sequence[Any]) -> Dict[str, Any]:
    return {field: (row[idx] if idx < len(row) else None) for idx, field in enumerate(_WIRE_FIELDS)}


def publish_raw_events(*, rows: Sequence[Sequence[Any]], redis_ok: bool) -> int:
    if not dual_write_enabled() or not rows:
        return 0

    producer = get_producer()
    if producer is None:
        record_producer_unavailable(stream="events_raw", redis_ok=redis_ok, count=len(rows))
        return 0

    on_result = dual_write_result_callback(stream="events_raw", redis_ok=redis_ok)
    published = 0
    try:
        for row in rows:
            event = wire_row_to_event(row)
            if producer.publish(
                EVENTS_RAW_TOPIC,
                key=str(event.get("agent_id") or ""),
                event=event,
                on_result=on_result,
            ):
                published += 1
    except Exception as exc:
        log_event(logger, "warning", "ingest_raw_event_publish_error", error=repr(exc), rows=len(rows))
    return published
