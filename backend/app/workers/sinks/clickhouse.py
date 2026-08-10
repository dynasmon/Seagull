from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.integrations.clickhouse import (
    ensure_clickhouse_events_schema,
    get_clickhouse_client,
    reset_clickhouse_client,
)
from app.core.observability import log_event
from app.features.events.worker_runtime import write_clickhouse_events
from app.features.ingest.control.service import record_clickhouse_progress, set_clickhouse_state
from app.shared.indexing.watermark import write_clickhouse_watermark
from app.shared.outbox.models import SINK_CLICKHOUSE
from app.workers.sinks.config import DispatcherConfig
from app.workers.sinks.delivery import DeliveryResult, delivered, retry_all

logger = logging.getLogger("seagull.worker.sinks")


def _record_watermark(events: List[Dict[str, Any]]) -> None:
    max_id = 0
    max_ts: Optional[datetime] = None
    for event in events:
        try:
            event_id = int(event.get("pg_event_id") or 0)
        except (TypeError, ValueError):
            event_id = 0
        if event_id > max_id:
            max_id = event_id
        timestamp = event.get("timestamp")
        if isinstance(timestamp, datetime) and (max_ts is None or timestamp > max_ts):
            max_ts = timestamp
    if max_ts is None:
        return
    write_clickhouse_watermark(max_pg_event_id=max_id, max_ts=max_ts)


class ClickHouseDelivery:
    sink = SINK_CLICKHOUSE

    def __init__(self, cfg: DispatcherConfig) -> None:
        self.cfg = cfg
        self._client: Any = None
        self._next_connect_at = 0.0

    def _connect(self) -> Any:
        if self._client is not None:
            return self._client
        if time.monotonic() < self._next_connect_at:
            return None
        try:
            client = get_clickhouse_client()
            if not ensure_clickhouse_events_schema():
                raise RuntimeError("clickhouse_schema_unavailable")
        except Exception as exc:
            self._disconnect()
            set_clickhouse_state(state="degraded", error_type=type(exc).__name__)
            return None
        self._client = client
        return client

    def _disconnect(self) -> None:
        self._client = None
        self._next_connect_at = time.monotonic() + self.cfg.clickhouse_reconnect_seconds
        reset_clickhouse_client()

    def deliver(self, events: List[Dict[str, Any]], *, batch_id: int) -> DeliveryResult:
        client = self._connect()
        if client is None:
            return retry_all(events, error="clickhouse_unavailable")

        try:
            written = write_clickhouse_events(
                ch_client=client,
                hot_rows=events,
                dedup_token=f"outbox:{int(batch_id)}",
            )
        except Exception as exc:
            self._disconnect()
            set_clickhouse_state(state="degraded", error_type=type(exc).__name__)
            log_event(
                logger,
                "warning",
                "sink_clickhouse_write_error",
                error_type=type(exc).__name__,
                batch_id=int(batch_id),
                events=len(events),
            )
            return retry_all(events, error=type(exc).__name__)

        record_clickhouse_progress(rows=written)
        _record_watermark(events)
        set_clickhouse_state(state="available")
        return delivered(written)
