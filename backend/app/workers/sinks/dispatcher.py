from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import List

from app.core.db import engine
from app.core.observability import incr_counter, log_event, observe_hist, set_gauge
from app.features.ingest.control.service import record_sink_runtime_metric, set_sink_queue_depth
from app.shared.outbox import store
from app.shared.outbox.store import REASON_MAX_ATTEMPTS, REASON_REJECTED, OutboxBatch
from app.workers.sinks.config import DispatcherConfig
from app.workers.sinks.delivery import DeliveryResult, SinkDelivery

logger = logging.getLogger("seagull.worker.sinks")


class OutboxDispatcher:
    def __init__(self, *, delivery: SinkDelivery, cfg: DispatcherConfig) -> None:
        self.delivery = delivery
        self.cfg = cfg
        self.sink = delivery.sink
        self._last_stats = 0.0

    def drain_once(self) -> int:
        with engine.begin() as conn:
            batches = store.claim(
                conn,
                sink=self.sink,
                limit=self.cfg.claim_batches,
                lease_seconds=self.cfg.lease_seconds,
            )
        if not batches:
            return 0

        for batch in batches:
            started = time.perf_counter()
            result = self.delivery.deliver(batch.events, batch_id=batch.id)
            observe_hist(
                "sink_outbox_delivery_seconds",
                time.perf_counter() - started,
                sink=self.sink,
                outcome="ok" if result.complete else "error",
            )
            self._settle(batch, result)
        return len(batches)

    def _settle(self, batch: OutboxBatch, result: DeliveryResult) -> None:
        now = datetime.now(timezone.utc)
        exhausted = int(batch.attempts) >= int(self.cfg.max_attempts)

        with engine.begin() as conn:
            if result.dead:
                store.dead_letter(
                    conn,
                    batch=batch,
                    events=result.dead,
                    reason=REASON_REJECTED,
                    error=result.error,
                    now=now,
                )
            if result.retry and exhausted:
                store.dead_letter(
                    conn,
                    batch=batch,
                    events=result.retry,
                    reason=REASON_MAX_ATTEMPTS,
                    error=result.error,
                    now=now,
                )
            if result.retry and not exhausted:
                store.reschedule(
                    conn,
                    batch_id=batch.id,
                    events=result.retry,
                    available_at=now + timedelta(seconds=self.cfg.retry_delay_seconds(batch.attempts)),
                    error=result.error,
                )
            else:
                store.complete(conn, batch_ids=[batch.id])

        self._record_outcome(batch, result, exhausted=exhausted)

    def _record_outcome(self, batch: OutboxBatch, result: DeliveryResult, *, exhausted: bool) -> None:
        if result.delivered:
            incr_counter("sink_outbox_delivered_total", value=float(result.delivered), sink=self.sink)
            record_sink_runtime_metric(sink=self.sink, metric="processed_batches", value=1)
            record_sink_runtime_metric(sink=self.sink, metric="processed_events", value=result.delivered)

        if result.dead:
            self._record_dead_letter(len(result.dead), reason=REASON_REJECTED)
        if result.retry and exhausted:
            self._record_dead_letter(len(result.retry), reason=REASON_MAX_ATTEMPTS)
        if result.retry and not exhausted:
            incr_counter("sink_outbox_retry_total", value=float(len(result.retry)), sink=self.sink)
            record_sink_runtime_metric(sink=self.sink, metric="failed_batches", value=1)

        if not result.complete:
            log_event(
                logger,
                "warning",
                "sink_batch_not_settled",
                sink=self.sink,
                batch_id=batch.id,
                attempts=batch.attempts,
                delivered=result.delivered,
                retry=len(result.retry),
                dead=len(result.dead),
                error=result.error,
            )

    def _record_dead_letter(self, events: int, *, reason: str) -> None:
        incr_counter("sink_outbox_dead_letter_total", value=float(events), sink=self.sink, reason=reason)
        record_sink_runtime_metric(sink=self.sink, metric="dropped_batches", value=1)
        record_sink_runtime_metric(sink=self.sink, metric="dropped_events", value=events)
        log_event(logger, "error", "sink_events_dead_lettered", sink=self.sink, reason=reason, events=events)

    def publish_stats(self) -> None:
        with engine.begin() as conn:
            depth = store.depth(conn, sink=self.sink)
            dead_events = store.dead_letter_depth(conn, sink=self.sink)
        set_gauge("sink_outbox_pending_batches", float(depth.batches), sink=self.sink)
        set_gauge("sink_outbox_pending_events", float(depth.events), sink=self.sink)
        set_gauge("sink_outbox_oldest_age_seconds", depth.oldest_age_seconds, sink=self.sink)
        set_gauge("sink_outbox_dead_letter_events", float(dead_events), sink=self.sink)
        set_sink_queue_depth(sink=self.sink, depth=depth.events)

    def _maybe_publish_stats(self) -> None:
        now = time.monotonic()
        if now - self._last_stats < self.cfg.stats_interval_seconds:
            return
        self._last_stats = now
        self.publish_stats()

    def run(self, stop: threading.Event) -> None:
        backoff = 1.0
        while not stop.is_set():
            try:
                handled = self.drain_once()
                self._maybe_publish_stats()
                backoff = 1.0
            except Exception as exc:
                incr_counter("sink_outbox_loop_errors_total", sink=self.sink)
                log_event(logger, "error", "sink_dispatcher_loop_error", sink=self.sink, error=repr(exc))
                stop.wait(min(backoff, 15.0))
                backoff = min(backoff * 2.0, 15.0)
                continue
            if handled == 0:
                stop.wait(self.cfg.idle_sleep_seconds)


def purge_dead_letters(*, retention_days: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, int(retention_days)))
    with engine.begin() as conn:
        return store.purge_dead_letter(conn, older_than=cutoff)


def build_dispatchers(deliveries: List[SinkDelivery], cfg: DispatcherConfig) -> List[OutboxDispatcher]:
    return [OutboxDispatcher(delivery=delivery, cfg=cfg) for delivery in deliveries]
