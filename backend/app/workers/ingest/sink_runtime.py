from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

from app.core.integrations.clickhouse import reset_clickhouse_client
from app.core.observability import incr_counter, log_event, observe_hist
from app.features.ingest.control.service import record_sink_runtime_metric, set_sink_queue_depth

from .clickhouse_sink import (
    _record_clickhouse_progress,
    _record_clickhouse_watermark,
    _set_clickhouse_state,
    _try_bootstrap_clickhouse,
    _write_clickhouse_events,
)
from .config import WorkerConfig
from .warm_index import _build_es_client, _ensure_warm_ilm_and_template, _index_for, _to_doc

logger = logging.getLogger("seagull.worker.ingest")


@dataclass
class _SinkTask:
    payload: List[Dict[str, Any]]
    retries: int = 0
    enqueued_at: float = field(default_factory=time.monotonic)


class _OptionalSinkRuntime:
    def __init__(self, *, cfg: WorkerConfig, redis_client: Any) -> None:
        self.cfg = cfg
        self.r = redis_client
        self.clickhouse_q: queue.Queue[_SinkTask] = queue.Queue(maxsize=max(1, int(cfg.clickhouse_sink_queue_max_batches)))
        self.warm_q: queue.Queue[_SinkTask] = queue.Queue(maxsize=max(1, int(cfg.warm_sink_queue_max_batches)))
        self._stop = threading.Event()

    def start(self) -> None:
        if self.cfg.clickhouse_enabled:
            threading.Thread(target=self._clickhouse_loop, name="ingest-sink-clickhouse", daemon=True).start()
        else:
            _set_clickhouse_state(self.r, state="disabled")
            set_sink_queue_depth(sink="clickhouse", depth=0)

        if self.cfg.warm_enabled:
            threading.Thread(target=self._warm_loop, name="ingest-sink-warm", daemon=True).start()
        else:
            set_sink_queue_depth(sink="warm", depth=0)

    def enqueue_clickhouse(self, rows: List[Dict[str, Any]]) -> bool:
        if not self.cfg.clickhouse_enabled:
            return False
        return self._enqueue(queue_obj=self.clickhouse_q, sink="clickhouse", payload=rows)

    def enqueue_warm(self, rows: List[Dict[str, Any]]) -> bool:
        if not self.cfg.warm_enabled:
            return False
        return self._enqueue(queue_obj=self.warm_q, sink="warm", payload=rows)

    def _enqueue(self, *, queue_obj: queue.Queue[_SinkTask], sink: str, payload: List[Dict[str, Any]]) -> bool:
        if not payload:
            return True
        task = _SinkTask(payload=list(payload))
        try:
            queue_obj.put_nowait(task)
            q_depth = queue_obj.qsize()
            set_sink_queue_depth(sink=sink, depth=q_depth)
            record_sink_runtime_metric(sink=sink, metric="enqueued_batches", value=1)
            record_sink_runtime_metric(sink=sink, metric="enqueued_events", value=len(task.payload))
            observe_hist("ingest_optional_sink_queue_depth", float(q_depth), sink=sink)
            return True
        except queue.Full:
            record_sink_runtime_metric(sink=sink, metric="dropped_batches", value=1)
            record_sink_runtime_metric(sink=sink, metric="dropped_events", value=len(task.payload))
            set_sink_queue_depth(sink=sink, depth=queue_obj.qsize())
            incr_counter("ingest_optional_sink_dropped_total", value=float(len(task.payload)), sink=sink, reason="queue_full")
            log_event(logger, "warning", "ingest_optional_sink_queue_full", sink=sink, dropped_events=len(task.payload))
            return False

    def _requeue_or_drop(self, *, queue_obj: queue.Queue[_SinkTask], sink: str, task: _SinkTask) -> None:
        retries = int(task.retries or 0)
        if retries >= int(self.cfg.sink_max_batch_retries):
            record_sink_runtime_metric(sink=sink, metric="dropped_batches", value=1)
            record_sink_runtime_metric(sink=sink, metric="dropped_events", value=len(task.payload))
            incr_counter(
                "ingest_optional_sink_dropped_total",
                value=float(len(task.payload)),
                sink=sink,
                reason="max_retries",
            )
            log_event(
                logger,
                "warning",
                "ingest_optional_sink_drop_after_retry",
                sink=sink,
                retries=retries,
                dropped_events=len(task.payload),
            )
            return

        retry_task = _SinkTask(payload=list(task.payload), retries=retries + 1, enqueued_at=task.enqueued_at)
        try:
            queue_obj.put_nowait(retry_task)
            set_sink_queue_depth(sink=sink, depth=queue_obj.qsize())
        except queue.Full:
            record_sink_runtime_metric(sink=sink, metric="dropped_batches", value=1)
            record_sink_runtime_metric(sink=sink, metric="dropped_events", value=len(task.payload))
            incr_counter(
                "ingest_optional_sink_dropped_total",
                value=float(len(task.payload)),
                sink=sink,
                reason="retry_queue_full",
            )
            log_event(
                logger,
                "warning",
                "ingest_optional_sink_retry_queue_full",
                sink=sink,
                dropped_events=len(task.payload),
            )

    def _clickhouse_loop(self) -> None:
        ch = None
        next_retry_at = 0.0
        _set_clickhouse_state(self.r, state="degraded", error_type="starting")
        set_sink_queue_depth(sink="clickhouse", depth=0)

        while not self._stop.is_set():
            try:
                task = self.clickhouse_q.get(timeout=0.5)
            except queue.Empty:
                continue

            set_sink_queue_depth(sink="clickhouse", depth=self.clickhouse_q.qsize())
            started = time.perf_counter()
            try:
                if ch is None and time.monotonic() >= next_retry_at:
                    ch = _try_bootstrap_clickhouse()
                    if ch is None:
                        reset_clickhouse_client()
                        next_retry_at = time.monotonic() + self.cfg.clickhouse_reconnect_seconds
                        _set_clickhouse_state(self.r, state="degraded", error_type="unavailable")
                if ch is None:
                    self._requeue_or_drop(queue_obj=self.clickhouse_q, sink="clickhouse", task=task)
                    record_sink_runtime_metric(sink="clickhouse", metric="failed_batches", value=1)
                    continue

                written = _write_clickhouse_events(ch_client=ch, hot_rows=task.payload)
                _record_clickhouse_progress(self.r, rows=written)
                _record_clickhouse_watermark(task.payload)
                _set_clickhouse_state(self.r, state="available")
                record_sink_runtime_metric(sink="clickhouse", metric="processed_batches", value=1)
                record_sink_runtime_metric(sink="clickhouse", metric="processed_events", value=written)
                observe_hist("ingest_optional_sink_latency_seconds", time.perf_counter() - started, sink="clickhouse", outcome="ok")
            except Exception as exc:
                ch = None
                reset_clickhouse_client()
                next_retry_at = time.monotonic() + self.cfg.clickhouse_reconnect_seconds
                _set_clickhouse_state(self.r, state="degraded", error_type=type(exc).__name__)
                record_sink_runtime_metric(sink="clickhouse", metric="failed_batches", value=1)
                observe_hist(
                    "ingest_optional_sink_latency_seconds",
                    time.perf_counter() - started,
                    sink="clickhouse",
                    outcome="error",
                )
                log_event(
                    logger,
                    "warning",
                    "ingest_clickhouse_write_error",
                    error_type=type(exc).__name__,
                    batch_rows=len(task.payload),
                    retries=int(task.retries or 0),
                )
                self._requeue_or_drop(queue_obj=self.clickhouse_q, sink="clickhouse", task=task)
            finally:
                self.clickhouse_q.task_done()
                set_sink_queue_depth(sink="clickhouse", depth=self.clickhouse_q.qsize())

    def _warm_loop(self) -> None:
        es = None
        template_ready = False
        next_retry_at = 0.0
        set_sink_queue_depth(sink="warm", depth=0)

        while not self._stop.is_set():
            try:
                task = self.warm_q.get(timeout=0.5)
            except queue.Empty:
                continue

            set_sink_queue_depth(sink="warm", depth=self.warm_q.qsize())
            started = time.perf_counter()
            try:
                if es is None and time.monotonic() >= next_retry_at:
                    es = _build_es_client(self.cfg)
                    if not es.ping():
                        es = None
                        next_retry_at = time.monotonic() + 2.0
                        template_ready = False
                if es is None:
                    record_sink_runtime_metric(sink="warm", metric="failed_batches", value=1)
                    self._requeue_or_drop(queue_obj=self.warm_q, sink="warm", task=task)
                    continue
                if not template_ready:
                    _ensure_warm_ilm_and_template(es, self.cfg)
                    template_ready = True

                from elasticsearch import helpers

                actions: List[Dict[str, Any]] = []
                for wd in task.payload:
                    idx = _index_for(self.cfg.warm_index_prefix, wd["timestamp"])
                    actions.append({"_op_type": "index", "_index": idx, "_source": _to_doc(wd)})
                helpers.bulk(
                    es,
                    actions,
                    request_timeout=self.cfg.es_request_timeout_seconds,
                    raise_on_error=False,
                    raise_on_exception=False,
                )
                record_sink_runtime_metric(sink="warm", metric="processed_batches", value=1)
                record_sink_runtime_metric(sink="warm", metric="processed_events", value=len(task.payload))
                observe_hist("ingest_optional_sink_latency_seconds", time.perf_counter() - started, sink="warm", outcome="ok")
            except Exception as exc:
                record_sink_runtime_metric(sink="warm", metric="failed_batches", value=1)
                observe_hist("ingest_optional_sink_latency_seconds", time.perf_counter() - started, sink="warm", outcome="error")
                log_event(
                    logger,
                    "warning",
                    "ingest_warm_index_error",
                    error_type=type(exc).__name__,
                    batch_rows=len(task.payload),
                    retries=int(task.retries or 0),
                )
                es = None
                template_ready = False
                next_retry_at = time.monotonic() + 2.0
                self._requeue_or_drop(queue_obj=self.warm_q, sink="warm", task=task)
            finally:
                self.warm_q.task_done()
                set_sink_queue_depth(sink="warm", depth=self.warm_q.qsize())
