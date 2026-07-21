
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.cache import get_blocking_redis
from app.core.config import settings
from app.core.db import engine
from app.core.db.lifecycle import ensure_database_ready
from app.core.observability import incr_counter, init_counter, log_event, observe_hist, set_gauge, setup_logging
from app.features.events.rollup_keys import (
    rollup_agent_id,
    rollup_dst_ip,
    rollup_dst_port,
    rollup_event_type,
    rollup_proto,
)
from app.features.ingest.control.service import (
    get_storm_status,
    record_worker_progress,
    storm_maybe_close_alert,
    storm_maybe_open_alert,
    worker_heartbeat,
)

from .config import load_config
from .es_stream_producer import publish_index_events
from .hot_store import _insert_hot_rows_with_pg_ids
from .parser import _event_fingerprint, _event_from_wire
from .queue import _decr_backlog_events, _requeue_processing, _requeue_processing_with_retry_cap
from .rollup import upsert_rollups
from .sink_runtime import _OptionalSinkRuntime

setup_logging("worker-ingest")
logger = logging.getLogger("seagull.worker.ingest")


def _parse_rollup_row(rr: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(rr, (list, tuple)) or len(rr) < 8:
        return None
    try:
        bucket_ts = datetime.fromisoformat(rr[0])
    except Exception:
        bucket_ts = datetime.now(timezone.utc)
    if bucket_ts.tzinfo is None:
        bucket_ts = bucket_ts.replace(tzinfo=timezone.utc)
    try:
        count = max(0, int(rr[6] or 0))
    except Exception:
        count = 0
    try:
        bytes_sum = max(0, int(rr[7] or 0))
    except Exception:
        bytes_sum = 0
    return {
        "bucket_ts": bucket_ts,
        "agent_id": rollup_agent_id(rr[1]),
        "event_type": rollup_event_type(rr[2]),
        "dst_ip": rollup_dst_ip(rr[3]),
        "dst_port": rollup_dst_port(rr[4]),
        "proto": rollup_proto(rr[5]),
        "count": count,
        "bytes_sum": bytes_sum,
    }


def _parse_warm_doc(ev: List[Any]) -> Dict[str, Any] | None:
    agent_id = ev[0] if len(ev) > 0 else None
    event_type = ev[1] if len(ev) > 1 else None
    if not agent_id or not event_type:
        return None

    try:
        ts = datetime.fromisoformat(ev[3]) if (len(ev) > 3 and ev[3]) else datetime.utcnow()
    except Exception:
        ts = datetime.utcnow()

    try:
        schema_v = int(ev[2] or 1)
    except Exception:
        schema_v = 1

    bytes_v = ev[9] if (len(ev) > 9) else None
    try:
        bytes_v = int(bytes_v) if bytes_v is not None else 0
    except Exception:
        bytes_v = 0

    return {
        "agent_id": agent_id,
        "event_type": event_type,
        "schema_version": schema_v,
        "timestamp": ts,
        "src_ip": ev[4] if (len(ev) > 4 and ev[4]) else None,
        "dst_ip": ev[5] if (len(ev) > 5 and ev[5]) else None,
        "src_port": int(ev[6]) if (len(ev) > 6 and ev[6] is not None) else None,
        "dst_port": int(ev[7]) if (len(ev) > 7 and ev[7] is not None) else None,
        "proto": ev[8] if (len(ev) > 8 and ev[8]) else None,
        "bytes": bytes_v,
        "extra": ev[10] if (len(ev) > 10 and isinstance(ev[10], dict)) else {},
    }


def main() -> None:
    settings.validate_for_service("worker-ingest")
    init_counter("ingest_events_sampled_total")
    cfg = load_config()

    ensure_database_ready()

    r = get_blocking_redis()
    if r is None:
        log_event(logger, "error", "ingest_redis_unavailable")
        while True:
            time.sleep(2.0)

    _requeue_processing(r, cfg)
    worker_id = f"ingest-{uuid.uuid4().hex[:8]}"
    sink_runtime = _OptionalSinkRuntime(cfg=cfg, redis_client=r)
    sink_runtime.start()

    backoff = 0.25
    last_metrics_sample = 0.0
    last_commit_wall = time.time()

    while True:
        try:
            worker_heartbeat(worker_id)

            now_mono = time.monotonic()
            if now_mono - last_metrics_sample >= 5.0:
                last_metrics_sample = now_mono
                try:
                    set_gauge("ingest_queue_depth", int(r.llen(cfg.queue_key) or 0), queue="pending")
                    set_gauge("ingest_queue_depth", int(r.llen(cfg.processing_key) or 0), queue="processing")
                    set_gauge(
                        "ingest_hot_store_last_commit_age_seconds",
                        max(0.0, time.time() - last_commit_wall),
                    )
                    storm = get_storm_status()
                    phase = str(storm.get("phase") or "").lower()
                    set_gauge("ingest_storm_active", 1 if storm.get("active") else 0)
                    backpressured = bool(storm.get("active")) or (phase not in {"", "ok", "normal", "recovered"})
                    set_gauge("ingest_backpressure_active", 1 if backpressured else 0)
                except Exception:
                    pass

            item = r.brpoplpush(cfg.queue_key, cfg.processing_key, timeout=1)
            if not item:
                storm_maybe_close_alert()
                time.sleep(cfg.idle_sleep_seconds)
                continue

            items = [item]
            for _ in range(cfg.batch_messages - 1):
                nxt = r.rpoplpush(cfg.queue_key, cfg.processing_key)
                if not nxt:
                    break
                items.append(nxt)

            hot_rows: List[Dict[str, Any]] = []
            analytics_rows: List[Dict[str, Any]] = []
            rollup_rows: List[Dict[str, Any]] = []
            warm_docs: List[Dict[str, Any]] = []

            total_received = 0
            received_by_raw: Dict[str, int] = {}

            for raw in items:
                msg = json.loads(raw)
                received = int(msg.get("received") or 0)
                total_received += received
                received_by_raw[str(raw)] = received_by_raw.get(str(raw), 0) + max(0, int(received))

                try:
                    mode = str(msg.get("mode") or "normal")
                    pressure = bool(msg.get("storm_active")) or mode != "normal"
                    if pressure:
                        storm_maybe_open_alert(
                            reason=str(msg.get("storm_reason") or mode)[:64],
                            sample_hot=int(msg.get("sample_hot_percent") or 0),
                            sample_warm=int(msg.get("sample_warm_percent") or 0),
                        )
                except Exception:
                    pass

                for ev in msg.get("hot_events") or []:
                    row = _event_from_wire(ev)
                    if row is not None:
                        hot_rows.append(row)

                for ev in msg.get("analytics_events") or []:
                    row = _event_from_wire(ev)
                    if row is not None:
                        analytics_rows.append(row)

                for rr in msg.get("rollups") or []:
                    rollup_row = _parse_rollup_row(rr)
                    if rollup_row is not None:
                        rollup_rows.append(rollup_row)

                if cfg.warm_enabled:
                    for ev in msg.get("warm_events") or []:
                        doc = _parse_warm_doc(ev)
                        if doc is not None:
                            warm_docs.append(doc)

            inserted_hot_rows: List[Dict[str, Any]] = []
            hot_path_started = time.perf_counter()
            rollup_error: Optional[str] = None

            with engine.begin() as conn:
                if hot_rows:
                    inserted_hot_rows = _insert_hot_rows_with_pg_ids(conn, hot_rows)
                if rollup_rows:
                    try:
                        with conn.begin_nested():
                            upsert_rollups(conn, rollup_rows)
                    except Exception as rollup_exc:
                        rollup_error = type(rollup_exc).__name__

            if hot_rows or rollup_rows:
                last_commit_wall = time.time()
                set_gauge("ingest_hot_store_last_commit_age_seconds", 0.0)

            if rollup_error is not None:
                incr_counter("ingest_rollup_write_errors_total")
                log_event(
                    logger,
                    "warning",
                    "ingest_rollup_write_error",
                    error_type=rollup_error,
                    rollup_rows=len(rollup_rows),
                )

            hot_id_by_fp = {_event_fingerprint(row): int(row.get("pg_event_id") or 0) for row in inserted_hot_rows}
            analytics_rows_for_ch: List[Dict[str, Any]] = []
            if analytics_rows:
                seen_fp: set[str] = set()
                for row in analytics_rows:
                    fp = _event_fingerprint(row)
                    if fp in seen_fp:
                        continue
                    seen_fp.add(fp)
                    item = dict(row)
                    mapped_pg_id = hot_id_by_fp.get(fp)
                    if mapped_pg_id:
                        item["pg_event_id"] = mapped_pg_id
                    analytics_rows_for_ch.append(item)

            if analytics_rows_for_ch and not sink_runtime.enqueue_clickhouse(analytics_rows_for_ch):
                log_event(
                    logger,
                    "warning",
                    "ingest_clickhouse_enqueue_drop",
                    dropped_rows=len(analytics_rows_for_ch),
                )

            if warm_docs and not sink_runtime.enqueue_warm(warm_docs):
                log_event(
                    logger,
                    "warning",
                    "ingest_warm_enqueue_drop",
                    dropped_rows=len(warm_docs),
                )

            if cfg.es_stream_producer_enabled and inserted_hot_rows:
                publish_index_events(r, inserted_hot_rows, cfg)

            observe_hist("ingest_hot_path_latency_seconds", time.perf_counter() - hot_path_started)

            ack_ok = True
            removed_received = 0
            removed_messages = 0
            try:
                pipe = r.pipeline()
                for raw in items:
                    pipe.lrem(cfg.processing_key, 1, raw)
                results = pipe.execute() or []
                for raw, removed in zip(items, results, strict=False):
                    if int(removed or 0) > 0:
                        removed_received += received_by_raw.get(str(raw), 0)
                        removed_messages += 1
            except Exception:
                ack_ok = False
                for raw in items:
                    try:
                        removed = int(r.lrem(cfg.processing_key, 1, raw) or 0)
                        if removed > 0:
                            removed_received += received_by_raw.get(str(raw), 0)
                            removed_messages += 1
                    except Exception:
                        continue

            if removed_received > 0:
                _decr_backlog_events(r, removed_received)
                record_worker_progress(
                    processed_events=removed_received,
                    processed_messages=removed_messages,
                )
                incr_counter("ingest_batches_processed_total")
                incr_counter("ingest_events_processed_total", value=float(removed_received))
            elif ack_ok:
                _decr_backlog_events(r, total_received)
                record_worker_progress(processed_events=max(0, total_received), processed_messages=len(items))
                incr_counter("ingest_batches_processed_total")
                incr_counter("ingest_events_processed_total", value=float(max(0, total_received)))
            else:
                try:
                    plen = int(r.llen(cfg.processing_key) or 0)
                except Exception:
                    plen = -1
                try:
                    _requeue_processing_with_retry_cap(r, cfg)
                except Exception:
                    pass
                log_event(
                    logger,
                    "warning",
                    "ingest_ack_failed",
                    processing_len=plen,
                    removed_received=removed_received,
                    total_received=total_received,
                )

            storm_maybe_close_alert()
            backoff = 0.25

        except Exception as e:
            incr_counter("ingest_loop_errors_total")
            try:
                _requeue_processing_with_retry_cap(r, cfg)
            except Exception:
                pass

            col = getattr(getattr(e, "diag", None), "column_name", None)
            tbl = getattr(getattr(e, "diag", None), "table_name", None)
            msg = f"[INGEST] error={type(e).__name__}"
            if tbl or col:
                msg += f" table={tbl} column={col}"
            msg += f" backoff={backoff}"
            log_event(logger, "error", "ingest_loop_error", message=msg)
            time.sleep(backoff)
            backoff = min(5.0, backoff * 1.8)


if __name__ == "__main__":
    main()
