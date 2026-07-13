from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.core.config.env_secrets import env_value, getenv_compat
from app.core.messaging import (
    EVENTS_INDEX_DLQ_TOPIC,
    EVENTS_INDEX_TOPIC,
    build_consumer,
    decode_message_event,
    get_producer,
    report_consumer_lag,
)
from app.core.observability import incr_counter, init_counter, log_event, observe_hist, setup_logging
from app.shared.indexing.es_doc import build_event_doc
from app.workers.indexing.es_bootstrap import ESConfig, bootstrap, load_config
from app.workers.indexing.es_stream import (
    _build_es_client,
    _is_permanent,
    _observe_lag,
    _parse_bulk_errors,
    _run_bulk,
)

setup_logging("worker-es-indexer-redpanda")
logger = logging.getLogger("seagull.worker.es_indexer_redpanda")


def _env_str(name: str, default: str) -> str:
    return env_value(name, default) or default


def _env_int(name: str, default: int) -> int:
    raw = getenv_compat(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip(), 10)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = getenv_compat(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


@dataclass(frozen=True)
class ESRedpandaConfig:
    topic: str
    dlq_topic: str
    group: str
    batch_size: int
    poll_timeout_seconds: float
    max_retries: int
    retry_backoff_seconds: float
    retry_backoff_max_seconds: float
    housekeeping_seconds: float


def load_redpanda_config() -> ESRedpandaConfig:
    return ESRedpandaConfig(
        topic=_env_str("SEAGULL_ES_REDPANDA_TOPIC", EVENTS_INDEX_TOPIC),
        dlq_topic=_env_str("SEAGULL_ES_REDPANDA_DLQ_TOPIC", EVENTS_INDEX_DLQ_TOPIC),
        group=_env_str("SEAGULL_ES_REDPANDA_GROUP", "es-indexer"),
        batch_size=min(5000, max(1, _env_int("SEAGULL_ES_REDPANDA_BATCH_SIZE", 500))),
        poll_timeout_seconds=min(60.0, max(0.1, _env_float("SEAGULL_ES_REDPANDA_POLL_TIMEOUT_SECONDS", 5.0))),
        max_retries=max(1, _env_int("SEAGULL_ES_REDPANDA_MAX_RETRIES", 5)),
        retry_backoff_seconds=max(0.05, _env_float("SEAGULL_ES_REDPANDA_RETRY_BACKOFF_SECONDS", 0.5)),
        retry_backoff_max_seconds=max(1.0, _env_float("SEAGULL_ES_REDPANDA_RETRY_BACKOFF_MAX_SECONDS", 15.0)),
        housekeeping_seconds=max(1.0, _env_float("SEAGULL_ES_REDPANDA_HOUSEKEEPING_SECONDS", 5.0)),
    )


@dataclass
class _Entry:
    event: Dict[str, Any]
    partition: int
    offset: int


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _consume_entries(consumer: Any, cfg: ESRedpandaConfig) -> List[_Entry]:
    messages = consumer.consume(num_messages=cfg.batch_size, timeout=cfg.poll_timeout_seconds) or []
    entries: List[_Entry] = []
    for msg in messages:
        err = msg.error()
        if err is not None:
            if not err.retriable():
                log_event(logger, "warning", "es_redpanda_message_error", error=str(err))
            continue
        event = decode_message_event(msg.value())
        entry = _Entry(event=event or {}, partition=int(msg.partition()), offset=int(msg.offset()))
        if event is None:
            incr_counter("es_indexer_dlq_total", reason="decode_error")
            _publish_dlq(cfg, entry, reason="decode_error", error="undecodable message", doc_id="")
            continue
        entries.append(entry)
    if messages:
        incr_counter(
            "redpanda_consumer_msgs_total",
            value=float(len(messages)),
            topic=cfg.topic,
            group=cfg.group,
        )
    return entries


def _publish_dlq(cfg: ESRedpandaConfig, entry: _Entry, *, reason: str, error: str, doc_id: str) -> None:
    producer = get_producer()
    if producer is None:
        log_event(logger, "error", "es_redpanda_dlq_producer_unavailable", reason=reason, doc_id=doc_id)
        return
    dlq_event = dict(entry.event)
    dlq_event["_dlq"] = {
        "reason": reason,
        "error": error[:300],
        "doc_id": doc_id,
        "source_topic": cfg.topic,
        "source_partition": entry.partition,
        "source_offset": entry.offset,
        "failed_at": _now_iso(),
    }
    producer.publish(
        cfg.dlq_topic,
        key=str(entry.event.get("agent_id") or ""),
        event=dlq_event,
    )


def _bulk_attempt(
    *,
    es: Any,
    es_cfg: ESConfig,
    cfg: ESRedpandaConfig,
    entries: List[_Entry],
) -> Tuple[List[_Entry], bool]:
    actions: List[Dict[str, Any]] = []
    by_docid: Dict[str, _Entry] = {}
    now_epoch = time.time()

    for entry in entries:
        doc = build_event_doc(entry.event)
        doc_id = doc.get("id")
        if doc_id is None:
            incr_counter("es_indexer_dlq_total", reason="missing_id")
            _publish_dlq(cfg, entry, reason="missing_id", error="event has no id", doc_id="")
            continue
        did = str(doc_id)
        actions.append({"_op_type": "index", "_index": es_cfg.write_alias, "_id": did, "_source": doc})
        by_docid[did] = entry

    if not actions:
        return [], False

    try:
        _success, raw_errors = _run_bulk(es, actions, es_cfg.request_timeout_seconds)
        failed = _parse_bulk_errors(raw_errors)
        unreachable = False
    except Exception as exc:
        failed = {did: (503, type(exc).__name__) for did in by_docid}
        unreachable = True
        incr_counter("es_indexer_bulk_error_total", reason="unreachable", value=float(len(by_docid)))
        log_event(logger, "warning", "es_redpanda_bulk_exception", error=type(exc).__name__, docs=len(by_docid))

    transient: List[_Entry] = []
    indexed = 0

    for did, entry in by_docid.items():
        if did not in failed:
            indexed += 1
            _observe_lag(entry.event, now_epoch)
            continue

        status, reason = failed[did]
        if not unreachable and _is_permanent(status):
            incr_counter("es_indexer_bulk_error_total", reason="permanent")
            incr_counter("es_indexer_dlq_total", reason="permanent")
            _publish_dlq(cfg, entry, reason=f"permanent_{status}", error=reason, doc_id=did)
            continue

        if not unreachable:
            incr_counter("es_indexer_bulk_error_total", reason="transient")
        transient.append(entry)

    if indexed:
        incr_counter("es_indexer_bulk_success_total", value=float(indexed))
    return transient, unreachable


def _keepalive_backoff(consumer: Any, seconds: float) -> None:
    partitions = consumer.assignment() or []
    if partitions:
        consumer.pause(partitions)
    try:
        deadline = time.monotonic() + max(0.0, seconds)
        while time.monotonic() < deadline:
            consumer.poll(min(1.0, max(0.05, deadline - time.monotonic())))
    finally:
        if partitions:
            consumer.resume(partitions)


def _process_batch(
    *,
    consumer: Any,
    es: Any,
    es_cfg: ESConfig,
    cfg: ESRedpandaConfig,
    entries: List[_Entry],
) -> None:
    pending = entries
    attempts = 0
    backoff = cfg.retry_backoff_seconds

    while pending:
        pending, unreachable = _bulk_attempt(es=es, es_cfg=es_cfg, cfg=cfg, entries=pending)
        if not pending:
            break

        if not unreachable:
            attempts += 1
            if attempts >= cfg.max_retries:
                for entry in pending:
                    incr_counter("es_indexer_dlq_total", reason="max_retries")
                    doc_id = str(entry.event.get("id") or "")
                    _publish_dlq(cfg, entry, reason="max_retries", error="transient failures exhausted", doc_id=doc_id)
                pending = []
                break

        log_event(
            logger,
            "warning",
            "es_redpanda_batch_retry",
            pending=len(pending),
            attempts=attempts,
            unreachable=unreachable,
            backoff_seconds=round(backoff, 3),
        )
        _keepalive_backoff(consumer, backoff)
        backoff = min(backoff * 2.0, cfg.retry_backoff_max_seconds)

    producer = get_producer()
    if producer is not None:
        producer.flush(10.0)
    consumer.commit(asynchronous=False)


def run(
    *,
    consumer: Any,
    es: Any,
    es_cfg: ESConfig,
    cfg: ESRedpandaConfig,
    bootstrap_enabled: bool,
    ping: bool = True,
    max_iterations: Optional[int] = None,
) -> None:
    for name in ("permanent", "transient", "unreachable"):
        init_counter("es_indexer_bulk_error_total", reason=name)
    for name in ("permanent", "max_retries", "missing_id", "decode_error"):
        init_counter("es_indexer_dlq_total", reason=name)

    bootstrap_done = not bootstrap_enabled
    backoff = 1.0
    last_housekeeping = 0.0
    iterations = 0

    while max_iterations is None or iterations < max_iterations:
        iterations += 1
        try:
            if ping and not es.ping():
                raise RuntimeError("elasticsearch_ping_failed")

            if not bootstrap_done:
                bootstrap(es, es_cfg)
                bootstrap_done = True

            now = time.monotonic()
            if now - last_housekeeping >= cfg.housekeeping_seconds:
                last_housekeeping = now
                report_consumer_lag(consumer, group_id=cfg.group)

            entries = _consume_entries(consumer, cfg)
            if not entries:
                backoff = 1.0
                continue

            incr_counter("es_indexer_events_consumed_total", value=float(len(entries)))
            batch_started = time.perf_counter()
            _process_batch(consumer=consumer, es=es, es_cfg=es_cfg, cfg=cfg, entries=entries)
            observe_hist(
                "redpanda_consumer_batch_seconds",
                time.perf_counter() - batch_started,
                topic=cfg.topic,
                group=cfg.group,
            )
            backoff = 1.0

        except Exception as exc:
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "es_redpanda_loop_error", wait_s=wait_s, error=repr(exc))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)


def main() -> None:
    settings.validate_for_service("worker-es-indexer-redpanda")
    es_cfg = load_config()
    cfg = load_redpanda_config()

    consumer = build_consumer(
        group_id=cfg.group,
        client_id="seagull-es-indexer-redpanda",
        topics=[cfg.topic],
    )
    es = _build_es_client(es_cfg)
    log_event(
        logger,
        "info",
        "es_redpanda_indexer_starting",
        topic=cfg.topic,
        group=cfg.group,
        brokers=settings.SEAGULL_REDPANDA_BROKERS,
        write_alias=es_cfg.write_alias,
        batch_size=cfg.batch_size,
    )
    run(consumer=consumer, es=es, es_cfg=es_cfg, cfg=cfg, bootstrap_enabled=es_cfg.bootstrap)


if __name__ == "__main__":
    main()
