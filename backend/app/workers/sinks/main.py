from __future__ import annotations

import logging
import signal
import threading
import time
from typing import List

from app.core.config import settings
from app.core.db.lifecycle import ensure_database_ready
from app.core.observability import init_counter, log_event, setup_logging
from app.shared.outbox.models import SINK_CLICKHOUSE, SINK_SEARCH, SINK_WARM
from app.workers.indexing.es_bootstrap import load_config as load_es_config
from app.workers.sinks.clickhouse import ClickHouseDelivery
from app.workers.sinks.config import DispatcherConfig, load_dispatcher_config
from app.workers.sinks.delivery import SinkDelivery
from app.workers.sinks.dispatcher import OutboxDispatcher, build_dispatchers, purge_dead_letters
from app.workers.sinks.elasticsearch import build_search_delivery, build_warm_delivery

setup_logging("worker-sink-dispatcher")
logger = logging.getLogger("seagull.worker.sinks")

_PURGE_INTERVAL_SECONDS = 3600.0


def build_deliveries(cfg: DispatcherConfig) -> List[SinkDelivery]:
    deliveries: List[SinkDelivery] = []
    if cfg.clickhouse_enabled:
        deliveries.append(ClickHouseDelivery(cfg))
    if cfg.warm_enabled or cfg.search_enabled:
        es_cfg = load_es_config()
        if cfg.warm_enabled:
            deliveries.append(build_warm_delivery(es_cfg=es_cfg, cfg=cfg))
        if cfg.search_enabled:
            deliveries.append(build_search_delivery(es_cfg=es_cfg))
    return deliveries


def _init_counters() -> None:
    for sink in (SINK_CLICKHOUSE, SINK_WARM, SINK_SEARCH):
        init_counter("sink_outbox_delivered_total", sink=sink)
        init_counter("sink_outbox_retry_total", sink=sink)
        for reason in ("rejected", "max_attempts"):
            init_counter("sink_outbox_dead_letter_total", sink=sink, reason=reason)


def _install_signal_handlers(stop: threading.Event) -> None:
    def _handler(signum: int, _frame: object) -> None:
        log_event(logger, "info", "sink_dispatcher_signal", signal=signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


def _housekeeping(dispatchers: List[OutboxDispatcher], cfg: DispatcherConfig, stop: threading.Event) -> None:
    next_purge = 0.0
    while not stop.is_set():
        now = time.monotonic()
        if now >= next_purge:
            next_purge = now + _PURGE_INTERVAL_SECONDS
            try:
                purged = purge_dead_letters(retention_days=cfg.dead_letter_retention_days)
                if purged:
                    log_event(logger, "info", "sink_dead_letter_purged", rows=purged)
            except Exception as exc:
                log_event(logger, "warning", "sink_dead_letter_purge_failed", error=repr(exc))
        stop.wait(5.0)
    for dispatcher in dispatchers:
        try:
            dispatcher.publish_stats()
        except Exception:
            continue


def main() -> None:
    settings.validate_for_service("worker-sinks")
    cfg = load_dispatcher_config()
    deliveries = build_deliveries(cfg)

    if not deliveries:
        log_event(logger, "error", "sink_dispatcher_no_sinks_enabled")
        return

    ensure_database_ready()
    _init_counters()

    dispatchers = build_dispatchers(deliveries, cfg)
    stop = threading.Event()
    _install_signal_handlers(stop)

    log_event(
        logger,
        "info",
        "sink_dispatcher_starting",
        sinks=[dispatcher.sink for dispatcher in dispatchers],
        claim_batches=cfg.claim_batches,
        max_attempts=cfg.max_attempts,
    )

    threads = [
        threading.Thread(target=dispatcher.run, args=(stop,), name=f"sink-{dispatcher.sink}", daemon=True)
        for dispatcher in dispatchers
    ]
    for thread in threads:
        thread.start()

    _housekeeping(dispatchers, cfg, stop)

    for thread in threads:
        thread.join(timeout=15.0)
    log_event(logger, "info", "sink_dispatcher_stopped")


if __name__ == "__main__":
    main()
