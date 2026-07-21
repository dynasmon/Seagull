from __future__ import annotations

import json
import logging
from typing import Any

from app.core.observability import incr_counter, log_event

from .config import WorkerConfig

logger = logging.getLogger("seagull.worker.ingest")

_DEADLETTER_MAX_MESSAGES = 200
_DEADLETTER_TTL_SECONDS = 7 * 86400


def _deadletter_key(cfg: WorkerConfig) -> str:
    return f"{cfg.queue_key}:deadletter"


def _push_deadletter(r: Any, cfg: WorkerConfig, payload: Any) -> None:
    try:
        key = _deadletter_key(cfg)
        pipe = r.pipeline()
        pipe.rpush(key, payload)
        pipe.ltrim(key, -_DEADLETTER_MAX_MESSAGES, -1)
        pipe.expire(key, _DEADLETTER_TTL_SECONDS)
        pipe.execute()
    except Exception:
        return


def _decr_backlog_events(r: Any, received: int) -> None:

    if r is None:
        return

    try:
        key = cfg_queue_backlog_key()
        new_v = r.decrby(key, int(received))
        try:
            vv = int(new_v)
            if vv < 0:
                r.set(key, 0)
        except Exception:
            pass
    except Exception:
        return


def cfg_queue_backlog_key() -> str:
    from app.core.config.env_secrets import env_value

    return env_value("SEAGULL_INGEST_BACKLOG_EVENTS_KEY", "seagull:ingest:backlog_events") or "seagull:ingest:backlog_events"


def _requeue_processing(r: Any, cfg: WorkerConfig) -> None:

    if r is None:
        return

    try:
        while True:
            item = r.rpoplpush(cfg.processing_key, cfg.queue_key)
            if not item:
                break
    except Exception:
        return


def _requeue_processing_with_retry_cap(r: Any, cfg: WorkerConfig) -> None:

    if r is None:
        return

    max_retries = max(1, _load_max_retries())

    try:
        while True:
            raw = r.rpop(cfg.processing_key)
            if not raw:
                break

            received = 0
            retry_n = 0
            try:
                msg = json.loads(raw)
                received = max(0, int(msg.get("received") or 0))
                retry_n = max(0, int(msg.get("_retry_count") or 0)) + 1
                msg["_retry_count"] = retry_n
                payload = json.dumps(msg, separators=(",", ":"), ensure_ascii=False)
            except Exception:
                payload = None

            if payload is not None and retry_n <= max_retries:
                r.lpush(cfg.queue_key, payload)
                continue

            if received > 0:
                _decr_backlog_events(r, received)
            incr_counter("ingest_deadletter_messages_total")
            _push_deadletter(r, cfg, payload if payload is not None else raw)
            log_event(
                logger,
                "warning",
                "ingest_deadletter_message",
                retries=retry_n,
                received=received,
            )
    except Exception:
        return


def _load_max_retries() -> int:
    from app.core.config.env_secrets import getenv_compat

    raw = getenv_compat("SEAGULL_INGEST_WORKER_MAX_MESSAGE_RETRIES")
    if raw is None:
        return 4
    try:
        return int(raw.strip() or "4", 10)
    except Exception:
        return 4
