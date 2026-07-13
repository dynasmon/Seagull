from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from app.core.config import settings
from app.core.observability import incr_counter, log_event, observe_hist, service_name

from .topics import MESSAGE_SCHEMA_VERSION

logger = logging.getLogger("seagull.messaging.producer")

_LOCK = threading.Lock()
_PRODUCER: Optional["EventLogProducer"] = None
_PRODUCER_FAILED_AT: float = 0.0
_REBUILD_COOLDOWN_SECONDS = 30.0


def _build_confluent_producer(config: Mapping[str, Any]) -> Any:
    from confluent_kafka import Producer

    return Producer(dict(config))


def producer_config(client_id: str) -> Dict[str, Any]:
    return {
        "bootstrap.servers": settings.SEAGULL_REDPANDA_BROKERS,
        "client.id": client_id,
        "enable.idempotence": True,
        "compression.type": "zstd",
        "linger.ms": 5,
        "message.timeout.ms": max(1000, int(settings.SEAGULL_REDPANDA_PRODUCER_MESSAGE_TIMEOUT_MS)),
        "queue.buffering.max.messages": max(1000, int(settings.SEAGULL_REDPANDA_PRODUCER_QUEUE_MAX_MESSAGES)),
        "socket.keepalive.enable": True,
        "log.connection.close": False,
    }


def message_envelope(event: Mapping[str, Any], *, produced_at: Optional[str] = None) -> Dict[str, Any]:
    return {
        "schema_version": MESSAGE_SCHEMA_VERSION,
        "produced_at": produced_at or datetime.now(timezone.utc).isoformat(),
        "event": dict(event),
    }


def serialize_message(event: Mapping[str, Any], *, produced_at: Optional[str] = None) -> bytes:
    return json.dumps(
        message_envelope(event, produced_at=produced_at),
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


class EventLogProducer:
    def __init__(self, client_id: str) -> None:
        self._client_id = client_id
        self._producer = _build_confluent_producer(producer_config(client_id))
        self._closed = threading.Event()
        self._poll_thread = threading.Thread(target=self._poll_loop, name="redpanda-producer-poll", daemon=True)
        self._poll_thread.start()

    def _poll_loop(self) -> None:
        while not self._closed.is_set():
            try:
                self._producer.poll(1.0)
            except Exception:
                pass
            self._closed.wait(0.05)

    def publish(
        self,
        topic: str,
        *,
        key: str,
        event: Mapping[str, Any],
        on_result: Optional[Any] = None,
        produced_at: Optional[str] = None,
    ) -> bool:
        started = time.perf_counter()

        def _delivery(err: Any, _msg: Any) -> None:
            if err is not None:
                incr_counter("redpanda_producer_error_total", topic=topic, reason=_error_reason(err))
                if on_result is not None:
                    on_result(False)
                return
            observe_hist("redpanda_producer_delivery_seconds", time.perf_counter() - started, topic=topic)
            incr_counter("redpanda_producer_msgs_total", topic=topic)
            if on_result is not None:
                on_result(True)

        try:
            self._producer.produce(
                topic,
                value=serialize_message(event, produced_at=produced_at),
                key=str(key or "").encode("utf-8"),
                on_delivery=_delivery,
            )
            self._producer.poll(0)
            return True
        except BufferError:
            incr_counter("redpanda_producer_error_total", topic=topic, reason="queue_full")
            self._producer.poll(0)
            if on_result is not None:
                on_result(False)
            return False
        except Exception as exc:
            incr_counter("redpanda_producer_error_total", topic=topic, reason=type(exc).__name__)
            log_event(logger, "warning", "redpanda_produce_failed", topic=topic, error=repr(exc))
            if on_result is not None:
                on_result(False)
            return False

    def poll(self, timeout_seconds: float = 0.0) -> int:
        return int(self._producer.poll(timeout_seconds))

    def flush(self, timeout_seconds: float = 10.0) -> int:
        return int(self._producer.flush(timeout_seconds))

    def close(self, timeout_seconds: float = 5.0) -> None:
        self._closed.set()
        try:
            self._producer.flush(timeout_seconds)
        except Exception:
            pass


def get_producer() -> Optional[EventLogProducer]:
    global _PRODUCER, _PRODUCER_FAILED_AT

    if not settings.SEAGULL_REDPANDA_ENABLED:
        return None
    if _PRODUCER is not None:
        return _PRODUCER

    with _LOCK:
        if _PRODUCER is not None:
            return _PRODUCER
        now = time.monotonic()
        if _PRODUCER_FAILED_AT and (now - _PRODUCER_FAILED_AT) < _REBUILD_COOLDOWN_SECONDS:
            return None
        try:
            _PRODUCER = EventLogProducer(client_id=f"seagull-{service_name() or 'backend'}")
            log_event(logger, "info", "redpanda_producer_started", brokers=settings.SEAGULL_REDPANDA_BROKERS)
        except Exception as exc:
            _PRODUCER_FAILED_AT = now
            log_event(logger, "error", "redpanda_producer_init_failed", error=repr(exc))
            return None
    return _PRODUCER


def flush_producer(timeout_seconds: float = 5.0) -> None:
    producer = _PRODUCER
    if producer is not None:
        try:
            producer.flush(timeout_seconds)
        except Exception as exc:
            log_event(logger, "warning", "redpanda_producer_flush_failed", error=repr(exc))


def reset_producer_for_tests() -> None:
    global _PRODUCER, _PRODUCER_FAILED_AT
    with _LOCK:
        if _PRODUCER is not None:
            _PRODUCER.close(0.1)
        _PRODUCER = None
        _PRODUCER_FAILED_AT = 0.0


def _error_reason(err: Any) -> str:
    try:
        name = err.name()
        if name:
            return str(name).lower()[:64]
    except Exception:
        pass
    return "unknown"
