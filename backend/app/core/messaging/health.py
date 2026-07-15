from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Optional

from app.core.config import settings
from app.core.observability import log_event

logger = logging.getLogger("seagull.messaging.health")

_LOCK = threading.Lock()
_ADMIN: Optional[Any] = None


def _admin_client() -> Any:
    global _ADMIN
    if _ADMIN is not None:
        return _ADMIN
    with _LOCK:
        if _ADMIN is None:
            from confluent_kafka.admin import AdminClient

            _ADMIN = AdminClient(
                {
                    "bootstrap.servers": settings.SEAGULL_REDPANDA_BROKERS,
                    "socket.keepalive.enable": True,
                    "log.connection.close": False,
                }
            )
    return _ADMIN


def redpanda_connectivity(timeout_seconds: float = 2.0) -> Dict[str, Any]:
    started = time.perf_counter()
    try:
        metadata = _admin_client().list_topics(timeout=timeout_seconds)
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        return {
            "status": "ok",
            "latency_ms": latency_ms,
            "brokers": len(metadata.brokers),
            "error": None,
        }
    except Exception as exc:
        log_event(logger, "warning", "redpanda_health_check_failed", error=repr(exc))
        return {
            "status": "degraded",
            "latency_ms": None,
            "brokers": 0,
            "error": str(exc).splitlines()[0][:200],
        }
