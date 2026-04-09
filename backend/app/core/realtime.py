from __future__ import annotations

import logging

from app.core.observability import log_event
from app.core.redis_client import get_redis


logger = logging.getLogger("netwatch.api.realtime")

PORTAL_REALTIME_CHANNEL = "netwatch:portal:realtime:v1"


def portal_realtime_channel() -> str:
    return PORTAL_REALTIME_CHANNEL


def publish_portal_realtime_message(message: str) -> bool:
    if not isinstance(message, str) or not message.strip():
        raise ValueError("message must be a non-empty string")

    redis_client = get_redis(decode_responses=True)
    if redis_client is None:
        return False

    try:
        redis_client.publish(PORTAL_REALTIME_CHANNEL, message)
        return True
    except Exception as exc:
        log_event(
            logger,
            "warning",
            "realtime_publish_failed",
            channel=PORTAL_REALTIME_CHANNEL,
            error_type=type(exc).__name__,
            error=str(exc),
        )
        return False
