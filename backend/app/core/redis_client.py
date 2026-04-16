from __future__ import annotations

import time
from typing import Optional

import redis

from app.core.config import settings


_redis: Optional[redis.Redis] = None
_redis_unavailable_until: float = 0.0
_REDIS_RETRY_COOLDOWN_SECONDS = 5.0


def get_redis(*, decode_responses: bool = True) -> Optional[redis.Redis]:
    """Best-effort Redis client.

    The platform should remain usable if Redis is temporarily unavailable.
    Callers must treat a None return as "Redis down" and fail open.
    """

    global _redis, _redis_unavailable_until
    if _redis is not None:
        return _redis
    if time.monotonic() < _redis_unavailable_until:
        return None

    try:
        r = redis.Redis(
            host=getattr(settings, "SEAGULL_REDIS_HOST", "redis"),
            port=int(getattr(settings, "SEAGULL_REDIS_PORT", 6379)),
            username=getattr(settings, "SEAGULL_REDIS_USERNAME", None) or None,
            password=getattr(settings, "SEAGULL_REDIS_PASSWORD", None) or None,
            decode_responses=bool(decode_responses),
            socket_connect_timeout=0.2,
            socket_timeout=0.2,
        )
        _redis = r
        return _redis
    except Exception:
        _redis = None
        _redis_unavailable_until = time.monotonic() + _REDIS_RETRY_COOLDOWN_SECONDS
        return None
