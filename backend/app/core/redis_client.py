from __future__ import annotations

from typing import Optional

import redis

from app.core.config import settings


_redis: Optional[redis.Redis] = None


def get_redis(*, decode_responses: bool = True) -> Optional[redis.Redis]:
    """Best-effort Redis client.

    The platform should remain usable if Redis is temporarily unavailable.
    Callers must treat a None return as "Redis down" and fail open.
    """

    global _redis
    if _redis is not None:
        return _redis

    try:
        r = redis.Redis(
            host=getattr(settings, "NETWATCH_REDIS_HOST", "redis"),
            port=int(getattr(settings, "NETWATCH_REDIS_PORT", 6379)),
            decode_responses=bool(decode_responses),
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
        )
        r.ping()
        _redis = r
        return _redis
    except Exception:
        _redis = None
        return None
