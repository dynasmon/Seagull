from __future__ import annotations

import json
import time
from typing import Any, Optional

import redis

from app.core.config import settings

_redis: Optional[redis.Redis] = None
_blocking_redis: Optional[redis.Redis] = None
_redis_unavailable_until: float = 0.0
_REDIS_RETRY_COOLDOWN_SECONDS = 5.0

_BLOCKING_SOCKET_TIMEOUT_SECONDS = 5.0
_BLOCKING_CONNECT_TIMEOUT_SECONDS = 1.0


def get_redis(*, decode_responses: bool = True) -> Optional[redis.Redis]:

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


def mark_redis_unavailable() -> None:

    global _redis, _redis_unavailable_until
    _redis = None
    _redis_unavailable_until = time.monotonic() + _REDIS_RETRY_COOLDOWN_SECONDS


def get_blocking_redis(*, decode_responses: bool = True) -> Optional[redis.Redis]:

    global _blocking_redis, _redis_unavailable_until
    if _blocking_redis is not None:
        return _blocking_redis
    if time.monotonic() < _redis_unavailable_until:
        return None

    try:
        r = redis.Redis(
            host=getattr(settings, "SEAGULL_REDIS_HOST", "redis"),
            port=int(getattr(settings, "SEAGULL_REDIS_PORT", 6379)),
            username=getattr(settings, "SEAGULL_REDIS_USERNAME", None) or None,
            password=getattr(settings, "SEAGULL_REDIS_PASSWORD", None) or None,
            decode_responses=bool(decode_responses),
            socket_connect_timeout=_BLOCKING_CONNECT_TIMEOUT_SECONDS,
            socket_timeout=_BLOCKING_SOCKET_TIMEOUT_SECONDS,
        )
        _blocking_redis = r
        return _blocking_redis
    except Exception:
        _blocking_redis = None
        _redis_unavailable_until = time.monotonic() + _REDIS_RETRY_COOLDOWN_SECONDS
        return None


def get_json(key: str) -> dict[str, Any] | None:
    r = get_redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
        if not raw:
            return None
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def set_json(key: str, payload: dict[str, Any], ttl_s: int) -> None:
    if ttl_s <= 0:
        return
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(key, int(ttl_s), json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str))
    except Exception:
        return


def delete_prefixes(*prefixes: str) -> None:
    r = get_redis()
    if r is None:
        return
    for prefix in prefixes:
        raw_prefix = str(prefix or "").strip()
        if not raw_prefix:
            continue
        try:
            cursor: int | str = 0
            while True:
                cursor, keys = r.scan(cursor=cursor, match=f"{raw_prefix}*", count=200)
                if keys:
                    r.delete(*keys)
                if str(cursor) == "0":
                    break
        except Exception:
            return
