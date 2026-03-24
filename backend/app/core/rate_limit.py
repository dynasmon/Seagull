from __future__ import annotations

from dataclasses import dataclass
import logging
import time
from typing import Optional
from threading import Lock

import redis
from fastapi import HTTPException, Request, status

from app.core.config import settings


_redis_client: Optional[redis.Redis] = None
_redis_unavailable_until: float = 0.0
_logger = logging.getLogger("netwatch.api.auth.ratelimit")
_local_lock = Lock()
_local_state: dict[str, tuple[int, float]] = {}

# Avoid repeated reconnect stalls when Redis is down.
_REDIS_RETRY_COOLDOWN_SECONDS = 5.0


def _get_redis() -> Optional[redis.Redis]:
    global _redis_client, _redis_unavailable_until
    if _redis_client is not None:
        return _redis_client
    if time.monotonic() < _redis_unavailable_until:
        return None
    try:
        _redis_client = redis.Redis(
            host=settings.NETWATCH_REDIS_HOST,
            port=settings.NETWATCH_REDIS_PORT,
            username=settings.NETWATCH_REDIS_USERNAME or None,
            password=settings.NETWATCH_REDIS_PASSWORD or None,
            decode_responses=True,
            socket_connect_timeout=0.2,
            socket_timeout=0.2,
        )
        return _redis_client
    except Exception:
        _redis_client = None
        _redis_unavailable_until = time.monotonic() + _REDIS_RETRY_COOLDOWN_SECONDS
        return None


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_seconds: int


def _incr_with_expire(r: redis.Redis, key: str, window_seconds: int) -> int:
    # Atomic-ish: INCR and set expire on first hit.
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.ttl(key)
    val, ttl = pipe.execute()
    if ttl is None or int(ttl) < 0:
        try:
            r.expire(key, window_seconds)
        except Exception:
            pass
    return int(val or 0)


def _incr_local(key: str, *, window_seconds: int) -> tuple[int, int]:
    now = time.monotonic()
    with _local_lock:
        current = _local_state.get(key)
        if current is None or current[1] <= now:
            count = 1
            expires_at = now + float(window_seconds)
        else:
            count = int(current[0]) + 1
            expires_at = float(current[1])
        _local_state[key] = (count, expires_at)
        ttl = max(1, int(expires_at - now))
    return count, ttl


def rate_limit(key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
    r = _get_redis()
    if r is None:
        # Security-first fallback: when Redis is unavailable, enforce a local in-memory limit.
        # This preserves login protection in single-node/self-hosted deployments.
        count, ttl_i = _incr_local(key, window_seconds=window_seconds)
        _logger.warning("auth_rate_limit_redis_unavailable_fallback", extra={"key": key, "window_seconds": window_seconds})
        remaining = max(0, limit - count)
        return RateLimitResult(allowed=(count <= limit), remaining=remaining, reset_seconds=ttl_i)

    try:
        count = _incr_with_expire(r, key, window_seconds)
        ttl = r.ttl(key)
        ttl_i = int(ttl) if ttl is not None and int(ttl) > 0 else window_seconds
    except Exception:
        global _redis_client, _redis_unavailable_until
        _redis_client = None
        _redis_unavailable_until = time.monotonic() + _REDIS_RETRY_COOLDOWN_SECONDS
        count, ttl_i = _incr_local(key, window_seconds=window_seconds)
        _logger.warning("auth_rate_limit_redis_error_fallback", extra={"key": key, "window_seconds": window_seconds})
        remaining = max(0, limit - count)
        return RateLimitResult(allowed=(count <= limit), remaining=remaining, reset_seconds=ttl_i)

    remaining = max(0, limit - count)
    return RateLimitResult(allowed=(count <= limit), remaining=remaining, reset_seconds=ttl_i)


def guard_login_rate_limit(request: Request, *, username: str) -> None:
    ip = (request.client.host if request.client else "") or "unknown"
    uname = (username or "").strip().lower() or "unknown"

    # Default limits: tuned for portal usage.
    ip_rl = rate_limit(f"rl:login:ip:{ip}", limit=25, window_seconds=300)
    user_rl = rate_limit(f"rl:login:user:{uname}", limit=12, window_seconds=300)

    if not ip_rl.allowed or not user_rl.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again in a few minutes.",
        )


def guard_otp_rate_limit(request: Request) -> None:
    ip = (request.client.host if request.client else "") or "unknown"
    ip_rl = rate_limit(f"rl:otp:ip:{ip}", limit=30, window_seconds=300)
    if not ip_rl.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Try again in a few minutes.",
        )
