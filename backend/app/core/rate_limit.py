from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import redis
from fastapi import HTTPException, Request, status

from app.core.config import settings


_redis_client: Optional[redis.Redis] = None


def _get_redis() -> Optional[redis.Redis]:
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        _redis_client = redis.Redis(
            host=settings.NETWATCH_REDIS_HOST,
            port=settings.NETWATCH_REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
        )
        # best-effort connectivity check
        _redis_client.ping()
        return _redis_client
    except Exception:
        _redis_client = None
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


def rate_limit(key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
    r = _get_redis()
    if r is None:
        # Fail-open if Redis is unavailable (keeps the platform usable),
        # but still provides a sane result.
        return RateLimitResult(allowed=True, remaining=limit, reset_seconds=window_seconds)

    try:
        count = _incr_with_expire(r, key, window_seconds)
        ttl = r.ttl(key)
        ttl_i = int(ttl) if ttl is not None and int(ttl) > 0 else window_seconds
    except Exception:
        return RateLimitResult(allowed=True, remaining=limit, reset_seconds=window_seconds)

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
