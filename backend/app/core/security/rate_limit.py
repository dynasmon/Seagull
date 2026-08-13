from __future__ import annotations

import hashlib
import logging
import math
import time
from collections import OrderedDict
from dataclasses import dataclass
from threading import Lock
from typing import Any

from fastapi import HTTPException, Request, status

from app.core.cache.client import get_redis, mark_redis_unavailable
from app.core.config import settings
from app.core.observability import incr_counter, log_event

_logger = logging.getLogger("seagull.api.security.ratelimit")

KEY_PREFIX = "rl"

POLICY_LOCAL = "local"
POLICY_DENY = "deny"

BACKEND_SHARED = "redis"
BACKEND_LOCAL = "local"
BACKEND_DENIED = "denied"

_WINDOW_LUA = """
local hits = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {hits, ttl}
"""


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_seconds: int


class _LocalWindows:
    def __init__(self) -> None:
        self._lock = Lock()
        self._windows: "OrderedDict[str, tuple[int, float]]" = OrderedDict()

    def hit(self, key: str, *, window_seconds: int, capacity: int) -> tuple[int, int]:
        now = time.monotonic()
        with self._lock:
            hits, expires_at = self._windows.pop(key, (0, 0.0))
            self._make_room(now, capacity)
            if expires_at <= now:
                hits, expires_at = 0, now + float(window_seconds)
            hits += 1
            self._windows[key] = (hits, expires_at)
            return hits, max(1, math.ceil(expires_at - now))

    def clear(self) -> None:
        with self._lock:
            self._windows.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._windows)

    def _make_room(self, now: float, capacity: int) -> None:
        while self._windows:
            _key, (_hits, expires_at) = next(iter(self._windows.items()))
            if expires_at > now:
                break
            self._windows.popitem(last=False)
        while len(self._windows) >= capacity:
            self._windows.popitem(last=False)


_local_windows = _LocalWindows()


def limit_key(scope: str, dimension: str, identity: str) -> str:
    return f"{KEY_PREFIX}:{scope}:{dimension}:{identity}"


def _identity_digest(identity: str) -> str:
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]


def _degraded_policy() -> str:
    policy = str(getattr(settings, "SEAGULL_RATE_LIMIT_DEGRADED_POLICY", POLICY_LOCAL) or POLICY_LOCAL)
    return POLICY_DENY if policy.strip().lower() == POLICY_DENY else POLICY_LOCAL


def _local_capacity() -> int:
    return max(1, int(getattr(settings, "SEAGULL_RATE_LIMIT_LOCAL_MAX_KEYS", 10000) or 10000))


def _local_limit(limit: int) -> int:
    processes = max(1, int(getattr(settings, "SEAGULL_RATE_LIMIT_LOCAL_PROCESSES", 1) or 1))
    return max(1, limit // processes)


def _reset_seconds(ttl_ms: int, window_seconds: int) -> int:
    if ttl_ms <= 0:
        return max(1, window_seconds)
    return max(1, math.ceil(ttl_ms / 1000))


def _shared_hit(client: Any, key: str, *, window_seconds: int) -> tuple[int, int]:
    window_ms = max(1, window_seconds * 1000)
    hits, ttl_ms = client.eval(_WINDOW_LUA, 1, key, str(window_ms))
    return int(hits), _reset_seconds(int(ttl_ms), window_seconds)


def _window_result(*, limit: int, hits: int, reset_seconds: int) -> RateLimitResult:
    return RateLimitResult(
        allowed=hits <= limit,
        remaining=max(0, limit - hits),
        reset_seconds=reset_seconds,
    )


def _record(scope: str, backend: str, result: RateLimitResult) -> RateLimitResult:
    incr_counter(
        "rate_limit_decisions_total",
        scope=scope,
        backend=backend,
        outcome="allowed" if result.allowed else "limited",
    )
    return result


def rate_limit(
    scope: str,
    dimension: str,
    identity: str,
    *,
    limit: int,
    window_seconds: int,
) -> RateLimitResult:
    key = limit_key(scope, dimension, identity)
    client = get_redis()
    if client is not None:
        try:
            hits, reset_seconds = _shared_hit(client, key, window_seconds=window_seconds)
            return _record(
                scope,
                BACKEND_SHARED,
                _window_result(limit=limit, hits=hits, reset_seconds=reset_seconds),
            )
        except Exception as exc:
            mark_redis_unavailable()
            log_event(
                _logger,
                "warning",
                "rate_limit_shared_window_unavailable",
                scope=scope,
                dimension=dimension,
                identity_digest=_identity_digest(identity),
                error_type=type(exc).__name__,
            )

    if _degraded_policy() == POLICY_DENY:
        return _record(
            scope,
            BACKEND_DENIED,
            RateLimitResult(allowed=False, remaining=0, reset_seconds=max(1, window_seconds)),
        )

    hits, reset_seconds = _local_windows.hit(key, window_seconds=window_seconds, capacity=_local_capacity())
    return _record(
        scope,
        BACKEND_LOCAL,
        _window_result(limit=_local_limit(limit), hits=hits, reset_seconds=reset_seconds),
    )


def _client_ip(request: Request) -> str:
    return (request.client.host if request.client else "") or "unknown"


def guard_login_rate_limit(request: Request, *, username: str) -> None:
    identity = (username or "").strip().lower() or "unknown"

    ip_rl = rate_limit("login", "ip", _client_ip(request), limit=25, window_seconds=300)
    user_rl = rate_limit("login", "user", identity, limit=12, window_seconds=300)

    if not ip_rl.allowed or not user_rl.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again in a few minutes.",
        )


def guard_otp_rate_limit(request: Request) -> None:
    ip_rl = rate_limit("otp", "ip", _client_ip(request), limit=30, window_seconds=300)
    if not ip_rl.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Try again in a few minutes.",
        )
