from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Optional

import redis

from app.core.config import settings

_redis_client: Optional[redis.Redis] = None


def _env_int(name: str, default: int) -> int:
    raw = getattr(settings, name, None)
    if raw is None:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _get_redis() -> Optional[redis.Redis]:

    global _redis_client
    if _redis_client is not None:
        return _redis_client

    try:
        _redis_client = redis.Redis(
            host=settings.SEAGULL_REDIS_HOST,
            port=settings.SEAGULL_REDIS_PORT,
            username=settings.SEAGULL_REDIS_USERNAME or None,
            password=settings.SEAGULL_REDIS_PASSWORD or None,
            decode_responses=True,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
        )
        _redis_client.ping()
        return _redis_client
    except Exception:
        _redis_client = None
        return None


@dataclass(frozen=True)
class StormDecision:
    storm_active: bool
    sample_percent: int
    reason: str


def _storm_key(agent_id: str) -> str:
    return f"storm:agent:{agent_id}"


def evaluate_storm(agent_id: str, batch_size: int) -> StormDecision:

    # Safe defaults (tune via env without code changes).
    eps_limit = _env_int("SEAGULL_INGEST_STORM_EVENTS_PER_SECOND", 8000)
    min_batch = _env_int("SEAGULL_INGEST_STORM_MIN_BATCH", 2500)
    ttl_s = _env_int("SEAGULL_INGEST_STORM_TTL_SECONDS", 20)

    # In storm mode we sample raw events to reduce write amplification.
    sample_pct = _env_int("SEAGULL_INGEST_STORM_SAMPLE_PERCENT", 2)
    sample_pct = max(0, min(sample_pct, 100))

    # If Redis is unavailable, we can still trigger storm on oversized batches.
    if batch_size >= min_batch and batch_size > 0 and eps_limit > 0:
        # For Redis-less environments, treat a huge batch as storm.
        if _get_redis() is None:
            return StormDecision(storm_active=True, sample_percent=sample_pct, reason="batch_threshold")

    r = _get_redis()
    if r is None:
        return StormDecision(storm_active=False, sample_percent=100, reason="redis_unavailable")

    now_s = int(time.time())
    eps_key = f"ingest:eps:{agent_id}:{now_s}"
    skey = _storm_key(agent_id)

    try:
        # Track EPS in a 1-second window.
        eps = int(r.incrby(eps_key, int(batch_size)))
        r.expire(eps_key, 2)

        already = bool(r.get(skey))
        triggered = (batch_size >= min_batch) or (eps_limit > 0 and eps >= eps_limit)

        if already or triggered:
            r.setex(skey, ttl_s, "1")
            reason = "active" if already else ("eps" if eps >= eps_limit else "batch_threshold")
            return StormDecision(storm_active=True, sample_percent=sample_pct, reason=reason)

        return StormDecision(storm_active=False, sample_percent=100, reason="normal")
    except Exception:
        return StormDecision(storm_active=False, sample_percent=100, reason="redis_error")


def stable_sample(*, seed: str, sample_percent: int) -> bool:

    p = max(0, min(int(sample_percent), 100))
    if p <= 0:
        return False
    if p >= 100:
        return True

    h = hashlib.blake2b(seed.encode("utf-8"), digest_size=8).digest()
    v = int.from_bytes(h, "big") % 10000
    return v < p * 100
