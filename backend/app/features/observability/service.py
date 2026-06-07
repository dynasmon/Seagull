from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

from app.core.config import settings
from app.core.integrations import prometheus as prom
from app.core.observability import queries

logger = logging.getLogger("seagull.observability.api")

_cache_lock = threading.Lock()
_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_CACHE_MAX_ENTRIES = 256


def _cache_ttl() -> float:
    try:
        return float(getattr(settings, "SEAGULL_OBSERVABILITY_CACHE_TTL_SECONDS", 10.0) or 0.0)
    except (TypeError, ValueError):
        return 10.0


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    if _cache_ttl() <= 0:
        return None
    now = time.monotonic()
    with _cache_lock:
        item = _cache.get(key)
        if not item:
            return None
        expiry, payload = item
        if expiry < now:
            _cache.pop(key, None)
            return None
        return payload


def _cache_set(key: str, payload: Dict[str, Any]) -> None:
    ttl = _cache_ttl()
    if ttl <= 0:
        return
    now = time.monotonic()
    with _cache_lock:
        _cache[key] = (now + ttl, payload)
        if len(_cache) > _CACHE_MAX_ENTRIES:
            for stale, _ in sorted(_cache.items(), key=lambda kv: kv[1][0])[: len(_cache) - _CACHE_MAX_ENTRIES]:
                _cache.pop(stale, None)


def observability_status() -> Dict[str, Any]:
    return {"enabled": prom.prometheus_is_enabled(), "available": prom.is_available()}


def query_catalogue() -> Dict[str, Any]:
    return {"queries": queries.list_query_catalogue()}


def _envelope(result: Optional[dict], available: bool, error: Optional[str]) -> Dict[str, Any]:
    return {"available": available, "result": result, "error": error}


def _execute(run: Callable[[], queries.QueryResult]) -> Dict[str, Any]:
    try:
        result = run()
        return _envelope(result.to_dict(), True, None)
    except prom.PrometheusUnavailable as exc:
        return _envelope(None, False, str(exc))
    except prom.PrometheusQueryError as exc:
        logger.warning("observability_query_failed error=%s", exc)
        return _envelope(None, True, str(exc))


def run_instant(key: str, *, window: Optional[str]) -> Dict[str, Any]:
    cache_key = f"i:{key}:{window or ''}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    payload = _execute(lambda: queries.run_instant(key, window=window))
    if payload["result"] is not None:
        _cache_set(cache_key, payload)
    return payload


def run_range(
    key: str,
    *,
    start: float,
    end: float,
    step: Optional[float],
    window: Optional[str],
) -> Dict[str, Any]:
    cache_key = f"r:{key}:{start}:{end}:{step}:{window or ''}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    payload = _execute(lambda: queries.run_range(key, start=start, end=end, step=step, window=window))
    if payload["result"] is not None:
        _cache_set(cache_key, payload)
    return payload


def reset_cache() -> None:
    with _cache_lock:
        _cache.clear()
