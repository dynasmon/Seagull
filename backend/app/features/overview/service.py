from __future__ import annotations

import asyncio
import json
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.cache import get_redis
from app.core.config import settings
from app.core.observability import incr_counter, observe_hist
from app.features.overview.repository import _env_int, get_overview_payload
from app.shared.analytics import AnalyticalReadModel, register_read_model, serve_read_model

_overview_cache_lock = threading.Lock()
_overview_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def _overview_cache_get(key: str) -> Optional[Dict[str, Any]]:
    ttl_s = max(0, _env_int("SEAGULL_OVERVIEW_CACHE_TTL_SECONDS", 3))
    if ttl_s <= 0:
        return None

    redis_key = f"seagull:overview:v2:{key}"
    r = get_redis()
    if r is not None:
        try:
            cached_raw = r.get(redis_key)
            if cached_raw:
                cached_payload = json.loads(cached_raw)
                if isinstance(cached_payload, dict):
                    return cached_payload
        except Exception:
            pass

    now = time.time()
    with _overview_cache_lock:
        item = _overview_cache.get(key)
        if not item:
            return None
        expires_at, payload = item
        if expires_at <= now:
            _overview_cache.pop(key, None)
            return None
        return payload


def _overview_cache_set(key: str, payload: Dict[str, Any]) -> None:
    ttl_s = max(0, _env_int("SEAGULL_OVERVIEW_CACHE_TTL_SECONDS", 3))
    if ttl_s <= 0:
        return
    redis_key = f"seagull:overview:v2:{key}"
    r = get_redis()
    if r is not None:
        try:
            r.setex(redis_key, ttl_s, json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str))
        except Exception:
            pass
    now = time.time()
    max_entries = max(16, _env_int("SEAGULL_OVERVIEW_CACHE_MAX_ENTRIES", 128))
    with _overview_cache_lock:
        _overview_cache[key] = (now + float(ttl_s), payload)
        if len(_overview_cache) > max_entries:
            keys = sorted(_overview_cache.items(), key=lambda kv: kv[1][0])
            for k, _ in keys[: max(1, len(_overview_cache) - max_entries)]:
                _overview_cache.pop(k, None)


def get_overview(
    db: Session,
    *,
    window_minutes: int,
    start_ts: datetime | None = None,
    end_ts: datetime | None = None,
    agent_id: str | None,
    lite: bool,
) -> Dict[str, Any]:
    started = time.perf_counter()
    cache_key = (
        f"w={int(window_minutes)}"
        f"|s={start_ts.isoformat() if start_ts is not None else ''}"
        f"|e={end_ts.isoformat() if end_ts is not None else ''}"
        f"|a={agent_id or '*'}|lite={1 if lite else 0}"
    )
    cached = _overview_cache_get(cache_key)
    if cached is not None:
        out = dict(cached)
        qmeta = out.get("query_meta")
        if isinstance(qmeta, dict) and str(qmeta.get("source") or "").strip():
            incr_counter("api_cache_hit_total", route="/overview")
            qmeta2 = dict(qmeta)
            qmeta2["cache_hit"] = True
            qmeta2["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
            out["query_meta"] = qmeta2
            return out

    payload = get_overview_payload(
        db,
        window_minutes=window_minutes,
        start_ts=start_ts,
        end_ts=end_ts,
        agent_id=agent_id,
        lite=lite,
    )
    _overview_cache_set(cache_key, payload)
    return payload


def _overview_ts_cache_part(value: datetime | None) -> str:
    if value is None:
        return "*"
    return value.isoformat()


def _overview_agent_cache_part(value: str | None) -> str:
    return str(value or "").strip() or "*"


def _overview_cache_key(params: Dict[str, Any]) -> str:
    return (
        "seagull:overview:swr:v1:"
        f"fr={1 if params.get('fixed_range') else 0}:w={int(params['window_minutes'])}:"
        f"s={_overview_ts_cache_part(params.get('start_ts'))}:"
        f"e={_overview_ts_cache_part(params.get('end_ts'))}:"
        f"a={_overview_agent_cache_part(params.get('agent_id'))}:lite={1 if params.get('lite') else 0}"
    )


def _resolve_overview_blocking(
    *,
    window_minutes: int,
    start_ts: datetime | None,
    end_ts: datetime | None,
    agent_id: str | None,
    lite: bool,
) -> Dict[str, Any]:
    from app.core.db import SessionLocal

    db = SessionLocal()
    try:
        return get_overview(
            db,
            window_minutes=window_minutes,
            start_ts=start_ts,
            end_ts=end_ts,
            agent_id=agent_id,
            lite=lite,
        )
    finally:
        db.close()


async def _compute_overview(params: Dict[str, Any]) -> dict:
    return await asyncio.to_thread(
        _resolve_overview_blocking,
        window_minutes=int(params["window_minutes"]),
        start_ts=params.get("start_ts"),
        end_ts=params.get("end_ts"),
        agent_id=params.get("agent_id") or None,
        lite=bool(params.get("lite")),
    )


OVERVIEW_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="overview",
        schema_version=1,
        fresh_s=int(getattr(settings, "SEAGULL_OVERVIEW_FRESH_SECONDS", 15) or 15),
        stale_s=int(getattr(settings, "SEAGULL_OVERVIEW_STALE_SECONDS", 60) or 60),
        key_builder=_overview_cache_key,
        compute=_compute_overview,
    )
)


OVERVIEW_FIXED_RANGE_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="overview_fixed_range",
        schema_version=1,
        fresh_s=int(getattr(settings, "SEAGULL_OVERVIEW_FRESH_SECONDS", 15) or 15),
        stale_s=int(getattr(settings, "SEAGULL_OVERVIEW_FIXED_RANGE_STALE_SECONDS", 600) or 600),
        key_builder=_overview_cache_key,
        compute=_compute_overview,
    )
)


async def get_overview_async(
    *,
    window_minutes: int,
    start_ts: datetime | None = None,
    end_ts: datetime | None = None,
    agent_id: str | None,
    lite: bool,
) -> tuple[dict, str, str]:
    started = time.perf_counter()
    fixed_range = start_ts is not None and end_ts is not None
    params: Dict[str, Any] = {
        "window_minutes": int(window_minutes),
        "start_ts": start_ts,
        "end_ts": end_ts,
        "agent_id": agent_id or None,
        "lite": bool(lite),
        "fixed_range": bool(fixed_range),
    }
    model = OVERVIEW_FIXED_RANGE_READ_MODEL if fixed_range else OVERVIEW_READ_MODEL
    payload, etag, outcome = await serve_read_model(model, params)
    payload = dict(payload)
    meta = dict(payload.get("meta") or {})
    meta["cache_hit"] = outcome != "miss"
    meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    payload["meta"] = meta
    query_meta = payload.get("query_meta")
    source = str((query_meta or {}).get("source") or meta.get("source") or "compute") if isinstance(query_meta, dict) else "compute"
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/overview",
        source=source,
    )
    return payload, etag, outcome
