from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import Awaitable, Callable, Optional

from app.core.cache import get_json, set_json
from app.core.cache.locks import single_flight
from app.core.config import settings
from app.core.observability import incr_counter, observe_hist

ComputeFn = Callable[[], Awaitable[dict]]

_VOLATILE_KEYS = ("generated_at", "meta", "query_meta")
_background_tasks: set[asyncio.Task] = set()


def payload_etag(payload: dict, *, schema_version: int) -> str:
    stable = {k: v for k, v in payload.items() if k not in _VOLATILE_KEYS}
    blob = json.dumps(stable, ensure_ascii=True, separators=(",", ":"), default=str, sort_keys=True)
    digest = hashlib.sha1(f"{int(schema_version)}:{blob}".encode("utf-8")).hexdigest()
    return f'W/"{int(schema_version)}-{digest}"'


def _read_entry(key: str) -> Optional[dict]:
    entry = get_json(key)
    if not isinstance(entry, dict):
        return None
    if "payload" not in entry or "fresh_until" not in entry or "stale_until" not in entry:
        return None
    return entry


def _store_entry(key: str, payload: dict, *, fresh_s: int, stale_s: int, schema_version: int) -> dict:
    now = time.time()
    entry = {
        "payload": payload,
        "stored_at": now,
        "fresh_until": now + max(0, int(fresh_s)),
        "stale_until": now + max(0, int(stale_s)),
        "etag": payload_etag(payload, schema_version=schema_version),
    }
    set_json(key, entry, int(stale_s) + 60)
    return entry


def _fresh_entry(key: str) -> Optional[dict]:
    entry = _read_entry(key)
    if entry is None:
        return None
    if time.time() < float(entry.get("fresh_until", 0.0)):
        return entry
    return None


async def get_or_compute(
    *,
    feature: str,
    key: str,
    compute: ComputeFn,
    fresh_s: int,
    stale_s: int,
    schema_version: int,
    allow_stale: bool = True,
    background: bool = True,
) -> tuple[dict, str, str]:
    now = time.time()
    entry = _read_entry(key)
    if entry is not None:
        if now < float(entry.get("fresh_until", 0.0)):
            incr_counter("analytics_cache_requests_total", feature=feature, outcome="fresh")
            return entry["payload"], str(entry.get("etag") or ""), "fresh"
        if allow_stale and now < float(entry.get("stale_until", 0.0)):
            incr_counter("analytics_cache_requests_total", feature=feature, outcome="stale")
            if background:
                _schedule_revalidate(
                    feature=feature,
                    key=key,
                    compute=compute,
                    fresh_s=fresh_s,
                    stale_s=stale_s,
                    schema_version=schema_version,
                )
            return entry["payload"], str(entry.get("etag") or ""), "stale"

    incr_counter("analytics_cache_requests_total", feature=feature, outcome="miss")
    result_entry = await _compute_single_flight(
        feature=feature,
        key=key,
        compute=compute,
        fresh_s=fresh_s,
        stale_s=stale_s,
        schema_version=schema_version,
    )
    return result_entry["payload"], str(result_entry.get("etag") or ""), "miss"


async def _compute_single_flight(
    *,
    feature: str,
    key: str,
    compute: ComputeFn,
    fresh_s: int,
    stale_s: int,
    schema_version: int,
) -> dict:
    async def _factory() -> dict:
        started = time.perf_counter()
        payload = await compute()
        source = str(((payload.get("meta") or {}).get("source")) or "compute")
        observe_hist("analytics_read_latency_seconds", time.perf_counter() - started, feature=feature, source=source)
        return _store_entry(key, payload, fresh_s=fresh_s, stale_s=stale_s, schema_version=schema_version)

    lock_ttl = float(getattr(settings, "SEAGULL_ANALYTICS_SINGLEFLIGHT_LOCK_TTL_SECONDS", 10.0) or 10.0)
    wait_timeout = float(getattr(settings, "SEAGULL_ANALYTICS_SINGLEFLIGHT_WAIT_SECONDS", 9.0) or 9.0)

    entry, _role = await single_flight(
        f"{key}:lock",
        _factory,
        lock_ttl_s=lock_ttl,
        wait_timeout_s=wait_timeout,
        poll=lambda: _fresh_entry(key),
        on_role=lambda role: incr_counter(
            "analytics_single_flight_total", feature=feature, role="leader" if role == "leader" else "waiter"
        ),
    )
    return entry


def _schedule_revalidate(
    *,
    feature: str,
    key: str,
    compute: ComputeFn,
    fresh_s: int,
    stale_s: int,
    schema_version: int,
) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return

    async def _run() -> None:
        try:
            await _compute_single_flight(
                feature=feature,
                key=key,
                compute=compute,
                fresh_s=fresh_s,
                stale_s=stale_s,
                schema_version=schema_version,
            )
        except Exception:
            return

    task = loop.create_task(_run())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
