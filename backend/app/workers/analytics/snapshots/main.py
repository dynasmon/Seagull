from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from typing import Dict

from app.core.cache import get_redis
from app.core.cache.locks import acquire_lock, release_lock
from app.core.config import settings
from app.core.observability import (
    incr_counter,
    log_event,
    observe_hist,
    set_gauge,
    setup_logging,
)
from app.shared.analytics import snapshot_store
from app.shared.analytics.snapshots import (
    SnapshotPage,
    collect_scopes,
    iter_snapshot_pages,
    snapshot_tick_seconds,
)

setup_logging("worker-dashboard-snapshots")
logger = logging.getLogger("seagull.worker.dashboard_snapshots")

_PRUNE_EVERY_SECONDS = 1800.0


def _load_snapshot_pages() -> None:
    from app.features.exposure import service as _exposure_service  # noqa: F401
    from app.features.network_topology import service as _topology_service  # noqa: F401
    from app.features.overview import service as _overview_service  # noqa: F401
    from app.features.vuln import overview as _vuln_overview  # noqa: F401


def _clickhouse_busy() -> bool:
    r = get_redis()
    if r is None:
        return False
    try:
        state = r.get("seagull:ingest:clickhouse:state")
    except Exception:
        return False
    return str(state or "").strip().lower() == "degraded"


def _lock_ttl_seconds() -> float:
    return max(60.0, snapshot_tick_seconds() * 2.0)


def _scope_lock_key(page: SnapshotPage, scope_key: str) -> str:
    digest = hashlib.sha1(f"{page.page}:{scope_key}".encode("utf-8")).hexdigest()[:24]
    return f"seagull:snapshots:lock:{digest}"


async def materialize_scope(page: SnapshotPage, params: dict) -> str:
    scope_key = page.scope_key(params)
    lock_key = _scope_lock_key(page, scope_key)
    token = await acquire_lock(lock_key, ttl_s=_lock_ttl_seconds())
    if token is None and get_redis() is not None:
        return "locked"
    try:
        started = time.perf_counter()
        payload = await page.raw_compute(dict(params))
        computed_ms = (time.perf_counter() - started) * 1000.0
        observe_hist(
            "snapshot_compute_seconds",
            computed_ms / 1000.0,
            page=page.page,
            scope=page.scope_label(params),
        )
        await asyncio.to_thread(
            snapshot_store.upsert_snapshot,
            page=page.page,
            scope_key=scope_key,
            schema_version=page.schema_version,
            payload=payload,
            computed_ms=computed_ms,
        )
        return "ok"
    finally:
        if token is not None:
            await release_lock(lock_key, token)


async def run_page(page: SnapshotPage) -> Dict[str, int]:
    stats = {"ok": 0, "error": 0, "locked": 0}
    try:
        scopes = collect_scopes(page)
    except Exception as exc:
        incr_counter("snapshot_compute_errors_total", page=page.page)
        log_event(
            logger,
            "warning",
            "snapshot_scope_collection_error",
            page=page.page,
            error_type=type(exc).__name__,
        )
        stats["error"] += 1
        return stats
    for params in scopes:
        try:
            outcome = await materialize_scope(page, params)
        except Exception as exc:
            incr_counter("snapshot_compute_errors_total", page=page.page)
            incr_counter("snapshot_writes_total", page=page.page, outcome="error")
            log_event(
                logger,
                "warning",
                "snapshot_scope_compute_error",
                page=page.page,
                scope=page.scope_label(params),
                error_type=type(exc).__name__,
            )
            stats["error"] += 1
            continue
        incr_counter("snapshot_writes_total", page=page.page, outcome=outcome)
        stats[outcome] += 1
    return stats


async def run_cycle() -> Dict[str, Dict[str, int]]:
    results: Dict[str, Dict[str, int]] = {}
    for page in iter_snapshot_pages():
        if not page.enabled():
            continue
        results[page.page] = await run_page(page)
    return results


def _publish_oldest_ages() -> None:
    try:
        ages = snapshot_store.oldest_age_seconds()
    except Exception as exc:
        log_event(logger, "warning", "snapshot_age_gauge_error", error_type=type(exc).__name__)
        return
    for page_name, age in ages.items():
        set_gauge("snapshot_oldest_age_seconds", age, page=page_name)


def _prune_stale() -> None:
    retention_hours = int(getattr(settings, "SEAGULL_SNAPSHOTS_RETENTION_HOURS", 24) or 24)
    try:
        removed = snapshot_store.prune_stale(retention_hours=retention_hours)
    except Exception as exc:
        log_event(logger, "warning", "snapshot_prune_error", error_type=type(exc).__name__)
        return
    if removed:
        log_event(logger, "info", "snapshot_prune_ok", removed=removed)


def main() -> int:
    settings.validate_for_service("worker-dashboard-snapshots")

    if not bool(getattr(settings, "SEAGULL_SNAPSHOTS_WORKER_ENABLED", True)):
        log_event(logger, "info", "snapshots_worker_disabled")
        return 0

    _load_snapshot_pages()
    every_s = snapshot_tick_seconds()
    last_prune = 0.0

    while True:
        try:
            if _clickhouse_busy():
                log_event(logger, "info", "snapshots_backoff_clickhouse_busy")
                time.sleep(min(every_s * 2.0, 120.0))
                continue

            t0 = time.perf_counter()
            results = asyncio.run(run_cycle())
            _publish_oldest_ages()
            if (time.time() - last_prune) >= _PRUNE_EVERY_SECONDS:
                _prune_stale()
                last_prune = time.time()

            took_s = time.perf_counter() - t0
            observe_hist("snapshot_cycle_seconds", took_s)
            log_event(
                logger,
                "info",
                "snapshots_cycle_ok",
                pages={name: stats for name, stats in results.items()},
                took_ms=int(took_s * 1000),
            )
            time.sleep(every_s)
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            log_event(logger, "error", "snapshots_loop_error", error_type=type(exc).__name__)
            time.sleep(min(every_s, 30.0))


if __name__ == "__main__":
    raise SystemExit(main())
