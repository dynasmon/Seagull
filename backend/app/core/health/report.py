from __future__ import annotations

import threading
import time
from typing import Any, Dict, Tuple

from sqlalchemy import text

from app.core.cache import get_redis
from app.core.config import settings
from app.core.db import engine, read_router
from app.core.integrations.clickhouse import (
    clickhouse_is_available,
    clickhouse_is_enabled,
    clickhouse_missing_mvs,
    expected_clickhouse_mv_names,
    get_clickhouse_client,
)
from app.core.integrations.es import es_cluster_status_report, es_is_available, search_backend_mode
from app.core.messaging.health import redpanda_connectivity

_verdict_lock = threading.Lock()
_verdict: Tuple[float, bool] | None = None


def _database_component() -> Tuple[Dict[str, Any], bool]:
    latency_ms = None
    error = None
    started = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
    except Exception as exc:
        error = str(exc).splitlines()[0][:200]
    component = {
        "status": "ok" if error is None else "down",
        "latency_ms": latency_ms,
        "error": error,
    }
    return component, error is None


def _replication_component() -> Dict[str, Any] | None:
    if not read_router.enabled:
        return None
    try:
        read_router.probe_if_stale()
    except Exception:
        pass
    replication = read_router.status_report()
    healthy = int(replication.get("healthy") or 0)
    total = int(replication.get("total") or 0)
    replication["status"] = "ok" if healthy == total else "degraded"
    return replication


def _redis_component() -> Dict[str, Any]:
    latency_ms = None
    error = None
    try:
        client = get_redis()
        if client is None:
            error = "redis unavailable"
        else:
            started = time.perf_counter()
            if not bool(client.ping()):
                error = "ping failed"
            latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
    except Exception as exc:
        error = str(exc).splitlines()[0][:200]
    return {
        "status": "ok" if error is None else "degraded",
        "latency_ms": latency_ms,
        "error": error,
    }


def _elasticsearch_component() -> Tuple[Dict[str, Any], bool]:
    mode = search_backend_mode()
    required = mode == "elasticsearch"
    latency_ms = None
    error = None
    started = time.perf_counter()
    try:
        available = bool(es_is_available())
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        if not available:
            error = "elasticsearch unavailable"
    except Exception as exc:
        error = str(exc).splitlines()[0][:200]

    cluster = None
    try:
        cluster = es_cluster_status_report()
    except Exception:
        cluster = None

    status = "ok" if error is None else ("down" if required else "degraded")
    if status == "ok" and cluster is not None and cluster.get("alert"):
        status = "degraded"

    component = {
        "status": status,
        "required": required,
        "mode": mode,
        "latency_ms": latency_ms,
        "error": error,
        "cluster": cluster,
    }
    return component, not (required and error is not None)


def _clickhouse_component() -> Tuple[Dict[str, Any], bool]:
    enabled = bool(clickhouse_is_enabled())
    required = bool(getattr(settings, "SEAGULL_CLICKHOUSE_REQUIRED", False))
    latency_ms = None
    error = None
    ready = True

    if required and not enabled:
        ready = False
        error = "clickhouse required but disabled"
    elif enabled:
        started = time.perf_counter()
        try:
            available = bool(clickhouse_is_available())
            latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
            if not available:
                error = "clickhouse unavailable"
        except Exception as exc:
            error = str(exc).splitlines()[0][:200]
        if required and error is not None:
            ready = False

    mvs = None
    if enabled and error is None:
        try:
            missing = clickhouse_missing_mvs(get_clickhouse_client())
            expected = expected_clickhouse_mv_names()
            mvs = {
                "expected": len(expected),
                "present": len(expected) - len(missing),
                "missing": missing,
            }
        except Exception as exc:
            mvs = {"error": str(exc).splitlines()[0][:200]}

    status = "disabled" if not enabled else ("ok" if error is None else ("down" if required else "degraded"))
    if status == "ok" and required and mvs is not None and (mvs.get("missing") or mvs.get("error")):
        status = "degraded"

    component = {
        "enabled": enabled,
        "required": required,
        "status": status,
        "latency_ms": latency_ms,
        "error": error,
        "mvs": mvs,
    }
    return component, ready


def _redpanda_component() -> Dict[str, Any] | None:
    if not settings.SEAGULL_REDPANDA_ENABLED:
        return None
    report = redpanda_connectivity(timeout_seconds=2.0)
    return {
        "enabled": True,
        "status": report.get("status"),
        "latency_ms": report.get("latency_ms"),
        "brokers": report.get("brokers"),
        "dual_write": bool(settings.SEAGULL_REDPANDA_DUAL_WRITE_ENABLED),
        "error": report.get("error"),
    }


def diagnostics_report() -> Dict[str, Any]:
    components: Dict[str, Any] = {}
    ready = True

    components["database"], database_ready = _database_component()
    ready = ready and database_ready

    replication = _replication_component()
    if replication is not None:
        components["postgres_replication"] = replication

    components["redis"] = _redis_component()

    components["elasticsearch"], search_ready = _elasticsearch_component()
    ready = ready and search_ready

    components["clickhouse"], analytics_ready = _clickhouse_component()
    ready = ready and analytics_ready

    redpanda = _redpanda_component()
    if redpanda is not None:
        components["redpanda"] = redpanda

    return {
        "status": "ok" if ready else "degraded",
        "ready": ready,
        "service": "backend-api",
        "environment": settings.SEAGULL_ENV,
        "components": components,
    }


def readiness_verdict() -> bool:
    global _verdict

    ttl = max(0.0, float(settings.SEAGULL_HEALTH_READY_CACHE_SECONDS))
    now = time.monotonic()

    cached = _verdict
    if cached is not None and ttl > 0.0 and (now - cached[0]) < ttl:
        return cached[1]

    with _verdict_lock:
        cached = _verdict
        if cached is not None and ttl > 0.0 and (time.monotonic() - cached[0]) < ttl:
            return cached[1]
        ready = bool(diagnostics_report()["ready"])
        _verdict = (time.monotonic(), ready)
        return ready


def reset_readiness_cache() -> None:
    global _verdict
    with _verdict_lock:
        _verdict = None
