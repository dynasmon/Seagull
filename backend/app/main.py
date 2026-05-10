import time
import logging

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette import status
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.core.db import engine
from app.core.integrations.clickhouse import clickhouse_is_available, clickhouse_is_enabled
from app.core.integrations.es import es_is_available, search_backend_mode
from app.core.cache import get_redis
from app.features.agents.api import router as agents_router
from app.features.alerts.api import router as alerts_router
from app.features.events.api import router as events_router
from app.features.ingest.api import router as ingest_router
from app.features.inventory.api import router as inventory_router
from app.features.investigations.api import router as investigations_router
from app.features.exposure.api import router as exposure_router
from app.core.db.lifecycle import ensure_database_ready
from app.features.overview.api import router as overview_router
from app.features.auth.api import router as auth_router
from app.features.account.api import router as account_router
from app.features.admin.api import router as admin_router
from app.features.correlations.api import router as correlations_router
from app.features.attack_chain.api import router as attack_chain_router
from app.features.detections.api import router as detections_router
from app.features.vuln.api import router as vuln_router
from app.features.users.api import router as users_router
from app.features.settings.api import router as settings_router
from app.features.response.api import router as response_router
from app.features.realtime.api import router as realtime_router
from app.core.config import settings
from app.core.observability import (
    clear_request_context,
    incr_counter,
    log_event,
    new_request_id,
    normalize_trace_id,
    observe_hist,
    request_id,
    set_request_context,
    setup_logging,
    snapshot_metrics,
)
from app.features.auth.bootstrap import bootstrap_portal_admin
from app.features.auth.session import require_admin
from app.features.correlations.bootstrap import bootstrap_correlation_rules
from app.core.db.model_registry import load_all_models


setup_logging("backend-api")
logger = logging.getLogger("seagull.api")

_prod = settings.SEAGULL_ENV in {"prod", "production"}
app = FastAPI(
    title="Seagull Backend",
    version="0.1.0",
    description="Mini-SIEM for network / Threat Hunting",
    openapi_url=None if _prod else "/openapi.json",
    docs_url=None if _prod else "/docs",
    redoc_url=None if _prod else "/redoc",
)

if settings.SEAGULL_TRUST_PROXY_HEADERS:
    app.add_middleware(
        ProxyHeadersMiddleware,
        trusted_hosts=settings.SEAGULL_TRUSTED_PROXY_CIDRS,
    )

# ... add basic compression for JSON payloads (lowers bandwidth for dashboards)
app.add_middleware(GZipMiddleware, minimum_size=1024)
if settings.SEAGULL_ALLOWED_HOSTS and settings.SEAGULL_ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.SEAGULL_ALLOWED_HOSTS)


@app.middleware("http")
async def request_size_guard(request: Request, call_next):
    max_body_bytes = max(1024, int(settings.SEAGULL_MAX_REQUEST_BODY_BYTES or 0))
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length, 10) > max_body_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": "request payload too large"},
                )
        except ValueError:
            pass
    return await call_next(request)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    rid = (request.headers.get("X-Request-Id") or request.headers.get("x-request-id") or "").strip() or new_request_id()
    tid = normalize_trace_id(request.headers.get("X-Trace-Id") or request.headers.get("x-trace-id"))
    set_request_context(rid, tid)

    t0 = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        incr_counter("http_requests_total", method=request.method, path=request.url.path, status="500")
        observe_hist("http_request_duration_ms", elapsed_ms, method=request.method, path=request.url.path, status="500")
        # Keep request context until exception handlers run, so request_id is preserved.
        log_event(
            logger,
            "error",
            "http_request_unhandled",
            method=request.method,
            path=request.url.path,
            duration_ms=round(elapsed_ms, 2),
            error_type=type(exc).__name__,
            error=str(exc),
            request_id=rid,
        )
        raise

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    status_code = int(getattr(response, "status_code", 500))
    status_label = str(status_code)

    response.headers.setdefault("X-Request-Id", rid)
    response.headers.setdefault("X-Trace-Id", tid)
    response.headers.setdefault("X-Response-Time-Ms", f"{elapsed_ms:.2f}")

    incr_counter("http_requests_total", method=request.method, path=request.url.path, status=status_label)
    observe_hist("http_request_duration_ms", elapsed_ms, method=request.method, path=request.url.path, status=status_label)

    log_event(
        logger,
        "info",
        "http_request",
        method=request.method,
        path=request.url.path,
        status=status_code,
        duration_ms=round(elapsed_ms, 2),
    )
    clear_request_context()
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    res = await call_next(request)
    # Baseline hardening: prevents a bunch of easy web exploitation primitives.
    res.headers.setdefault("X-Content-Type-Options", "nosniff")
    res.headers.setdefault("X-Frame-Options", "DENY")
    res.headers.setdefault("Referrer-Policy", "no-referrer")
    res.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    res.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    res.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    # CSP intentionally minimal (portal is same-origin via reverse-proxy)
    # If you serve the portal from a different origin, tighten this.
    res.headers.setdefault("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'")
    if settings.SEAGULL_ENABLE_HSTS or settings.SEAGULL_COOKIE_SECURE:
        # Only effective on HTTPS; safe to emit when TLS is terminated before app.
        res.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path.startswith("/auth/"):
        # Authentication endpoints should never be cached by intermediaries.
        res.headers.setdefault("Cache-Control", "no-store")
        res.headers.setdefault("Pragma", "no-cache")
    return res


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    status_code = int(getattr(exc, "status_code", 500))
    rid = request_id()
    log_event(
        logger,
        "warning" if status_code < 500 else "error",
        "http_exception",
        method=request.method,
        path=request.url.path,
        status=status_code,
        detail=str(exc.detail),
        request_id=rid,
    )
    body = {"detail": exc.detail, "request_id": rid}
    res = JSONResponse(status_code=status_code, content=body)
    clear_request_context()
    return res


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    rid = request_id()
    log_event(
        logger,
        "error",
        "unhandled_exception",
        method=request.method,
        path=request.url.path,
        request_id=rid,
        error_type=type(exc).__name__,
        error=str(exc),
    )
    body = {"detail": "Internal server error", "request_id": rid}
    if (settings.SEAGULL_ENV or "").lower() == "dev":
        body["error_type"] = type(exc).__name__
        body["error"] = str(exc)[:300]
    res = JSONResponse(status_code=500, content=body)
    clear_request_context()
    return res


@app.on_event("startup")
def on_startup():
    try:
        settings.validate_for_service("backend-api")

        if settings.SEAGULL_SKIP_STARTUP_BOOTSTRAP:
            return

        # Ensure all models are loaded before bootstrap hooks.
        load_all_models()

        # Uvicorn workers execute startup hooks independently.
        # Serialize first-boot DB/bootstrap routines to avoid race conditions
        # (e.g., concurrent admin/rule bootstrap on a fresh database).
        if engine.dialect.name == "postgresql":
            startup_lock_id = 8_642_709
            with engine.connect() as conn:
                conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": startup_lock_id})
                try:
                    ensure_database_ready()
                    bootstrap_portal_admin()
                    bootstrap_correlation_rules()
                finally:
                    conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": startup_lock_id})
        else:
            ensure_database_ready()
            bootstrap_portal_admin()
            bootstrap_correlation_rules()
        log_event(logger, "info", "startup_complete", env=settings.SEAGULL_ENV)
    except Exception as exc:
        logger.exception("startup_failed: %s", exc)
        raise


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/health/live")
async def health_live():
    return {"status": "ok"}


@app.get("/health/ready")
async def health_ready(response: Response):
    ready = True
    components = {}

    db_latency_ms = None
    db_error = None
    t0 = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    except Exception as exc:
        ready = False
        db_error = str(exc).splitlines()[0][:200]
    components["database"] = {
        "status": "ok" if db_error is None else "down",
        "latency_ms": db_latency_ms,
        "error": db_error,
    }

    redis_latency_ms = None
    redis_error = None
    try:
        r = get_redis()
        if r is None:
            redis_error = "redis unavailable"
        else:
            t1 = time.perf_counter()
            if not bool(r.ping()):
                redis_error = "ping failed"
            redis_latency_ms = round((time.perf_counter() - t1) * 1000.0, 2)
    except Exception as exc:
        redis_error = str(exc).splitlines()[0][:200]
    components["redis"] = {
        "status": "ok" if redis_error is None else "degraded",
        "latency_ms": redis_latency_ms,
        "error": redis_error,
    }

    es_mode = search_backend_mode()
    es_required = es_mode == "elasticsearch"
    es_latency_ms = None
    es_error = None
    t2 = time.perf_counter()
    try:
        es_ok = bool(es_is_available())
        es_latency_ms = round((time.perf_counter() - t2) * 1000.0, 2)
        if not es_ok:
            es_error = "elasticsearch unavailable"
    except Exception as exc:
        es_error = str(exc).splitlines()[0][:200]

    if es_required and es_error is not None:
        ready = False
    components["elasticsearch"] = {
        "status": "ok" if es_error is None else ("down" if es_required else "degraded"),
        "required": es_required,
        "mode": es_mode,
        "latency_ms": es_latency_ms,
        "error": es_error,
    }

    ch_enabled = bool(clickhouse_is_enabled())
    ch_required = bool(getattr(settings, "SEAGULL_CLICKHOUSE_REQUIRED", False))
    ch_latency_ms = None
    ch_error = None
    if ch_required and not ch_enabled:
        ready = False
        ch_error = "clickhouse required but disabled"
    elif ch_enabled:
        t3 = time.perf_counter()
        try:
            ch_ok = bool(clickhouse_is_available())
            ch_latency_ms = round((time.perf_counter() - t3) * 1000.0, 2)
            if not ch_ok:
                ch_error = "clickhouse unavailable"
        except Exception as exc:
            ch_error = str(exc).splitlines()[0][:200]
        if ch_required and ch_error is not None:
            ready = False
    components["clickhouse"] = {
        "enabled": ch_enabled,
        "required": ch_required,
        "status": ("disabled" if not ch_enabled else ("ok" if ch_error is None else ("down" if ch_required else "degraded"))),
        "latency_ms": ch_latency_ms,
        "error": ch_error,
    }

    response.status_code = status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ok" if ready else "degraded",
        "service": "backend-api",
        "environment": settings.SEAGULL_ENV,
        "components": components,
    }


@app.get("/metrics")
async def metrics(_: object = Depends(require_admin)):
    return snapshot_metrics()


app.include_router(ingest_router)
app.include_router(auth_router)
app.include_router(account_router)
app.include_router(admin_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(correlations_router)
app.include_router(attack_chain_router)
app.include_router(detections_router)
app.include_router(vuln_router)
app.include_router(users_router)
app.include_router(settings_router)
app.include_router(response_router)
app.include_router(realtime_router)
app.include_router(agents_router)
app.include_router(inventory_router)
app.include_router(overview_router)
app.include_router(investigations_router)
app.include_router(exposure_router)
