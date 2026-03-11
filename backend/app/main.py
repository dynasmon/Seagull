import time
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette import status
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.api.agents import router as agents_router
from app.api.alerts import router as alerts_router
from app.api.events import router as events_router
from app.api.ingest import router as ingest_router
from app.api.inventory import router as inventory_router
from app.core.db_lifecycle import ensure_database_ready
from app.api.overview import router as overview_router
from app.api.auth import router as auth_router
from app.api.account import router as account_router
from app.api.admin import router as admin_router
from app.api.correlations import router as correlations_router
from app.api.attack_chain import router as attack_chain_router
from app.api.vuln import router as vuln_router
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
from app.core.portal_bootstrap import bootstrap_portal_admin, bootstrap_correlation_rules
from app.models.registry import load_all_models


setup_logging("backend-api")
logger = logging.getLogger("netwatch.api")

app = FastAPI(
    title="NetWatch Backend",
    version="0.1.0",
    description="Mini-SIEM for network / Threat Hunting",
)

if settings.NETWATCH_TRUST_PROXY_HEADERS:
    app.add_middleware(
        ProxyHeadersMiddleware,
        trusted_hosts=settings.NETWATCH_TRUSTED_PROXY_CIDRS,
    )

# ... add basic compression for JSON payloads (lowers bandwidth for dashboards)
app.add_middleware(GZipMiddleware, minimum_size=1024)
if settings.NETWATCH_ALLOWED_HOSTS and settings.NETWATCH_ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.NETWATCH_ALLOWED_HOSTS)


@app.middleware("http")
async def request_size_guard(request: Request, call_next):
    max_body_bytes = max(1024, int(settings.NETWATCH_MAX_REQUEST_BODY_BYTES or 0))
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
    if settings.NETWATCH_ENABLE_HSTS or settings.NETWATCH_COOKIE_SECURE:
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
    if (settings.NETWATCH_ENV or "").lower() == "dev":
        body["error_type"] = type(exc).__name__
        body["error"] = str(exc)[:300]
    res = JSONResponse(status_code=500, content=body)
    clear_request_context()
    return res


@app.on_event("startup")
def on_startup():
    settings.validate_for_service("backend-api")

    if settings.NETWATCH_SKIP_STARTUP_BOOTSTRAP:
        return

    # Ensure all models are loaded before bootstrap hooks.
    load_all_models()

    ensure_database_ready()
    bootstrap_portal_admin()
    bootstrap_correlation_rules()
    log_event(logger, "info", "startup_complete", env=settings.NETWATCH_ENV)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/metrics")
async def metrics():
    return snapshot_metrics()


app.include_router(ingest_router)
app.include_router(auth_router)
app.include_router(account_router)
app.include_router(admin_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(correlations_router)
app.include_router(attack_chain_router)
app.include_router(vuln_router)
app.include_router(agents_router)
app.include_router(inventory_router)
app.include_router(overview_router)
