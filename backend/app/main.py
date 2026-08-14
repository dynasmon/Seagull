import asyncio
import logging
import multiprocessing
import os
import signal
import sys
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette import status
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.core.api.body_limit import RequestBodyLimitMiddleware, policy_from_settings
from app.core.config import settings
from app.core.db import engine, start_replica_monitor, stop_replica_monitor
from app.core.db.capacity import sequence_capacity_report
from app.core.db.lifecycle import FatalStartupError, ensure_database_ready
from app.core.db.locks import advisory_lock
from app.core.db.model_registry import load_all_models
from app.core.health import diagnostics_report, readiness_verdict
from app.core.integrations.es import es_cluster_status_report, search_backend_mode
from app.core.observability import (
    clear_request_context,
    incr_counter,
    init_counter,
    log_event,
    new_request_id,
    normalize_trace_id,
    observe_hist,
    render_exposition,
    request_id,
    set_request_context,
    setup_logging,
)
from app.core.realtime import realtime_drain
from app.features.account.api import router as account_router
from app.features.admin.api import router as admin_router
from app.features.agents.api import router as agents_router
from app.features.alerts.api import router as alerts_router
from app.features.attack_chain.api import router as attack_chain_router
from app.features.auth.api import router as auth_router
from app.features.auth.bootstrap import bootstrap_portal_admin
from app.features.auth.session import PortalPrincipal, require_admin
from app.features.correlations.api import router as correlations_router
from app.features.correlations.bootstrap import bootstrap_correlation_rules
from app.features.detections.api import router as detections_router
from app.features.events.api import router as events_router
from app.features.exposure.api import router as exposure_router
from app.features.ingest.api import router as ingest_router
from app.features.inventory.api import router as inventory_router
from app.features.investigations.api import router as investigations_router
from app.features.network_topology.api import router as network_topology_router
from app.features.observability.api import router as observability_router
from app.features.overview.api import router as overview_router
from app.features.realtime.api import router as realtime_router
from app.features.response.agent_actions_api import router as agent_response_actions_router
from app.features.response.api import router as response_router
from app.features.settings.api import router as settings_router
from app.features.threat_map.api import router as threat_map_router
from app.features.ueba.api import router as ueba_router
from app.features.users.api import router as users_router
from app.features.vuln.api import router as vuln_router
from app.shared.analytics import swr_cache_control_middleware

setup_logging("backend-api")
logger = logging.getLogger("seagull.api")


def _shutdown_drain_seconds() -> float:
    configured = int(getattr(settings, "SEAGULL_REALTIME_SHUTDOWN_DRAIN_SECONDS", 5) or 5)
    if configured < 1:
        return 1.0
    if configured > 30:
        return 30.0
    return float(configured)


def _prewarm_rule_registry() -> None:
    from app.workers.intelligence.rules.registry import load_baseline_rules

    try:
        load_baseline_rules(include_disabled=True)
    except Exception as exc:
        log_event(logger, "warning", "rule_registry_prewarm_failed", error_type=type(exc).__name__)


def _startup() -> None:
    settings.validate_for_service("backend-api")

    realtime_drain.reset_state()
    realtime_drain.install_signal_handlers()

    for severity in ("critical", "high", "medium", "low"):
        init_counter("alert_created_total", severity=severity, detector_type="none")

    if settings.SEAGULL_SKIP_STARTUP_BOOTSTRAP:
        return

    start_replica_monitor()
    load_all_models()
    _prewarm_rule_registry()

    if engine.dialect.name == "postgresql":
        with advisory_lock(8_642_709):
            ensure_database_ready()
            bootstrap_portal_admin()
            bootstrap_correlation_rules()
    else:
        ensure_database_ready()
        bootstrap_portal_admin()
        bootstrap_correlation_rules()
    log_event(logger, "info", "startup_complete", env=settings.SEAGULL_ENV)


async def _shutdown() -> None:
    realtime_drain.begin_draining()
    drain_deadline = time.monotonic() + _shutdown_drain_seconds()
    while realtime_drain.active_connection_count() > 0 and time.monotonic() < drain_deadline:
        await asyncio.sleep(0.05)
    remaining = realtime_drain.active_connection_count()
    log_event(
        logger,
        "info",
        "realtime_drain_complete",
        remaining_connections=remaining,
        drained=bool(remaining == 0),
    )
    realtime_drain.reset_state()
    stop_replica_monitor()


_FATAL_STARTUP_EXIT_CODE = 3


def _report_fatal_startup(exc: BaseException) -> None:
    log_event(logger, "error", "startup_failed_fatal", reason=str(exc))
    print(f"\nFATAL: seagull backend cannot start.\n\n{exc}\n", file=sys.stderr, flush=True)


def _abort_supervised_worker() -> None:
    if multiprocessing.parent_process() is None:
        return
    try:
        os.kill(os.getppid(), signal.SIGTERM)
    except OSError:
        pass
    for handler in logging.getLogger().handlers:
        handler.flush()
    os._exit(_FATAL_STARTUP_EXIT_CODE)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    try:
        _startup()
    except FatalStartupError as exc:
        _report_fatal_startup(exc)
        _abort_supervised_worker()
        raise
    except Exception as exc:
        logger.exception("startup_failed: %s", exc)
        raise
    yield
    await _shutdown()


_prod = settings.SEAGULL_ENV in {"prod", "production"}
app = FastAPI(
    title="Seagull Backend",
    version="0.1.0",
    description="Mini-SIEM for network / Threat Hunting",
    openapi_url=None if _prod else "/openapi.json",
    docs_url=None if _prod else "/docs",
    redoc_url=None if _prod else "/redoc",
    lifespan=_lifespan,
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


app.add_middleware(RequestBodyLimitMiddleware, policy=policy_from_settings())


def _route_label(request: Request) -> str:
    route = request.scope.get("route")
    path_format = getattr(route, "path_format", None)
    if path_format:
        return str(path_format)[:128]
    return "unmatched"


def _status_class(status_code: int) -> str:
    try:
        return f"{int(status_code) // 100}xx"
    except Exception:
        return "5xx"


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
        route_label = _route_label(request)
        incr_counter("http_requests_total", method=request.method, route=route_label, status_class="5xx")
        observe_hist("http_request_duration_ms", elapsed_ms, method=request.method, route=route_label, status_class="5xx")
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
    route_label = _route_label(request)
    status_class = _status_class(status_code)

    response.headers.setdefault("X-Request-Id", rid)
    response.headers.setdefault("X-Trace-Id", tid)
    response.headers.setdefault("X-Response-Time-Ms", f"{elapsed_ms:.2f}")

    incr_counter("http_requests_total", method=request.method, route=route_label, status_class=status_class)
    observe_hist("http_request_duration_ms", elapsed_ms, method=request.method, route=route_label, status_class=status_class)

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


app.middleware("http")(swr_cache_control_middleware)


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


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/health/live")
async def health_live():
    return {"status": "ok"}


@app.get("/health/ready")
def health_ready(response: Response):
    ready = readiness_verdict()
    response.status_code = status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ok" if ready else "degraded"}


@app.get("/health/diagnostics")
def health_diagnostics(response: Response, _: PortalPrincipal = Depends(require_admin)):
    report = diagnostics_report()
    response.status_code = status.HTTP_200_OK if report["ready"] else status.HTTP_503_SERVICE_UNAVAILABLE
    return report


@app.get("/metrics")
def metrics():
    if not settings.SEAGULL_METRICS_ENABLED:
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    if search_backend_mode() != "postgres":
        try:
            es_cluster_status_report()
        except Exception:
            pass
    try:
        sequence_capacity_report()
    except Exception:
        pass
    body, content_type = render_exposition()
    return Response(content=body, media_type=content_type)


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
app.include_router(ueba_router)
app.include_router(response_router)
app.include_router(realtime_router)
app.include_router(agents_router)
app.include_router(agent_response_actions_router)
app.include_router(inventory_router)
app.include_router(overview_router)
app.include_router(investigations_router)
app.include_router(exposure_router)
app.include_router(network_topology_router)
app.include_router(threat_map_router)
app.include_router(observability_router)
