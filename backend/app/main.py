from fastapi import FastAPI, Request
from starlette.middleware.gzip import GZipMiddleware

from app.api.agents import router as agents_router
from app.api.alerts import router as alerts_router
from app.api.events import router as events_router
from app.api.ingest import router as ingest_router
from app.api.inventory import router as inventory_router
from app.core.db import Base, engine
from app.core.schema_bootstrap import bootstrap_schema
from app.api.overview import router as overview_router
from app.api.auth import router as auth_router
from app.api.account import router as account_router
from app.api.admin import router as admin_router
from app.api.correlations import router as correlations_router
from app.core.portal_bootstrap import bootstrap_portal_admin


app = FastAPI(
    title="NetWatch Backend",
    version="0.1.0",
    description="Mini-SIEM for network / Threat Hunting",
)

# ... add basic compression for JSON payloads (lowers bandwidth for dashboards)
app.add_middleware(GZipMiddleware, minimum_size=1024)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    res = await call_next(request)
    # Baseline hardening: prevents a bunch of easy web exploitation primitives.
    res.headers.setdefault("X-Content-Type-Options", "nosniff")
    res.headers.setdefault("X-Frame-Options", "DENY")
    res.headers.setdefault("Referrer-Policy", "no-referrer")
    res.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    # CSP intentionally minimal (portal is same-origin via reverse-proxy)
    # If you serve the portal from a different origin, tighten this.
    res.headers.setdefault("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'")
    return res


@app.on_event("startup")
def on_startup():
    # Ensure all models are registered on Base.metadata before create_all.
    from app.models import agents as _agents  # noqa: F401
    from app.models import alerts as _alerts  # noqa: F401
    from app.models import alert_rule_overrides as _alert_rule_overrides  # noqa: F401
    from app.models import events as _events  # noqa: F401
    from app.models import inventory as _inventory  # noqa: F401
    from app.models import portal_users as _portal_users  # noqa: F401
    from app.models import portal_refresh_sessions as _portal_sessions  # noqa: F401
    from app.models import portal_otp_tokens as _portal_otp  # noqa: F401
    from app.models import portal_login_events as _portal_login_events  # noqa: F401
    from app.models import correlation_rules as _correlation_rules  # noqa: F401

    Base.metadata.create_all(bind=engine)
    bootstrap_schema(engine)
    bootstrap_portal_admin()


@app.get("/health")
async def health():
    return {"status": "ok"}


app.include_router(ingest_router)
app.include_router(auth_router)
app.include_router(account_router)
app.include_router(admin_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(correlations_router)
app.include_router(agents_router)
app.include_router(inventory_router)
app.include_router(overview_router)
