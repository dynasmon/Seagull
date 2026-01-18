from fastapi import FastAPI

from app.api.agents import router as agents_router
from app.api.alerts import router as alerts_router
from app.api.events import router as events_router
from app.api.ingest import router as ingest_router
from app.api.inventory import router as inventory_router
from app.core.db import Base, engine
from app.core.schema_bootstrap import bootstrap_schema
from app.api.overview import router as overview_router


app = FastAPI(
    title="NetWatch Backend",
    version="0.1.0",
    description="Mini-SIEM for network / Threat Hunting",
)


@app.on_event("startup")
def on_startup():
    # Ensure all models are registered on Base.metadata before create_all.
    from app.models import agents as _agents  # noqa: F401
    from app.models import alerts as _alerts  # noqa: F401
    from app.models import events as _events  # noqa: F401
    from app.models import inventory as _inventory  # noqa: F401

    Base.metadata.create_all(bind=engine)
    bootstrap_schema(engine)


@app.get("/health")
async def health():
    return {"status": "ok"}


app.include_router(ingest_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(agents_router)
app.include_router(inventory_router)
app.include_router(overview_router)
