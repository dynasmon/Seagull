from fastapi import FastAPI

from app.api.ingest import router as ingest_router
from app.api.events import router as events_router
from app.core.db import Base, engine

app = FastAPI(
    title="NetWatch Backend",
    version="0.1.0",
    description="Mini-SIEM de network / Threat Hunting",
)


@app.on_event("startup")
def on_startup():
    # Create tables if they do not exist
    Base.metadata.create_all(bind=engine)


@app.get("/health")
async def health():
    return {"status": "ok"}


# Routers
app.include_router(ingest_router)
app.include_router(events_router)
