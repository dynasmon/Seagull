from fastapi import FastAPI

from app.api.ingest import router as ingest_router

app = FastAPI(
    title="NetWatch Backend",
    version="0.1.0",
    description="Mini-SIEM de rede / Threat Hunting",
)


@app.get("/health")
async def health():
    return {"status": "ok"}


# Registra as rotas de ingest
app.include_router(ingest_router)
