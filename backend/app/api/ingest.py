from fastapi import APIRouter, status
from typing import List

from app.schemas.events import NetEvent

router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
)


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(events: List[NetEvent]):
    # MVP: por enquanto só loga.
    # Depois: empilhar em Redis Streams -> worker -> Postgres.
    print(f"[INGEST] Recebidos {len(events)} eventos")
    # Exemplo de debug do primeiro evento
    if events:
        print("[INGEST] Primeiro evento:", events[0].dict())
    return {"received": len(events)}
