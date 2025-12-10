from fastapi import APIRouter, status
from typing import List

from app.schemas.events import NetEvent
from app.core.db import SessionLocal
from app.models.events import NetEventModel  # <-- aqui, "events" (plural)


router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
)


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(events: List[NetEvent]):
    print(f"[INGEST] Received {len(events)} events")

    db = SessionLocal()
    try:
        for e in events:
            db_event = NetEventModel(
                agent_id=e.agent_id,
                event_type=e.event_type,
                timestamp=e.timestamp,
                src_ip=e.src_ip,
                dst_ip=e.dst_ip,
                src_port=e.src_port,
                dst_port=e.dst_port,
                proto=e.proto,
                bytes=e.bytes,
                extra=e.extra,
            )
            db.add(db_event)

        db.commit()
    finally:
        db.close()

    if events:
        print("[INGEST] First event (in memory):", events[0].dict())

    return {"received": len(events)}
