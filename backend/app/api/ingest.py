import os
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from app.schemas.events import NetEvent
from app.core.db import SessionLocal
from app.models.events import NetEventModel  # <-- aqui, "events" (plural)
from app.core.agent_auth import AgentPrincipal, get_current_agent


router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
)


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(events: List[NetEvent], agent: AgentPrincipal = Depends(get_current_agent)):
    print(f"[INGEST] Received {len(events)} events")

    # Prevent spoofing by enforcing the authenticated agent_id.
    for e in events:
        if e.agent_id != agent.agent_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent_id mismatch")

    # NOTE: the agent supplies a timestamp, but detection windows are evaluated
    # against DB time (rules worker). If the agent clock is skewed, rules may miss
    # events (e.g., "last 30s" window).
    # We therefore store server-side time by default, and only trust the client
    # timestamp when it's close enough.
    max_skew_s = int((os.getenv("NETWATCH_MAX_EVENT_CLOCK_SKEW_SECONDS") or "30").strip() or "30")

    db = SessionLocal()
    try:
        for e in events:
            extra = dict(e.extra or {})

            now = datetime.now(timezone.utc)
            ts = e.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            use_client_ts = False
            try:
                skew = abs((now - ts).total_seconds())
                use_client_ts = skew <= max_skew_s
                if not use_client_ts:
                    extra.setdefault("client_timestamp", ts.isoformat())
                    extra.setdefault("clock_skew_seconds", round(skew, 3))
            except Exception:
                # If anything is off, fall back to server-side timestamp.
                use_client_ts = False

            kwargs = dict(
                agent_id=e.agent_id,
                event_type=e.event_type,
                src_ip=e.src_ip,
                dst_ip=e.dst_ip,
                src_port=e.src_port,
                dst_port=e.dst_port,
                proto=e.proto,
                bytes=e.bytes,
                extra=extra,
            )
            if use_client_ts:
                kwargs["timestamp"] = ts

            db_event = NetEventModel(**kwargs)
            db.add(db_event)

        db.commit()
    finally:
        db.close()

    if events:
        print("[INGEST] First event (in memory):", events[0].dict())

    return {"received": len(events)}
