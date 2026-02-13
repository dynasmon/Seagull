import os
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from app.schemas.events import NetEvent
from app.core.db import SessionLocal
from app.models.events import NetEventModel
from app.core.agent_auth import AgentPrincipal, get_current_agent


router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
)


@router.post("/events")
def ingest_events(
    events: List[NetEvent],
    agent: AgentPrincipal = Depends(get_current_agent),
):
    if not events:
        return {"received": 0}

    # Enforce that an agent can only send its own events.
    for e in events:
        if e.agent_id != agent.agent_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent_id mismatch")

    # NOTE: the agent supplies a timestamp, but detection windows are evaluated against DB time.
    # We store server-side time by default, and only trust the client timestamp when it is
    # close enough to the server clock.
    max_skew_s = int((os.getenv("NETWATCH_MAX_EVENT_CLOCK_SKEW_SECONDS") or "30").strip() or "30")

    db = SessionLocal()
    try:
        rows = []
        now = datetime.now(timezone.utc)

        for e in events:
            extra = dict(e.extra or {})

            ts = e.timestamp
            use_client_ts = False
            try:
                skew = abs((now - ts).total_seconds())
                use_client_ts = skew <= max_skew_s
                if not use_client_ts:
                    extra.setdefault("client_timestamp", ts.isoformat())
                    extra.setdefault("clock_skew_seconds", round(skew, 3))
            except Exception:
                use_client_ts = False

            row = dict(
                agent_id=e.agent_id,
                event_type=e.event_type,
                schema_version=int(getattr(e, "schema_version", 1) or 1),
                src_ip=e.src_ip,
                dst_ip=e.dst_ip,
                src_port=e.src_port,
                dst_port=e.dst_port,
                proto=e.proto,
                bytes=e.bytes,
                extra=extra,
            )

            # Only store client ts if it is close to server time; otherwise rely on DB default.
            if use_client_ts:
                row["timestamp"] = ts

            rows.append(row)

        # Bulk insert to reduce Python/ORM overhead.
        db.bulk_insert_mappings(NetEventModel, rows, render_nulls=True)
        db.commit()
    finally:
        db.close()

    return {"received": len(events)}
