from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.core.api.idempotency import read_batch_id, request_fingerprint, run_once
from app.core.db import get_db
from app.features.agents.auth import AgentPrincipal, get_current_agent
from app.features.auth.session import get_current_user, require_admin
from app.features.events.schemas import NetEvent
from app.features.ingest.service import ingest_events, storm_recover, storm_status

router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
)


@router.get("/storm/status")
def storm_status_endpoint(_: object = Depends(get_current_user)):
    return storm_status()


@router.post("/storm/recover")
def storm_recover_endpoint(
    clear_backlog_counters: bool = Query(False, description="Also reset backlog event counter key."),
    clear_ui_caches: bool = Query(True, description="Clear overview/events/inventory redis caches."),
    _admin=Depends(require_admin),
):
    return storm_recover(
        clear_backlog_counters=clear_backlog_counters,
        clear_ui_caches=clear_ui_caches,
    )


@router.post("/events")
def ingest_events_endpoint(
    events: List[NetEvent],
    request: Request,
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    return run_once(
        scope="ingest_events",
        agent_id=agent.agent_id,
        batch_id=read_batch_id(request),
        handler=lambda: ingest_events(db, events=events, agent=agent),
        request_digest=request_fingerprint(events),
    )
