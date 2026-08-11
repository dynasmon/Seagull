from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from typing import Iterator, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.api.idempotency import read_batch_id, request_fingerprint, run_once
from app.core.db import get_db
from app.features.agents.auth import AgentPrincipal, get_current_agent
from app.features.auth.session import get_current_user, require_admin
from app.features.events.schemas import NetEvent
from app.features.ingest.control import deadletter
from app.features.ingest.schemas import (
    DeadLetterPageOut,
    DeadLetterPurgeOut,
    DeadLetterRedriveOut,
)
from app.features.ingest.service import ingest_events, storm_recover, storm_status

router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
)


@contextmanager
def _deadletter_online() -> Iterator[None]:
    try:
        yield
    except deadletter.DeadLetterUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
            headers={"Retry-After": "5"},
        ) from exc


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


@router.get("/deadletter", response_model=DeadLetterPageOut)
def deadletter_page_endpoint(
    offset: int = Query(0, ge=0, description="Messages to skip, oldest first."),
    limit: int = Query(
        deadletter.DEADLETTER_PAGE_MAX,
        ge=1,
        le=deadletter.DEADLETTER_PAGE_MAX,
        description="Message summaries to return.",
    ),
    _admin=Depends(require_admin),
):
    with _deadletter_online():
        return DeadLetterPageOut(**asdict(deadletter.page(offset=offset, limit=limit)))


@router.post("/deadletter/redrive", response_model=DeadLetterRedriveOut)
def deadletter_redrive_endpoint(
    limit: int = Query(
        deadletter.DEADLETTER_PAGE_MAX,
        ge=1,
        le=deadletter.DEADLETTER_MAX_MESSAGES,
        description="Messages to move back to the ingest queue, oldest first.",
    ),
    _admin=Depends(require_admin),
):
    with _deadletter_online():
        return DeadLetterRedriveOut(**asdict(deadletter.redrive(limit=limit)))


@router.post("/deadletter/purge", response_model=DeadLetterPurgeOut)
def deadletter_purge_endpoint(
    limit: Optional[int] = Query(
        None,
        ge=1,
        le=deadletter.DEADLETTER_MAX_MESSAGES,
        description="Messages to drop, oldest first. Omit to drop every message.",
    ),
    _admin=Depends(require_admin),
):
    with _deadletter_online():
        return DeadLetterPurgeOut(**asdict(deadletter.purge(limit=limit)))


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
