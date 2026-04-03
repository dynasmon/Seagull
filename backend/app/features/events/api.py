from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.portal_auth import get_current_user
from app.features.events.schemas import (
    NetEventDB,
    NetEventRollup1s,
    ProtocolIntelSummaryResponse,
    SshSummaryResponse,
)
from app.features.events.service import (
    get_port_stats,
    get_protocol_intel_samples,
    get_protocol_intel_summary,
    get_recent_events,
    get_ssh_summary,
    list_events,
    list_rollups_1s,
)
from app.shared.schemas import CursorPage


router = APIRouter(
    prefix="/events",
    tags=["events"],
    dependencies=[Depends(get_current_user)],
)


@router.get("", response_model=CursorPage[NetEventDB])
def list_events_endpoint(
    page_size: int = Query(50, ge=1, le=200, description="Page size (max 200)"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, min_length=1, max_length=32, description="Filter by event type"),
    db: Session = Depends(get_db),
):
    return list_events(
        db,
        page_size=page_size,
        cursor=cursor,
        agent_id=agent_id,
        event_type=event_type,
    )


@router.get("/recent", response_model=List[NetEventDB])
def get_recent_events_endpoint(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of events to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    since_minutes: Optional[int] = Query(None, ge=1, le=60 * 24 * 30, description="Optional lookback window in minutes"),
    window_minutes: Optional[int] = Query(None, ge=1, le=60 * 24 * 30, description="Backward-compatible alias for since_minutes"),
    db: Session = Depends(get_db),
):
    lookback_minutes = since_minutes if since_minutes is not None else window_minutes
    return get_recent_events(db, limit=limit, agent_id=agent_id, event_type=event_type, since_minutes=lookback_minutes)


@router.get("/rollups/1s", response_model=List[NetEventRollup1s])
def list_rollups_1s_endpoint(
    minutes: int = Query(60, ge=1, le=24 * 60, description="Lookback window in minutes"),
    limit: int = Query(500, ge=1, le=5000, description="Max buckets to return"),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    event_type: Optional[str] = Query(None, min_length=1, max_length=32),
    dst_ip: Optional[str] = Query(None, min_length=1, max_length=45),
    dst_port: Optional[int] = Query(None, ge=0, le=65535),
    db: Session = Depends(get_db),
):
    return list_rollups_1s(
        db,
        minutes=minutes,
        limit=limit,
        agent_id=agent_id,
        event_type=event_type,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )


@router.get("/stats/ports")
def get_port_stats_endpoint(
    limit: int = Query(20, ge=1, le=200, description="Maximum number of ports to return"),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    return get_port_stats(db, limit=limit)


@router.get("/ssh/summary", response_model=SshSummaryResponse)
def get_ssh_summary_endpoint(
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(50, ge=1, le=500, description="Row limit for recent/raw SSH views and supporting aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    db: Session = Depends(get_db),
):
    return get_ssh_summary(
        db,
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )


@router.get("/network/summary", response_model=ProtocolIntelSummaryResponse)
def get_protocol_intel_summary_endpoint(
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(25, ge=1, le=200, description="Top-N limit for aggregations"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    db: Session = Depends(get_db),
):
    return get_protocol_intel_summary(
        db,
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )


@router.get("/network/samples", response_model=List[NetEventDB])
def get_protocol_intel_samples_endpoint(
    kind: str = Query(..., min_length=2, max_length=32, description="Which field to filter on"),
    value: str = Query(..., min_length=1, max_length=512, description="Exact value for the selected field"),
    since_minutes: int = Query(60 * 12, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of events to return"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    db: Session = Depends(get_db),
):
    return get_protocol_intel_samples(
        db,
        kind=kind,
        value=value,
        since_minutes=since_minutes,
        limit=limit,
        agent_id=agent_id,
    )
