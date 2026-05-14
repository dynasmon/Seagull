from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.features.auth.session import get_current_user
from app.features.overview.service import get_overview

router = APIRouter(
    prefix="",
    tags=["overview"],
    dependencies=[Depends(get_current_user)],
)


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@router.get("/overview")
def get_overview_endpoint(
    window_minutes: int = Query(60, ge=5, le=1440, description="Time window (minutes) for charts"),
    start_ts: datetime | None = Query(None, description="Optional ISO8601 inclusive start timestamp"),
    end_ts: datetime | None = Query(None, description="Optional ISO8601 inclusive end timestamp"),
    agent_id: Optional[str] = Query(None, description="Optional agent filter for charts/tables"),
    lite: bool = Query(False, description="If true, skip heavy tables for faster first paint"),
    db: Session = Depends(get_db),
):
    start_utc = _to_utc(start_ts)
    end_utc = _to_utc(end_ts)

    if start_utc is not None and end_utc is not None and start_utc > end_utc:
        raise HTTPException(status_code=422, detail="start_ts must be less than or equal to end_ts")

    if start_utc is not None and end_utc is not None:
        span_minutes = int(max(1, (end_utc - start_utc).total_seconds() // 60))
        if span_minutes > 10080:
            raise HTTPException(status_code=422, detail="Overview range is limited to 7 days")

    return get_overview(
        db,
        window_minutes=window_minutes,
        start_ts=start_utc,
        end_ts=end_utc,
        agent_id=agent_id,
        lite=lite,
    )
