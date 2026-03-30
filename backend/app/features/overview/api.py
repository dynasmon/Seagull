from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.portal_auth import get_current_user
from app.features.overview.service import get_overview


router = APIRouter(
    prefix="",
    tags=["overview"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/overview")
def get_overview_endpoint(
    window_minutes: int = Query(60, ge=5, le=1440, description="Time window (minutes) for charts"),
    agent_id: Optional[str] = Query(None, description="Optional agent filter for charts/tables"),
    lite: bool = Query(False, description="If true, skip heavy tables for faster first paint"),
    db: Session = Depends(get_db),
):
    return get_overview(db, window_minutes=window_minutes, agent_id=agent_id, lite=lite)
