from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.db.session import managed_session
from app.features.auth.session import get_current_user
from app.features.threat_map import service
from app.features.threat_map.schemas import ThreatGeoResponse

router = APIRouter(
    prefix="/threat-map",
    tags=["threat-map"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/geo", response_model=ThreatGeoResponse)
def get_threat_geo_endpoint(
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(200, ge=1, le=1000, description="Maximum number of geographic points to return"),
    severity: Optional[str] = Query(None, min_length=1, max_length=16, description="Optional severity filter"),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return service.get_threat_geo(
            db_session,
            since_minutes=since_minutes,
            limit=limit,
            severity=severity,
        )
