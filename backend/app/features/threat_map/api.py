from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.features.auth.session import get_current_user
from app.features.threat_map import service
from app.features.threat_map.schemas import ThreatGeoResponse

router = APIRouter(
    prefix="/threat-map",
    tags=["threat-map"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/geo", response_model=ThreatGeoResponse)
async def get_threat_geo_endpoint(
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30, description="Lookback window in minutes"),
    limit: int = Query(200, ge=1, le=1000, description="Maximum number of geographic points to return"),
    severity: Optional[str] = Query(
        None,
        pattern="^(critical|high|medium|low|info)$",
        description="Optional severity class filter",
    ),
    source: str = Query("both", pattern="^(both|events|alerts)$", description="Activity layer: ambient events, confirmed alerts, or both"),
):
    return await service.get_threat_geo_async(
        since_minutes=since_minutes,
        limit=limit,
        severity=severity,
        source=source,
    )
