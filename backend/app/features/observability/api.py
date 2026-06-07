from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.observability.queries import QueryValidationError
from app.features.auth.session import PortalPrincipal, require_admin
from app.features.observability import service
from app.features.observability.schemas import (
    ObservabilityStatusOut,
    QueryCatalogueOut,
    QueryEnvelopeOut,
)

router = APIRouter(prefix="/observability", tags=["observability"])


@router.get("/status", response_model=ObservabilityStatusOut)
def get_status(_: PortalPrincipal = Depends(require_admin)):
    return service.observability_status()


@router.get("/catalogue", response_model=QueryCatalogueOut)
def get_catalogue(_: PortalPrincipal = Depends(require_admin)):
    return service.query_catalogue()


@router.get("/query/{key}", response_model=QueryEnvelopeOut)
def get_query_instant(
    key: str,
    window: Optional[str] = Query(None),
    _: PortalPrincipal = Depends(require_admin),
):
    try:
        return service.run_instant(key, window=window)
    except QueryValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/query/{key}/range", response_model=QueryEnvelopeOut)
def get_query_range(
    key: str,
    start: Optional[float] = Query(None),
    end: Optional[float] = Query(None),
    step: Optional[float] = Query(None, gt=0),
    window: Optional[str] = Query(None),
    _: PortalPrincipal = Depends(require_admin),
):
    now = time.time()
    end_value = end if end is not None else now
    start_value = start if start is not None else end_value - 3600.0
    try:
        return service.run_range(key, start=start_value, end=end_value, step=step, window=window)
    except QueryValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
