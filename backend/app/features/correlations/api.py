from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.features.auth.session import PortalPrincipal, require_admin
from app.features.correlations.engine import (
    segment_by_window as _segment_by_window,
    stage_requirements_met as _stage_requirements_met,
)
from app.features.correlations.schemas import CorrelationRunOut, CorrelationRuleIn, CorrelationRuleOut
from app.features.correlations.service import (
    create_correlation_rule,
    delete_correlation_rule,
    list_correlation_rules,
    run_correlations,
    update_correlation_rule,
)


router = APIRouter(
    prefix="/correlations",
    tags=["correlations"],
    dependencies=[Depends(require_admin)],
)


@router.get("/rules", response_model=List[CorrelationRuleOut])
def list_correlation_rules_endpoint(db: Session = Depends(get_db)):
    return list_correlation_rules(db)


@router.post("/rules", response_model=CorrelationRuleOut)
def create_correlation_rule_endpoint(
    payload: CorrelationRuleIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return create_correlation_rule(
        db,
        payload=payload,
        request=request,
        admin=admin,
    )


@router.put("/rules/{rule_id}", response_model=CorrelationRuleOut)
def update_correlation_rule_endpoint(
    rule_id: int,
    payload: CorrelationRuleIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return update_correlation_rule(
        db,
        rule_id=rule_id,
        payload=payload,
        request=request,
        admin=admin,
    )


@router.delete("/rules/{rule_id}")
def delete_correlation_rule_endpoint(
    rule_id: int,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return delete_correlation_rule(db, rule_id=rule_id, request=request, admin=admin)


@router.post("/run", response_model=CorrelationRunOut)
def run_correlations_endpoint(
    limit: int = Query(500, ge=1, le=5000, description="How many recent alerts to scan"),
    max_age_minutes: int = Query(1440, ge=1, le=60 * 24 * 14, description="Ignore alerts older than this"),
    sample_limit: int = Query(25, ge=1, le=200, description="How many alerts to include per incident"),
    db: Session = Depends(get_db),
):
    return run_correlations(
        db,
        limit=limit,
        max_age_minutes=max_age_minutes,
        sample_limit=sample_limit,
    )
