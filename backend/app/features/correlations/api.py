from __future__ import annotations

from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select

from app.core.audit import audit_actor, write_audit_event
from app.core.db import SessionLocal
from app.core.portal_auth import PortalPrincipal, require_admin
from app.models.alerts import AlertModel
from app.models.correlation_rules import CorrelationRuleModel
from app.features.correlations.engine import (
    build_incidents,
    norm_patterns,
    segment_by_window as _segment_by_window,
    stage_requirements_met as _stage_requirements_met,
)
from app.schemas.correlations import (
    CorrelationRunOut,
    CorrelationRuleIn,
    CorrelationRuleOut,
)


router = APIRouter(
    prefix="/correlations",
    tags=["correlations"],
    dependencies=[Depends(require_admin)],
)


@router.get("/rules", response_model=List[CorrelationRuleOut])
def list_correlation_rules():
    db = SessionLocal()
    try:
        rows = db.execute(select(CorrelationRuleModel).order_by(CorrelationRuleModel.id.asc())).scalars().all()
        return rows
    finally:
        db.close()


@router.post("/rules", response_model=CorrelationRuleOut)
def create_correlation_rule(payload: CorrelationRuleIn, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        m = CorrelationRuleModel(
            name=payload.name,
            description=payload.description,
            enabled=bool(payload.enabled),
            severity=payload.severity,
            strategy=payload.strategy,
            group_by=payload.group_by,
            window_seconds=int(payload.window_seconds),
            min_alerts=int(payload.min_alerts),
            include_patterns=norm_patterns(payload.include_patterns),
            exclude_patterns=norm_patterns(payload.exclude_patterns),
            stages=[s.dict() for s in (payload.stages or [])],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(m)
        db.flush()
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="correlation_rule.create",
            resource_type="correlation_rule",
            resource_id=str(m.id),
            outcome="success",
            before={},
            after={
                "id": m.id,
                "name": m.name,
                "enabled": bool(m.enabled),
                "severity": m.severity,
                "strategy": m.strategy,
                "group_by": m.group_by,
                "window_seconds": int(m.window_seconds),
                "min_alerts": int(m.min_alerts),
                "include_patterns": m.include_patterns,
                "exclude_patterns": m.exclude_patterns,
                "stages": m.stages,
            },
        )
        db.commit()
        db.refresh(m)
        return m
    finally:
        db.close()


@router.put("/rules/{rule_id}", response_model=CorrelationRuleOut)
def update_correlation_rule(rule_id: int, payload: CorrelationRuleIn, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        m = db.get(CorrelationRuleModel, rule_id)
        if not m:
            raise HTTPException(status_code=404, detail="Correlation rule not found")

        before = {
            "id": m.id,
            "name": m.name,
            "enabled": bool(m.enabled),
            "severity": m.severity,
            "strategy": m.strategy,
            "group_by": m.group_by,
            "window_seconds": int(m.window_seconds),
            "min_alerts": int(m.min_alerts),
            "include_patterns": m.include_patterns,
            "exclude_patterns": m.exclude_patterns,
            "stages": m.stages,
        }
        m.name = payload.name
        m.description = payload.description
        m.enabled = bool(payload.enabled)
        m.severity = payload.severity
        m.strategy = payload.strategy
        m.group_by = payload.group_by
        m.window_seconds = int(payload.window_seconds)
        m.min_alerts = int(payload.min_alerts)
        m.include_patterns = norm_patterns(payload.include_patterns)
        m.exclude_patterns = norm_patterns(payload.exclude_patterns)
        m.stages = [s.dict() for s in (payload.stages or [])]
        m.updated_at = datetime.utcnow()

        db.add(m)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="correlation_rule.update",
            resource_type="correlation_rule",
            resource_id=str(m.id),
            outcome="success",
            before=before,
            after={
                "id": m.id,
                "name": m.name,
                "enabled": bool(m.enabled),
                "severity": m.severity,
                "strategy": m.strategy,
                "group_by": m.group_by,
                "window_seconds": int(m.window_seconds),
                "min_alerts": int(m.min_alerts),
                "include_patterns": m.include_patterns,
                "exclude_patterns": m.exclude_patterns,
                "stages": m.stages,
            },
        )
        db.commit()
        db.refresh(m)
        return m
    finally:
        db.close()


@router.delete("/rules/{rule_id}")
def delete_correlation_rule(rule_id: int, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        m = db.get(CorrelationRuleModel, rule_id)
        if not m:
            raise HTTPException(status_code=404, detail="Correlation rule not found")
        before = {
            "id": m.id,
            "name": m.name,
            "enabled": bool(m.enabled),
            "severity": m.severity,
            "strategy": m.strategy,
            "group_by": m.group_by,
            "window_seconds": int(m.window_seconds),
            "min_alerts": int(m.min_alerts),
            "include_patterns": m.include_patterns,
            "exclude_patterns": m.exclude_patterns,
            "stages": m.stages,
        }
        db.delete(m)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="correlation_rule.delete",
            resource_type="correlation_rule",
            resource_id=str(rule_id),
            outcome="success",
            before=before,
            after={},
        )
        db.commit()
        return {"ok": True}
    finally:
        db.close()


@router.post("/run", response_model=CorrelationRunOut)
def run_correlations(
    limit: int = Query(500, ge=1, le=5000, description="How many recent alerts to scan"),
    max_age_minutes: int = Query(1440, ge=1, le=60 * 24 * 14, description="Ignore alerts older than this"),
    sample_limit: int = Query(25, ge=1, le=200, description="How many alerts to include per incident"),
):
    """Run correlation rules against recent alerts.

    This is a synchronous, on-demand compute endpoint intended for small/medium
    environments (portal use). In larger deployments, move this into a worker
    and persist incident rows.
    """
    db = SessionLocal()
    try:
        rules = (
            db.execute(
                select(CorrelationRuleModel)
                .where(CorrelationRuleModel.enabled.is_(True))
                .order_by(CorrelationRuleModel.id.asc())
            )
            .scalars()
            .all()
        )

        min_ts = datetime.utcnow() - timedelta(minutes=max_age_minutes)
        alerts = (
            db.execute(
                select(AlertModel)
                .where(AlertModel.created_at >= min_ts)
                .order_by(AlertModel.created_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )

        incidents = build_incidents(rules, alerts, sample_limit=sample_limit)
        return CorrelationRunOut(rules_evaluated=len(rules), alerts_scanned=len(alerts), incidents=incidents)
    finally:
        db.close()
