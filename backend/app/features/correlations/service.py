from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.core.portal_auth import PortalPrincipal
from app.features.correlations.engine import build_incidents, norm_patterns
from app.features.correlations.models import CorrelationRuleModel
from app.features.correlations.repository import (
    add,
    commit,
    delete,
    flush,
    get_rule_by_id,
    list_enabled_rules,
    list_recent_alerts,
    list_rules,
    refresh,
)
from app.features.correlations.schemas import CorrelationRuleIn, CorrelationRunOut


def _rule_snapshot(m: CorrelationRuleModel) -> dict:
    return {
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


def _apply_rule_payload(m: CorrelationRuleModel, payload: CorrelationRuleIn) -> None:
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


def list_correlation_rules(db: Session) -> list[CorrelationRuleModel]:
    return list_rules(db)


def create_correlation_rule(
    db: Session,
    *,
    payload: CorrelationRuleIn,
    request: Request,
    admin: PortalPrincipal,
) -> CorrelationRuleModel:
    now = datetime.utcnow()
    m = CorrelationRuleModel(created_at=now, updated_at=now)
    _apply_rule_payload(m, payload)

    add(db, m)
    flush(db)
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
        after=_rule_snapshot(m),
    )
    commit(db)
    refresh(db, m)
    return m


def update_correlation_rule(
    db: Session,
    *,
    rule_id: int,
    payload: CorrelationRuleIn,
    request: Request,
    admin: PortalPrincipal,
) -> CorrelationRuleModel:
    m = get_rule_by_id(db, rule_id)
    if not m:
        raise HTTPException(status_code=404, detail="Correlation rule not found")

    before = _rule_snapshot(m)
    _apply_rule_payload(m, payload)

    add(db, m)
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
        after=_rule_snapshot(m),
    )
    commit(db)
    refresh(db, m)
    return m


def delete_correlation_rule(
    db: Session,
    *,
    rule_id: int,
    request: Request,
    admin: PortalPrincipal,
) -> dict[str, bool]:
    m = get_rule_by_id(db, rule_id)
    if not m:
        raise HTTPException(status_code=404, detail="Correlation rule not found")

    before = _rule_snapshot(m)
    delete(db, m)
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
    commit(db)
    return {"ok": True}


def run_correlations(
    db: Session,
    *,
    limit: int,
    max_age_minutes: int,
    sample_limit: int,
) -> CorrelationRunOut:
    rules = list_enabled_rules(db)
    min_ts = datetime.utcnow() - timedelta(minutes=max_age_minutes)
    alerts = list_recent_alerts(db, min_ts=min_ts, limit=limit)
    incidents = build_incidents(rules, alerts, sample_limit=sample_limit)
    return CorrelationRunOut(
        rules_evaluated=len(rules),
        alerts_scanned=len(alerts),
        incidents=incidents,
    )
