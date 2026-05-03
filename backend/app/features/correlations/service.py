from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.features.auth.session import PortalPrincipal
from app.features.correlations.engine import build_incidents, norm_patterns
from app.features.correlations.models import (
    CorrelationEntityStateModel,
    CorrelationIncidentEvidenceModel,
    CorrelationIncidentModel,
    CorrelationRuleModel,
    CorrelationRuleRunModel,
)
from app.features.correlations.repository import (
    _VALID_STATUSES,
    add,
    commit,
    delete,
    find_open_incident,
    flush,
    get_entity_state,
    get_evidence_alert_ids,
    get_incident_by_id,
    get_rule_by_id,
    list_enabled_rules,
    list_evidence_for_incident,
    list_incidents as _list_incidents,
    list_recent_alerts,
    list_rules,
    refresh,
)
from app.features.correlations.schemas import (
    CorrelationIncidentDetailOut,
    CorrelationIncidentListItemOut,
    CorrelationIncidentStatusIn,
    CorrelationRuleIn,
    CorrelationRunOut,
)


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


def _incident_dedup_key(rule_id: int, group_value: str, started_at: datetime) -> str:
    bucket = started_at.strftime("%Y%m%dT%H%M")
    return f"cr{rule_id}:{group_value}:{bucket}"


def _upsert_incident(db, *, rule, incident_out, now):
    existing = find_open_incident(db, correlation_rule_id=rule.id, group_value=incident_out.group_value)
    if existing:
        existing.last_seen_at = max(existing.last_seen_at, incident_out.ended_at)
        existing.alert_count = max(existing.alert_count, incident_out.alert_count)
        existing.unique_rules = sorted(set(existing.unique_rules or []) | set(incident_out.unique_rules))
        existing.stage_hits = dict(incident_out.stage_hits)
        existing.updated_at = now
        return existing, False

    dedup_key = _incident_dedup_key(rule.id, incident_out.group_value, incident_out.started_at)
    incident = CorrelationIncidentModel(
        correlation_rule_id=rule.id,
        correlation_rule_name=rule.name,
        status="open",
        severity=rule.severity,
        entity_type=incident_out.group_by,
        entity_value=incident_out.group_value,
        group_by=incident_out.group_by,
        group_value=incident_out.group_value,
        dedup_key=dedup_key,
        started_at=incident_out.started_at,
        last_seen_at=incident_out.ended_at,
        alert_count=incident_out.alert_count,
        unique_rules=list(incident_out.unique_rules),
        stage_hits=dict(incident_out.stage_hits),
        context={},
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()
    return incident, True


def _upsert_evidence(db, *, incident, sample_alerts, is_new):
    if is_new:
        for a in sample_alerts:
            db.add(CorrelationIncidentEvidenceModel(
                incident_id=incident.id,
                alert_id=a.id,
                evidence_type="alert",
                rule_id=a.rule_id,
                timestamp=a.created_at,
                src_ip=a.src_ip,
                dst_ip=a.dst_ip,
                dst_port=a.dst_port,
                details={"severity": a.severity, "description": a.description},
            ))
    else:
        seen = get_evidence_alert_ids(db, incident.id)
        for a in sample_alerts:
            if a.id not in seen:
                db.add(CorrelationIncidentEvidenceModel(
                    incident_id=incident.id,
                    alert_id=a.id,
                    evidence_type="alert",
                    rule_id=a.rule_id,
                    timestamp=a.created_at,
                    src_ip=a.src_ip,
                    dst_ip=a.dst_ip,
                    dst_port=a.dst_port,
                    details={"severity": a.severity, "description": a.description},
                ))


def _upsert_entity_state(db, *, entity_type, entity_value, now, context):
    existing = get_entity_state(db, entity_type=entity_type, entity_value=entity_value)
    if existing:
        existing.last_seen_at = now
        existing.seen_count = (existing.seen_count or 0) + 1
        existing.last_context = context
        existing.updated_at = now
    else:
        db.add(CorrelationEntityStateModel(
            entity_type=entity_type,
            entity_value=entity_value,
            first_seen_at=now,
            last_seen_at=now,
            seen_count=1,
            last_context=context,
            created_at=now,
            updated_at=now,
        ))


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
    request: Optional[Request] = None,
    admin: Optional[PortalPrincipal] = None,
) -> CorrelationRunOut:
    now = datetime.utcnow()
    rules = list_enabled_rules(db)
    min_ts = now - timedelta(minutes=max_age_minutes)
    alerts = list_recent_alerts(db, min_ts=min_ts, limit=limit)

    run_record = CorrelationRuleRunModel(
        started_at=now,
        status="running",
        scanned_alerts=len(alerts),
        incidents_created=0,
        incidents_updated=0,
        context={"triggered_by": "manual" if admin else "api"},
    )
    db.add(run_record)
    db.flush()

    incidents = build_incidents(rules, alerts, sample_limit=sample_limit)

    rules_by_id = {r.id: r for r in rules}
    incidents_created = 0
    incidents_updated = 0

    for inc_out in incidents:
        rule_obj = rules_by_id.get(inc_out.correlation_rule_id)
        if not rule_obj:
            continue
        incident, is_new = _upsert_incident(db, rule=rule_obj, incident_out=inc_out, now=now)
        _upsert_evidence(db, incident=incident, sample_alerts=inc_out.sample_alerts, is_new=is_new)
        _upsert_entity_state(
            db,
            entity_type=incident.group_by,
            entity_value=incident.group_value,
            now=now,
            context={"correlation_rule_id": rule_obj.id, "severity": rule_obj.severity},
        )
        inc_out.db_id = incident.id
        inc_out.status = incident.status
        if is_new:
            incidents_created += 1
        else:
            incidents_updated += 1

    run_record.finished_at = datetime.utcnow()
    run_record.status = "completed"
    run_record.incidents_created = incidents_created
    run_record.incidents_updated = incidents_updated

    if request and admin:
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="correlation.run",
            resource_type="correlation_run",
            resource_id=str(run_record.id),
            outcome="success",
            before={},
            after={
                "rules_evaluated": len(rules),
                "alerts_scanned": len(alerts),
                "incidents_created": incidents_created,
                "incidents_updated": incidents_updated,
            },
        )

    commit(db)
    return CorrelationRunOut(
        rules_evaluated=len(rules),
        alerts_scanned=len(alerts),
        incidents=incidents,
    )


def list_correlation_incidents(
    db: Session,
    *,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[CorrelationIncidentModel]:
    return _list_incidents(db, status=status, limit=limit, offset=offset)


def get_correlation_incident(db: Session, incident_id: int) -> CorrelationIncidentDetailOut:
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    evidence = list_evidence_for_incident(db, incident_id)
    out = CorrelationIncidentDetailOut.from_orm(incident)
    out.evidence = [
        type("_Ev", (), {"__dict__": ev.__dict__})  # type: ignore[arg-type]
        for ev in evidence
    ]
    # Rebuild properly using from_orm on each evidence item
    from app.features.correlations.schemas import CorrelationEvidenceOut
    out.evidence = [CorrelationEvidenceOut.from_orm(ev) for ev in evidence]
    return out


def update_incident_status(
    db: Session,
    *,
    incident_id: int,
    payload: CorrelationIncidentStatusIn,
    request: Request,
    admin: PortalPrincipal,
) -> CorrelationIncidentDetailOut:
    if payload.status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status: {payload.status}. Must be one of: {', '.join(sorted(_VALID_STATUSES))}",
        )

    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.utcnow()
    before_status = incident.status
    incident.status = payload.status
    incident.updated_at = now
    if payload.summary is not None:
        incident.summary = payload.summary
    if payload.status in ("closed", "suppressed"):
        incident.closed_at = incident.closed_at or now

    write_audit_event(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="correlation_incident.status_change",
        resource_type="correlation_incident",
        resource_id=str(incident_id),
        outcome="success",
        before={"status": before_status},
        after={"status": payload.status, "summary": payload.summary},
    )
    commit(db)
    return get_correlation_incident(db, incident_id)
