from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.features.auth.session import PortalPrincipal
from app.features.correlations.engine import build_incidents, norm_patterns
from app.features.correlations.engines import CorrelationDataset
from app.features.correlations.engines.base import stable_json
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
    list_entity_states,
    list_enabled_rules,
    list_evidence_for_incident,
    list_incidents as _list_incidents,
    list_recent_alerts,
    list_recent_attack_chain_cases,
    list_recent_attack_chain_steps,
    list_recent_exposure_findings,
    list_recent_net_events,
    list_recent_vuln_findings,
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
        "entity": m.entity,
        "strategy_config": m.strategy_config,
        "risk_config": m.risk_config,
        "evidence_config": m.evidence_config,
        "lifecycle_config": m.lifecycle_config,
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
    m.stages = [s.dict(exclude_none=True) for s in (payload.stages or [])]
    m.entity = dict(payload.entity or {}) or None
    m.strategy_config = dict(payload.strategy_config or {}) or None
    m.risk_config = dict(payload.risk_config or {}) or None
    m.evidence_config = dict(payload.evidence_config or {}) or None
    m.lifecycle_config = dict(payload.lifecycle_config or {}) or None
    m.updated_at = datetime.utcnow()


def _incident_dedup_key(rule_id: int, group_value: str, started_at: datetime) -> str:
    bucket = started_at.strftime("%Y%m%dT%H%M")
    return f"cr{rule_id}:{group_value}:{bucket}"


def _sanitize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _sanitize_json(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_sanitize_json(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_json(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _upsert_incident(db, *, rule, incident_out, now):
    existing = find_open_incident(db, correlation_rule_id=rule.id, group_value=incident_out.group_value)
    if existing:
        existing.last_seen_at = max(existing.last_seen_at, incident_out.ended_at)
        existing.alert_count = max(existing.alert_count, incident_out.alert_count)
        existing.unique_rules = sorted(set(existing.unique_rules or []) | set(incident_out.unique_rules))
        existing.stage_hits = {
            str(key): max(int(value), int((existing.stage_hits or {}).get(key, 0)))
            for key, value in {**(existing.stage_hits or {}), **dict(incident_out.stage_hits or {})}.items()
        }
        existing.entity_type = incident_out.entity_type or existing.entity_type
        existing.entity_value = incident_out.entity_value or existing.entity_value
        existing.risk_score = max(
            int(existing.risk_score or 0),
            int(incident_out.risk_score or 0),
        ) or None
        existing.confidence = max(
            int(existing.confidence or 0),
            int(incident_out.confidence or 0),
        ) or None
        if incident_out.summary:
            existing.summary = incident_out.summary
        merged_context = dict(existing.context or {})
        merged_context.update(_sanitize_json(dict(incident_out.context or {})))
        existing.context = merged_context
        existing.updated_at = now
        return existing, False

    dedup_key = _incident_dedup_key(rule.id, incident_out.group_value, incident_out.started_at)
    incident = CorrelationIncidentModel(
        correlation_rule_id=rule.id,
        correlation_rule_name=rule.name,
        status="open",
        severity=rule.severity,
        risk_score=incident_out.risk_score,
        confidence=incident_out.confidence,
        entity_type=incident_out.entity_type or incident_out.group_by,
        entity_value=incident_out.entity_value or incident_out.group_value,
        group_by=incident_out.group_by,
        group_value=incident_out.group_value,
        dedup_key=dedup_key,
        started_at=incident_out.started_at,
        last_seen_at=incident_out.ended_at,
        alert_count=incident_out.alert_count,
        unique_rules=list(incident_out.unique_rules),
        stage_hits=dict(incident_out.stage_hits),
        summary=incident_out.summary,
        context=_sanitize_json(dict(incident_out.context or {})),
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()
    return incident, True


def _upsert_evidence(db, *, incident, sample_alerts, is_new, evidence_items=None):
    existing_signatures = set()
    seen_alert_ids: set[int] = set()
    if not is_new:
        if not evidence_items:
            seen_alert_ids = {int(alert_id) for alert_id in get_evidence_alert_ids(db, incident.id)}
        else:
            existing_signatures = {
                stable_key
                for stable_key in (
                    (
                        ev.evidence_type,
                        ev.alert_id,
                        ev.net_event_id,
                        ev.rule_id,
                        ev.stage,
                        ev.timestamp.isoformat() if getattr(ev, "timestamp", None) is not None else None,
                        ev.src_ip,
                        ev.dst_ip,
                        ev.dst_port,
                        stable_json(_sanitize_json(ev.details or {})),
                    )
                    for ev in list_evidence_for_incident(db, incident.id)
                )
            }

    if evidence_items:
        for item in evidence_items:
            signature = (
                item.evidence_type,
                item.alert_id,
                item.net_event_id,
                item.rule_id,
                item.stage,
                item.timestamp.isoformat(),
                item.src_ip,
                item.dst_ip,
                item.dst_port,
                stable_json(_sanitize_json(item.details or {})),
            )
            if signature in existing_signatures:
                continue
            existing_signatures.add(signature)
            db.add(
                CorrelationIncidentEvidenceModel(
                    incident_id=incident.id,
                    alert_id=item.alert_id,
                    net_event_id=item.net_event_id,
                    evidence_type=item.evidence_type,
                    rule_id=item.rule_id,
                    stage=item.stage,
                    timestamp=item.timestamp,
                    src_ip=item.src_ip,
                    dst_ip=item.dst_ip,
                    dst_port=item.dst_port,
                    details=_sanitize_json(item.details or {}),
                )
            )
        return

    for a in sample_alerts:
        if int(a.id) in seen_alert_ids:
            continue
        signature = (
            "alert",
            a.id,
            None,
            a.rule_id,
            None,
            a.created_at.isoformat(),
            a.src_ip,
            a.dst_ip,
            a.dst_port,
            stable_json({"severity": a.severity, "description": a.description}),
        )
        if signature in existing_signatures:
            continue
        existing_signatures.add(signature)
        db.add(
            CorrelationIncidentEvidenceModel(
                incident_id=incident.id,
                alert_id=a.id,
                evidence_type="alert",
                rule_id=a.rule_id,
                timestamp=a.created_at,
                src_ip=a.src_ip,
                dst_ip=a.dst_ip,
                dst_port=a.dst_port,
                details={"severity": a.severity, "description": a.description},
            )
        )


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


def _rule_required_lookback_seconds(rule: CorrelationRuleModel) -> int:
    max_window = int(getattr(rule, "window_seconds", 600) or 600)
    strategy_cfg = getattr(rule, "strategy_config", None) or {}
    risk_cfg = getattr(rule, "risk_config", None) or {}
    evidence_cfg = getattr(rule, "evidence_config", None) or {}

    for key in ("window_seconds", "baseline_window_seconds", "long_absent_seconds", "absent_seconds"):
        value = strategy_cfg.get(key)
        if value is not None:
            max_window = max(max_window, int(value or 0))
        value = risk_cfg.get(key)
        if value is not None:
            max_window = max(max_window, int(value or 0))

    for stage in list(getattr(rule, "stages", None) or []):
        for key in ("within_seconds", "maxspan_seconds"):
            value = (stage or {}).get(key)
            if value is not None:
                max_window = max(max_window, int(value or 0))

    for family in list(evidence_cfg.get("families") or []) + list(strategy_cfg.get("families") or []):
        for key in ("within_seconds", "maxspan_seconds"):
            value = (family or {}).get(key)
            if value is not None:
                max_window = max(max_window, int(value or 0))

    return max_window


def _rule_entity_types(rules: list[CorrelationRuleModel]) -> list[str]:
    entity_types: set[str] = set()
    for rule in rules:
        entity_cfg = getattr(rule, "entity", None) or {}
        entity_type = str(entity_cfg.get("type") or getattr(rule, "group_by", "") or "").strip()
        if entity_type:
            entity_types.add(entity_type)
    return sorted(entity_types)


def _build_dataset(
    db: Session,
    *,
    rules: list[CorrelationRuleModel],
    alerts: list,
    min_ts: datetime,
    limit: int,
) -> CorrelationDataset:
    entity_states = {
        (str(row.entity_type), str(row.entity_value)): row
        for row in list_entity_states(db, entity_types=_rule_entity_types(rules))
    }
    return CorrelationDataset(
        alerts=list(alerts or []),
        net_events=list_recent_net_events(db, min_ts=min_ts, limit=max(limit, 500)),
        vuln_findings=list_recent_vuln_findings(db, min_ts=min_ts, limit=max(limit, 250)),
        exposure_findings=list_recent_exposure_findings(db, min_ts=min_ts, limit=max(limit, 250)),
        attack_chain_steps=list_recent_attack_chain_steps(db, min_ts=min_ts, limit=max(limit, 500)),
        attack_chain_cases=list_recent_attack_chain_cases(db, min_ts=min_ts, limit=max(limit, 250)),
        entity_states=entity_states,
    )


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
    rule_lookback_seconds = max([_rule_required_lookback_seconds(rule) for rule in rules], default=0)
    max_lookback_seconds = max(int(max_age_minutes) * 60, int(rule_lookback_seconds))
    min_ts = now - timedelta(seconds=max_lookback_seconds)
    alerts = list_recent_alerts(db, min_ts=min_ts, limit=limit)
    dataset = _build_dataset(db, rules=rules, alerts=alerts, min_ts=min_ts, limit=limit)

    run_record = CorrelationRuleRunModel(
        started_at=now,
        status="running",
        scanned_alerts=len(alerts),
        incidents_created=0,
        incidents_updated=0,
        context={
            "triggered_by": "manual" if admin else "api",
            "lookback_seconds": max_lookback_seconds,
        },
    )
    db.add(run_record)
    db.flush()

    incidents = build_incidents(rules, alerts, sample_limit=sample_limit, dataset=dataset)

    rules_by_id = {r.id: r for r in rules}
    incidents_created = 0
    incidents_updated = 0

    for inc_out in incidents:
        rule_obj = rules_by_id.get(inc_out.correlation_rule_id)
        if not rule_obj:
            continue
        incident, is_new = _upsert_incident(db, rule=rule_obj, incident_out=inc_out, now=now)
        _upsert_evidence(
            db,
            incident=incident,
            sample_alerts=inc_out.sample_alerts,
            is_new=is_new,
            evidence_items=inc_out.evidence_items,
        )
        _upsert_entity_state(
            db,
            entity_type=incident.entity_type or incident.group_by,
            entity_value=incident.entity_value or incident.group_value,
            now=now,
            context={
                "correlation_rule_id": rule_obj.id,
                "severity": rule_obj.severity,
                "strategy": rule_obj.strategy,
            },
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
