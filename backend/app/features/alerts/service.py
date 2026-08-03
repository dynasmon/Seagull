from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.api.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.audit import audit_actor, write_audit_event
from app.core.config import settings
from app.core.observability import observe_hist
from app.features.alerts import repository
from app.features.alerts.evidence import extract_evidence_specs
from app.features.alerts.governance import validate_governance_request
from app.features.alerts.lifecycle import (
    VALID_DISPOSITIONS,
    VALID_STATUSES,
    InvalidTransitionError,
    MissingDispositionError,
    apply_triage,
)
from app.features.alerts.models import (
    AlertEvidenceModel,
    AlertModel,
    AlertRuleOverrideModel,
    AlertRuleSuppressionHistoryModel,
    AlertRuleSuppressionModel,
    AlertRuleTuningHistoryModel,
    AlertRuleTuningModel,
)
from app.features.alerts.realtime import (
    build_alert_realtime_payload_from_row,
    publish_alert_created_from_row,
    publish_alert_updated_payload,
)
from app.features.alerts.rule_runtime import (
    apply_override,
    apply_tuning_and_suppressions,
    load_baseline_rules,
    normalize_rule_list,
    run_all_rules,
)
from app.features.alerts.schemas import (
    AlertEvidenceOut,
    AlertOut,
    AlertTriageIn,
    RuleGovernanceHistoryOut,
    RuleOut,
    RuleOverrideIn,
    RuleValidationResult,
)
from app.features.auth.session import PortalPrincipal
from app.shared.analytics import AnalyticalReadModel, register_read_model, serve_read_model
from app.shared.schemas import CursorPage
from app.shared.taxonomy.catalog import technique_name
from app.shared.taxonomy.schemas import MitreCoverageResponse, MitreTacticCoverage, MitreTechniqueStat


def _parse_optional_until(v: Any) -> Optional[datetime]:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v
    raw = str(v).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except Exception:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _rule_override_snapshot(row: Optional[AlertRuleOverrideModel]) -> dict[str, Any]:
    if row is None:
        return {}
    return {
        "rule_id": row.rule_id,
        "enabled": row.enabled,
        "severity": row.severity,
        "window": row.window,
        "cooldown": row.cooldown,
        "min_events": row.min_events,
        "condition": row.condition if isinstance(row.condition, dict) else {},
        "schedule": row.schedule if isinstance(row.schedule, dict) else {},
        "patch": row.patch if isinstance(row.patch, dict) else {},
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _rule_tuning_snapshot(row: Optional[AlertRuleTuningModel]) -> dict[str, Any]:
    if row is None:
        return {}
    return {
        "rule_id": row.rule_id,
        "tuning": row.tuning if isinstance(row.tuning, dict) else {},
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "updated_by_user_id": row.updated_by_user_id,
        "updated_by_username": row.updated_by_username,
    }


def _rule_suppression_snapshot(rows: list[AlertRuleSuppressionModel]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for s in rows or []:
        out.append(
            {
                "id": s.id,
                "enabled": bool(s.enabled),
                "reason": s.reason,
                "when": s.when if isinstance(s.when, dict) else {},
                "until": s.until.isoformat() if s.until else None,
            }
        )
    out.sort(key=lambda x: int(x.get("id") or 0))
    return out


def _persist_alerts(db: Session, rows: list[AlertModel]) -> list[AlertModel]:
    for row in rows:
        repository.add_alert(db, row)
    if rows:
        repository.commit(db)
        evidence_items: list[AlertEvidenceModel] = []
        for row in rows:
            repository.refresh(db, row)
            for spec in extract_evidence_specs(row):
                evidence_items.append(AlertEvidenceModel(alert_id=row.id, **spec))
            publish_alert_created_from_row(row)
        if evidence_items:
            for ev in evidence_items:
                repository.add_alert_evidence(db, ev)
            repository.commit(db)
    return rows


def persist_generated_alerts(db: Session, rows: list[AlertModel]) -> list[AlertModel]:

    return _persist_alerts(db, rows)


def _rule_out(
    *,
    rule_id: str,
    base: dict[str, Any],
    effective: dict[str, Any],
    override_payload: dict[str, Any] | None,
    has_override: bool,
    updated_at: datetime | None,
) -> RuleOut:
    return RuleOut(
        id=rule_id,
        name=effective.get("name") or base.get("name"),
        description=effective.get("description") or base.get("description"),
        source_file=base.get("source_file"),
        pack=effective.get("pack") or base.get("pack"),
        category=effective.get("category") or base.get("category"),
        rule_version=int(effective.get("rule_version") or base.get("rule_version") or 1),
        enabled=bool(effective.get("enabled", True)),
        severity=str(effective.get("severity") or "low"),
        type=effective.get("type"),
        window=effective.get("window"),
        cooldown=effective.get("cooldown"),
        has_override=has_override,
        updated_at=updated_at,
        base=base,
        override=override_payload,
        effective=effective,
    )


def get_alert(db: Session, alert_id: int) -> AlertModel:
    row = repository.get_alert_by_id(db, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row


def get_alert_evidence(db: Session, alert_id: int) -> list[AlertEvidenceOut]:
    row = repository.get_alert_by_id(db, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return repository.list_alert_evidence(db, alert_id)


def triage_alert(
    db: Session,
    *,
    alert_id: int,
    body: AlertTriageIn,
    actor_username: str | None,
) -> AlertModel:
    row = repository.get_alert_by_id(db, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    if body.status is not None and body.status not in VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status '{body.status}'")
    if body.disposition is not None and body.disposition not in VALID_DISPOSITIONS:
        raise HTTPException(status_code=422, detail=f"Invalid disposition '{body.disposition}'")
    if body.priority is not None and not (1 <= body.priority <= 4):
        raise HTTPException(status_code=422, detail="priority must be between 1 and 4")
    if body.risk_score is not None and not (0 <= body.risk_score <= 100):
        raise HTTPException(status_code=422, detail="risk_score must be between 0 and 100")

    fields_set = body.model_fields_set
    try:
        apply_triage(
            row,
            fields_set=fields_set,
            status=body.status,
            disposition=body.disposition,
            false_positive_reason=body.false_positive_reason,
            priority=body.priority,
            assigned_to=body.assigned_to,
            triage_notes=body.triage_notes,
            risk_score=body.risk_score,
            investigation_id=body.investigation_id,
            actor_username=actor_username,
            now=datetime.utcnow(),
        )
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except MissingDispositionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    repository.commit(db)
    repository.refresh(db, row)
    publish_alert_updated_payload(build_alert_realtime_payload_from_row(row))
    return row


def list_alerts(
    db: Session,
    *,
    page_size: int,
    cursor: str | None,
    severity: str | None,
    rule_id: str | None,
    agent_id: str | None,
    tactic: str | None,
    technique_id: str | None,
    min_confidence: int | None,
    status: str | None = None,
) -> CursorPage[AlertOut]:
    cursor_parsed = parse_cursor_ts_id(cursor) if cursor else None
    rows = repository.list_alerts_page(
        db,
        page_size=page_size,
        severity=severity,
        rule_id=rule_id,
        agent_id=agent_id,
        tactic=tactic,
        technique_id=technique_id,
        min_confidence=min_confidence,
        status=status,
        cursor_parsed=cursor_parsed,
    )

    has_more = len(rows) > page_size
    items = rows[:page_size]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = make_cursor_ts_id(last.created_at, last.id)

    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


def mitre_coverage(db: Session, *, minutes: int) -> MitreCoverageResponse:
    threshold = datetime.utcnow() - timedelta(minutes=int(minutes))
    rows = repository.list_mitre_coverage_rows(db, threshold=threshold)

    by_tactic: dict[str, dict[str, Any]] = {}
    total_alerts = 0

    for r in rows:
        tactic = str(r.tactic or "").strip() or "unknown"
        tid = str(r.technique_id or "").strip() or "unknown"
        tname = str(r.technique or "").strip() or (technique_name(tid) or None)
        cnt = int(r.cnt or 0)
        maxc = int(r.max_conf or 0)
        avgc = float(r.avg_conf or 0.0)

        total_alerts += cnt
        bucket = by_tactic.setdefault(
            tactic,
            {
                "total": 0,
                "max_conf": 0,
                "sum_conf": 0.0,
                "sum_cnt": 0,
                "techniques": [],
            },
        )

        bucket["total"] += cnt
        bucket["max_conf"] = max(bucket["max_conf"], maxc)
        bucket["sum_conf"] += avgc * cnt
        bucket["sum_cnt"] += cnt
        bucket["techniques"].append(
            MitreTechniqueStat(
                technique_id=tid,
                technique=tname,
                count=cnt,
                max_confidence=maxc,
                avg_confidence=avgc,
            )
        )

    tactics: list[MitreTacticCoverage] = []
    for tactic, bucket in by_tactic.items():
        bucket["techniques"].sort(key=lambda x: (-int(x.count), x.technique_id))
        avg_conf = (bucket["sum_conf"] / bucket["sum_cnt"]) if bucket["sum_cnt"] else 0.0
        tactics.append(
            MitreTacticCoverage(
                tactic=tactic,
                total=int(bucket["total"]),
                max_confidence=int(bucket["max_conf"]),
                avg_confidence=float(avg_conf),
                techniques=bucket["techniques"],
            )
        )

    tactics.sort(key=lambda x: (-int(x.total), x.tactic))
    return MitreCoverageResponse(window_minutes=int(minutes), total_alerts=int(total_alerts), tactics=tactics)


def run_ssh_bruteforce_rule(db: Session, *, minutes: int, min_events: int) -> list[AlertModel]:
    time_threshold = datetime.utcnow() - timedelta(minutes=minutes)
    rows = repository.list_ssh_bruteforce_candidates(db, time_threshold=time_threshold, min_events=min_events)

    alerts: list[AlertModel] = []
    for row in rows:
        src_ip = row.src_ip
        count = int(row.count)
        alerts.append(
            AlertModel(
                rule_id="ssh_bruteforce_v1",
                severity="medium",
                src_ip=src_ip,
                dst_ip=None,
                dst_port=22,
                mitre_tactic="credential_access",
                mitre_technique_id="T1110.001",
                mitre_technique=(technique_name("T1110.001") or "Brute Force: Password Guessing"),
                confidence=70,
                description="Possible SSH brute force or port scanning activity detected",
                detector_type="inline",
                rule_version=1,
                details={
                    "mitre": {
                        "tactic": "credential_access",
                        "technique_id": "T1110.001",
                        "technique": (technique_name("T1110.001") or "Brute Force: Password Guessing"),
                        "confidence": 70,
                    },
                    "time_window_minutes": minutes,
                    "min_events": min_events,
                    "event_count": count,
                    "dst_port": 22,
                },
            )
        )

    return _persist_alerts(db, alerts)


def run_port_scan_rule(db: Session, *, minutes: int, min_distinct_ports: int) -> list[AlertModel]:
    time_threshold = datetime.utcnow() - timedelta(minutes=minutes)
    rows = repository.list_port_scan_candidates(
        db,
        time_threshold=time_threshold,
        min_distinct_ports=min_distinct_ports,
    )

    alerts: list[AlertModel] = []
    for row in rows:
        src_ip = row.src_ip
        distinct_ports = int(row.distinct_ports)
        event_count = int(row.event_count)
        alerts.append(
            AlertModel(
                rule_id="port_scan_v1",
                severity="high",
                src_ip=src_ip,
                dst_ip=None,
                dst_port=None,
                mitre_tactic="discovery",
                mitre_technique_id="T1046",
                mitre_technique=(technique_name("T1046") or "Network Service Scanning"),
                confidence=80,
                description="Possible TCP vertical port scan detected",
                detector_type="inline",
                rule_version=1,
                details={
                    "mitre": {
                        "tactic": "discovery",
                        "technique_id": "T1046",
                        "technique": (technique_name("T1046") or "Network Service Scanning"),
                        "confidence": 80,
                    },
                    "time_window_minutes": minutes,
                    "min_distinct_ports": min_distinct_ports,
                    "distinct_ports": distinct_ports,
                    "event_count": event_count,
                },
            )
        )

    return _persist_alerts(db, alerts)


def run_horizontal_scan_rule(
    db: Session,
    *,
    minutes: int,
    min_distinct_targets: int,
    dst_port: int,
) -> list[AlertModel]:
    time_threshold = datetime.utcnow() - timedelta(minutes=minutes)
    rows = repository.list_horizontal_scan_candidates(
        db,
        time_threshold=time_threshold,
        min_distinct_targets=min_distinct_targets,
        dst_port=dst_port,
    )

    alerts: list[AlertModel] = []
    for row in rows:
        src_ip = row.src_ip
        dst_p = int(row.dst_port)
        distinct_targets = int(row.distinct_targets)
        event_count = int(row.event_count)
        alerts.append(
            AlertModel(
                rule_id="horizontal_scan_v1",
                severity="medium",
                src_ip=src_ip,
                dst_ip=None,
                dst_port=dst_p,
                mitre_tactic="discovery",
                mitre_technique_id="T1046",
                mitre_technique=(technique_name("T1046") or "Network Service Scanning"),
                confidence=75,
                description="Possible horizontal scan against multiple targets on the same port",
                detector_type="inline",
                rule_version=1,
                details={
                    "mitre": {
                        "tactic": "discovery",
                        "technique_id": "T1046",
                        "technique": (technique_name("T1046") or "Network Service Scanning"),
                        "confidence": 75,
                    },
                    "time_window_minutes": minutes,
                    "min_distinct_targets": min_distinct_targets,
                    "distinct_targets": distinct_targets,
                    "event_count": event_count,
                    "dst_port": dst_p,
                },
            )
        )

    return _persist_alerts(db, alerts)


def run_new_hosts_rule(db: Session, *, minutes: int, min_events: int) -> list[AlertModel]:
    time_threshold = datetime.utcnow() - timedelta(minutes=minutes)

    alerts: list[AlertModel] = []

    src_rows = repository.list_new_source_hosts_candidates(
        db,
        time_threshold=time_threshold,
        min_events=min_events,
    )
    for row in src_rows:
        ip = row.ip
        first_seen = row.first_seen
        event_count = int(row.event_count)
        alerts.append(
            AlertModel(
                rule_id="new_host_seen_v1",
                severity="low",
                src_ip=ip,
                dst_ip=None,
                dst_port=None,
                mitre_tactic="discovery",
                mitre_technique_id="T1018",
                mitre_technique=(technique_name("T1018") or "Remote System Discovery"),
                confidence=40,
                description="New source host observed in network events",
                detector_type="inline",
                rule_version=1,
                details={
                    "mitre": {
                        "tactic": "discovery",
                        "technique_id": "T1018",
                        "technique": (technique_name("T1018") or "Remote System Discovery"),
                        "confidence": 40,
                    },
                    "role": "src",
                    "first_seen": first_seen.isoformat() if first_seen else None,
                    "event_count": event_count,
                    "time_window_minutes": minutes,
                    "min_events": min_events,
                },
            )
        )

    dst_rows = repository.list_new_destination_hosts_candidates(
        db,
        time_threshold=time_threshold,
        min_events=min_events,
    )
    for row in dst_rows:
        ip = row.ip
        first_seen = row.first_seen
        event_count = int(row.event_count)
        alerts.append(
            AlertModel(
                rule_id="new_host_seen_v1",
                severity="low",
                src_ip=None,
                dst_ip=ip,
                dst_port=None,
                mitre_tactic="discovery",
                mitre_technique_id="T1018",
                mitre_technique=(technique_name("T1018") or "Remote System Discovery"),
                confidence=40,
                description="New destination host observed in network events",
                detector_type="inline",
                rule_version=1,
                details={
                    "mitre": {
                        "tactic": "discovery",
                        "technique_id": "T1018",
                        "technique": (technique_name("T1018") or "Remote System Discovery"),
                        "confidence": 40,
                    },
                    "role": "dst",
                    "first_seen": first_seen.isoformat() if first_seen else None,
                    "event_count": event_count,
                    "time_window_minutes": minutes,
                    "min_events": min_events,
                },
            )
        )

    return _persist_alerts(db, alerts)


def get_recent_alerts(db: Session, *, limit: int) -> list[AlertModel]:
    return repository.list_recent_alerts(db, limit=limit)


def _alerts_recent_cache_key(params: dict) -> str:
    return f"seagull:alerts:recent:v1:l={int(params['limit'])}"


def _resolve_alerts_recent_blocking(*, limit: int) -> list[AlertModel]:
    from app.core.db import SessionLocal

    db = SessionLocal()
    try:
        return get_recent_alerts(db, limit=limit)
    finally:
        db.close()


async def _compute_alerts_recent(params: dict) -> dict:
    rows = await asyncio.to_thread(_resolve_alerts_recent_blocking, limit=int(params["limit"]))
    return {"items": [AlertOut.model_validate(row).model_dump(mode="json") for row in rows]}


ALERTS_RECENT_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="alerts_recent",
        schema_version=1,
        fresh_s=int(getattr(settings, "SEAGULL_ALERTS_RECENT_FRESH_SECONDS", 10) or 10),
        stale_s=int(getattr(settings, "SEAGULL_ALERTS_RECENT_STALE_SECONDS", 60) or 60),
        key_builder=_alerts_recent_cache_key,
        compute=_compute_alerts_recent,
    )
)


async def get_recent_alerts_async(*, limit: int) -> tuple[list[dict], str, str]:
    started = time.perf_counter()
    params = {"limit": int(limit)}
    payload, etag, outcome = await serve_read_model(ALERTS_RECENT_READ_MODEL, params)
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/alerts/recent",
        source="compute",
    )
    return list(payload.get("items") or []), etag, outcome


def run_all_rules_now() -> list[AlertModel]:
    return run_all_rules()


def list_alert_rules(db: Session) -> list[RuleOut]:
    base_rules = normalize_rule_list(load_baseline_rules(include_disabled=True))
    overrides = repository.list_overrides_map(db)
    tunings = repository.list_tuning_map(db)
    suppressions = repository.list_suppressions_map(db)

    out: list[RuleOut] = []
    for base in base_rules:
        rid = base.get("id")
        if not rid:
            continue

        row = overrides.get(rid)
        trow = tunings.get(rid)
        srows = suppressions.get(rid) or []

        effective, override_payload = apply_override(base, row)
        effective = apply_tuning_and_suppressions(
            effective,
            tuning_row=trow,
            suppression_rows=srows,
        )

        has_any_override = (row is not None) or (trow is not None) or (len(srows) > 0)
        updated_candidates = [getattr(x, "updated_at", None) for x in [row, trow] if x is not None]
        updated_candidates.extend([getattr(s, "updated_at", None) for s in srows])
        updated_candidates = [x for x in updated_candidates if isinstance(x, datetime)]
        updated_at = max(updated_candidates) if updated_candidates else None

        out.append(
            _rule_out(
                rule_id=rid,
                base=base,
                effective=effective,
                override_payload=override_payload,
                has_override=has_any_override,
                updated_at=updated_at,
            )
        )

    out.sort(key=lambda r: (r.severity, r.id))
    return out


def patch_alert_rule(
    db: Session,
    *,
    rule_id: str,
    body: RuleOverrideIn,
    request: Request,
    admin: PortalPrincipal,
) -> RuleOut:
    base_rules = normalize_rule_list(load_baseline_rules(include_disabled=True))
    base = next((r for r in base_rules if r.get("id") == rule_id), None)
    if not base:
        raise HTTPException(status_code=404, detail="Rule not found")

    governance = validate_governance_request(body, base_rule=base)
    if not governance.ok:
        raise HTTPException(
            status_code=422,
            detail={"message": "Rule governance validation failed", "errors": governance.errors},
        )

    row_existing = repository.get_rule_override(db, rule_id)
    row = row_existing
    if row is None:
        row = AlertRuleOverrideModel(rule_id=rule_id, condition={}, schedule={}, patch={})
        repository.add_rule_override(db, row)

    before = {
        "override": _rule_override_snapshot(row_existing),
        "tuning": _rule_tuning_snapshot(repository.get_rule_tuning(db, rule_id)),
        "suppressions": _rule_suppression_snapshot(repository.list_rule_suppressions(db, rule_id=rule_id)),
    }

    fields = getattr(body, "__fields_set__", set())

    if "enabled" in fields:
        row.enabled = body.enabled
    if "severity" in fields:
        row.severity = body.severity
    if "window" in fields:
        row.window = body.window
    if "cooldown" in fields:
        row.cooldown = body.cooldown
    if "min_events" in fields:
        row.min_events = body.min_events
    if "condition" in fields:
        row.condition = body.condition or {}
    if "schedule" in fields:
        row.schedule = body.schedule or {}
    if "patch" in fields:
        row.patch = body.patch or {}

    if "tuning" in fields:
        trow = repository.get_rule_tuning(db, rule_id)
        if body.tuning is None:
            if trow is not None:
                repository.add_tuning_history(
                    db,
                    AlertRuleTuningHistoryModel(
                        rule_id=rule_id,
                        action="deleted",
                        snapshot={"tuning": trow.tuning or {}},
                        actor_user_id=admin.id,
                        actor_username=admin.username,
                    ),
                )
                repository.delete_rule_tuning(db, trow)
        else:
            action = "created" if trow is None else "updated"
            if trow is None:
                trow = AlertRuleTuningModel(rule_id=rule_id, tuning={})
                repository.add_rule_tuning(db, trow)
            trow.tuning = body.tuning or {}
            trow.updated_at = datetime.utcnow()
            trow.updated_by_user_id = admin.id
            trow.updated_by_username = admin.username
            repository.add_tuning_history(
                db,
                AlertRuleTuningHistoryModel(
                    rule_id=rule_id,
                    action=action,
                    snapshot={"tuning": trow.tuning or {}},
                    actor_user_id=admin.id,
                    actor_username=admin.username,
                ),
            )

    if "suppressions" in fields:
        existing = repository.list_rule_suppressions(db, rule_id=rule_id)
        for s in existing:
            repository.add_suppression_history(
                db,
                AlertRuleSuppressionHistoryModel(
                    rule_id=rule_id,
                    suppression_id=s.id,
                    action="deleted",
                    snapshot={
                        "enabled": bool(s.enabled),
                        "reason": s.reason,
                        "when": s.when if isinstance(s.when, dict) else {},
                        "until": s.until.isoformat() if s.until else None,
                    },
                    actor_user_id=admin.id,
                    actor_username=admin.username,
                ),
            )
            repository.delete_rule_suppression(db, s)

        for item in (body.suppressions or []):
            if not isinstance(item, dict):
                continue
            srow = AlertRuleSuppressionModel(
                rule_id=rule_id,
                enabled=bool(item.get("enabled", True)),
                reason=(str(item.get("reason") or "").strip() or None),
                when=item.get("when") if isinstance(item.get("when"), dict) else {},
                until=_parse_optional_until(item.get("until")),
                updated_at=datetime.utcnow(),
                updated_by_user_id=admin.id,
                updated_by_username=admin.username,
            )
            repository.add_rule_suppression(db, srow)
            repository.flush(db)
            repository.add_suppression_history(
                db,
                AlertRuleSuppressionHistoryModel(
                    rule_id=rule_id,
                    suppression_id=srow.id,
                    action="created",
                    snapshot={
                        "enabled": bool(srow.enabled),
                        "reason": srow.reason,
                        "when": srow.when if isinstance(srow.when, dict) else {},
                        "until": srow.until.isoformat() if srow.until else None,
                    },
                    actor_user_id=admin.id,
                    actor_username=admin.username,
                ),
            )

    row.updated_at = datetime.utcnow()

    after = {
        "override": _rule_override_snapshot(row),
        "tuning": _rule_tuning_snapshot(repository.get_rule_tuning(db, rule_id)),
        "suppressions": _rule_suppression_snapshot(repository.list_rule_suppressions(db, rule_id=rule_id)),
    }

    write_audit_event(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="alert_rule.override.patch",
        resource_type="alert_rule",
        resource_id=rule_id,
        outcome="success",
        before=before,
        after=after,
        context={"fields_set": sorted([str(x) for x in fields])},
    )

    repository.commit(db)
    repository.refresh(db, row)

    trow_after = repository.get_rule_tuning(db, rule_id)
    srows_after = repository.list_rule_suppressions(db, rule_id=rule_id)
    effective, override_payload = apply_override(base, row)
    effective = apply_tuning_and_suppressions(
        effective,
        tuning_row=trow_after,
        suppression_rows=srows_after,
    )

    return _rule_out(
        rule_id=rule_id,
        base=base,
        effective=effective,
        override_payload=override_payload,
        has_override=True,
        updated_at=row.updated_at,
    )


def preview_rule_override(
    *,
    rule_id: str,
    body: RuleOverrideIn,
) -> RuleValidationResult:
    base_rules = normalize_rule_list(load_baseline_rules(include_disabled=True))
    base = next((r for r in base_rules if r.get("id") == rule_id), None)
    if not base:
        raise HTTPException(status_code=404, detail="Rule not found")

    result = validate_governance_request(body, base_rule=base)
    return RuleValidationResult(
        ok=result.ok,
        errors=result.errors,
        effective=result.effective,
    )


def delete_alert_rule_override(
    db: Session,
    *,
    rule_id: str,
    request: Request,
    admin: PortalPrincipal,
) -> None:
    row = repository.get_rule_override(db, rule_id)
    before = {
        "override": _rule_override_snapshot(row),
        "tuning": _rule_tuning_snapshot(repository.get_rule_tuning(db, rule_id)),
        "suppressions": _rule_suppression_snapshot(repository.list_rule_suppressions(db, rule_id=rule_id)),
    }

    if row is not None:
        repository.delete_rule_override(db, row)

    trow = repository.get_rule_tuning(db, rule_id)
    if trow is not None:
        repository.add_tuning_history(
            db,
            AlertRuleTuningHistoryModel(
                rule_id=rule_id,
                action="deleted",
                snapshot={"tuning": trow.tuning or {}},
                actor_user_id=admin.id,
                actor_username=admin.username,
            ),
        )
        repository.delete_rule_tuning(db, trow)

    sups = repository.list_rule_suppressions(db, rule_id=rule_id)
    for s in sups:
        repository.add_suppression_history(
            db,
            AlertRuleSuppressionHistoryModel(
                rule_id=rule_id,
                suppression_id=s.id,
                action="deleted",
                snapshot={
                    "enabled": bool(s.enabled),
                    "reason": s.reason,
                    "when": s.when if isinstance(s.when, dict) else {},
                    "until": s.until.isoformat() if s.until else None,
                },
                actor_user_id=admin.id,
                actor_username=admin.username,
            ),
        )
        repository.delete_rule_suppression(db, s)

    write_audit_event(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="alert_rule.override.delete",
        resource_type="alert_rule",
        resource_id=rule_id,
        outcome="success",
        before=before,
        after={"override": {}, "tuning": {}, "suppressions": []},
    )

    repository.commit(db)


def get_alert_rule_history(db: Session, *, rule_id: str, limit: int) -> list[RuleGovernanceHistoryOut]:
    rows_t = repository.list_tuning_history(db, rule_id=rule_id, limit=limit)
    rows_s = repository.list_suppression_history(db, rule_id=rule_id, limit=limit)

    out: list[RuleGovernanceHistoryOut] = []
    for r in rows_t:
        out.append(
            RuleGovernanceHistoryOut(
                id=int(r.id),
                rule_id=r.rule_id,
                kind="tuning",
                action=r.action,
                created_at=r.created_at,
                actor_user_id=r.actor_user_id,
                actor_username=r.actor_username,
                snapshot=r.snapshot if isinstance(r.snapshot, dict) else {},
            )
        )

    for r in rows_s:
        out.append(
            RuleGovernanceHistoryOut(
                id=int(r.id),
                rule_id=r.rule_id,
                kind="suppression",
                action=r.action,
                created_at=r.created_at,
                actor_user_id=r.actor_user_id,
                actor_username=r.actor_username,
                snapshot=r.snapshot if isinstance(r.snapshot, dict) else {},
            )
        )

    out.sort(key=lambda x: (x.created_at, x.id), reverse=True)
    return out[:limit]
