import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.core.observability import log_event
from app.features.alerts.evidence import extract_evidence_specs
from app.features.alerts.models import AlertEvidenceModel, AlertModel
from app.features.alerts.realtime import publish_alert_created_from_row
from app.features.alerts.rule_registry_runtime import (
    apply_override,
    apply_tuning_and_suppressions,
    fetch_overrides,
    fetch_suppressions,
    fetch_tuning,
    load_baseline_rules,
    normalize_rule_list,
)
from app.features.detections.repository import get_rule_health_map
from app.features.detections.rules.compiler import execute_v2_rule
from app.shared.taxonomy.catalog import technique_name

from .conditions import (
    _ALLOWED_EVENT_FIELDS,
    _build_match_filters,
    _enrich_alert_ips,
    _evaluate_condition,
    _extract_alert_key,
    _parse_window,
    _safe_col,
)
from .dedup import _index_add, _recent_alert_index, _recent_alert_last_at
from .health import RuleExecResult, _content_hash, flush_cycle_health
from .heuristics import _emit_heuristic_signals
from .mitre import _extract_mitre_meta
from .suppression import _is_suppressed, _schedule_allows
from .tuning import (
    _build_rule_context,
    _is_tuning_allowlisted,
    _load_agent_context,
    _resolve_tuning_eval,
)

logger = logging.getLogger("seagull.worker.rules")


def _correlate_ddos_incidents(db: Session, now: datetime, created_alerts: List[AlertModel]) -> List[AlertModel]:
    horizon = timedelta(minutes=10)
    since = now - horizon

    ddos_alerts = [
        a
        for a in created_alerts
        if isinstance(a.rule_id, str)
        and (a.rule_id.startswith("ddos_") or a.rule_id.startswith("dos_") or a.rule_id.startswith("l7_"))
    ]

    if not ddos_alerts:
        return []

    out: List[AlertModel] = []
    incident_rule_id = "incident_ddos_correlated_v1"

    dst_ips = sorted({str(a.dst_ip) for a in ddos_alerts if a.dst_ip})
    if not dst_ips:
        return []

    correlated_rows = db.execute(
        select(
            AlertModel.dst_ip.label("dst_ip"),
            AlertModel.rule_id.label("rule_id"),
            func.count().label("cnt"),
        )
        .where(
            and_(
                AlertModel.created_at >= since,
                AlertModel.dst_ip.in_(dst_ips),
                AlertModel.rule_id.in_(["port_scan_pcap_v1", "ssh_bruteforce_authlog_v2"]),
            )
        )
        .group_by(AlertModel.dst_ip, AlertModel.rule_id)
    ).all()

    by_dst: Dict[str, Dict[str, int]] = {}
    for row in correlated_rows:
        if not row.dst_ip or not row.rule_id:
            continue
        by_dst.setdefault(str(row.dst_ip), {})[str(row.rule_id)] = int(row.cnt or 0)

    cooldown_since = now - timedelta(minutes=10)
    candidate_pairs = {(str(a.dst_ip), int(a.dst_port) if a.dst_port is not None else None) for a in ddos_alerts if a.dst_ip}
    existing_rows = db.execute(
        select(AlertModel.dst_ip, AlertModel.dst_port)
        .where(
            and_(
                AlertModel.created_at >= cooldown_since,
                AlertModel.rule_id == incident_rule_id,
                AlertModel.dst_ip.in_(dst_ips),
            )
        )
    ).all()
    existing_pairs = {(str(r.dst_ip), int(r.dst_port) if r.dst_port is not None else None) for r in existing_rows}

    for a in ddos_alerts:
        dst_ip = a.dst_ip
        if not dst_ip:
            continue
        correlated = by_dst.get(str(dst_ip)) or {}
        if sum(correlated.values()) <= 0:
            continue
        pair = (str(dst_ip), int(a.dst_port) if a.dst_port is not None else None)
        if pair in existing_pairs:
            continue
        if pair not in candidate_pairs:
            continue

        incident = AlertModel(
            rule_id=incident_rule_id,
            severity="critical",
            src_ip=None,
            dst_ip=dst_ip,
            dst_port=a.dst_port,
            mitre_tactic="impact",
            mitre_technique_id="T1498",
            mitre_technique=(technique_name("T1498") or "Network Denial of Service"),
            confidence=85,
            description="Potential incident: DDoS/DoS correlated with additional hostile activity",
            detector_type="correlation",
            details={
                "type": "correlation",
                "window_seconds": int(horizon.total_seconds()),
                "correlated_rules": correlated,
                "base_rule_id": a.rule_id,
                "mitre": {
                    "tactic": "impact",
                    "technique_id": "T1498",
                    "technique": (technique_name("T1498") or "Network Denial of Service"),
                    "confidence": 85,
                },
            },
        )
        db.add(incident)
        out.append(incident)
        existing_pairs.add(pair)

    return out


def run_rules_once():
    now = datetime.utcnow()
    created_alerts: List[AlertModel] = []
    health_results: List[RuleExecResult] = []

    db = SessionLocal()
    try:
        base_rules = normalize_rule_list(load_baseline_rules(include_disabled=True))
        overrides = fetch_overrides(db)
        tunings = fetch_tuning(db)
        suppressions = fetch_suppressions(db)

        rules: List[Dict[str, Any]] = []
        max_cooldown_s = 0
        for base in base_rules:
            rid = base.get("id")
            eff, _ = apply_override(base, overrides.get(rid))
            eff = apply_tuning_and_suppressions(
                eff,
                tuning_row=tunings.get(str(rid)),
                suppression_rows=suppressions.get(str(rid)) or [],
            )
            rules.append(eff)
            try:
                max_cooldown_s = max(max_cooldown_s, int(_parse_window(eff.get("cooldown") or "0")))
            except Exception as exc:
                log_event(logger, "warning", "rule_cooldown_parse_error", rule_id=eff.get("id"), error=repr(exc))

        horizon = timedelta(seconds=max(120, max_cooldown_s))
        recent_idx = _recent_alert_index(db, horizon)
        agent_ctx_map = _load_agent_context(db)

        existing_health = get_rule_health_map(db)

        for rule in rules:
            rule_id = rule.get("id")
            if not rule_id:
                continue

            if not rule.get("enabled", True):
                health_results.append(RuleExecResult(
                    rule_id=rule_id,
                    rule_version=int(rule.get("rule_version") or 1),
                    content_hash=_content_hash(rule),
                    duration_ms=0,
                    disabled=True,
                ))
                continue

            if not _schedule_allows(rule, now):
                continue

            schema_version = int(rule.get("schema_version") or 1)
            t_start = time.monotonic()

            if schema_version == 2:
                try:
                    v2_alerts = execute_v2_rule(db, rule, now, recent_idx, agent_ctx_map)
                    rule_version = int(rule.get("rule_version") or 1)
                    rule_hash_val = _content_hash(rule)
                    for al in v2_alerts:
                        al.detector_type = "rule"
                        al.rule_version = rule_version
                        al.rule_hash = rule_hash_val
                        created_alerts.append(al)
                    health_results.append(RuleExecResult(
                        rule_id=rule_id,
                        rule_version=int(rule.get("rule_version") or 1),
                        content_hash=_content_hash(rule),
                        duration_ms=int((time.monotonic() - t_start) * 1000),
                        alerts_created=len(v2_alerts),
                    ))
                except Exception as exc:
                    log_event(logger, "error", "rule_exec_error", rule_id=rule_id, schema_version=2, error=repr(exc))
                    health_results.append(RuleExecResult(
                        rule_id=rule_id,
                        rule_version=int(rule.get("rule_version") or 1),
                        content_hash=_content_hash(rule),
                        duration_ms=int((time.monotonic() - t_start) * 1000),
                        error=exc,
                    ))
                continue

            rule_type = rule.get("type")

            if rule_type not in ("aggregate_count", "distinct_count", "multi_distinct"):
                continue

            severity = str(rule.get("severity", "low") or "low").strip().lower()
            description = rule.get("description", "")
            mitre = _extract_mitre_meta(rule)

            window_s = rule.get("window", "5m")
            cooldown_s = rule.get("cooldown", "10m")

            try:
                window = timedelta(seconds=_parse_window(window_s))
                cooldown = timedelta(seconds=_parse_window(cooldown_s))
            except Exception as exc:
                log_event(logger, "warning", "rule_window_parse_error", rule_id=rule_id, error=repr(exc))
                window = timedelta(minutes=5)
                cooldown = timedelta(minutes=10)

            since = now - window
            until = now

            match = rule.get("match") or {}
            filters = _build_match_filters(match, since, until)

            _alerts_before = len(created_alerts)
            _events_scanned = 0
            _suppressions_applied = 0

            try:
                if rule_type == "aggregate_count":
                    group_by = rule.get("group_by")
                    group_fields = group_by if isinstance(group_by, list) else [group_by] if isinstance(group_by, str) else []
                    group_fields = [f for f in group_fields if isinstance(f, str) and f in _ALLOWED_EVENT_FIELDS]
                    if not group_fields:
                        continue

                    group_cols = [_safe_col(f) for f in group_fields]
                    condition = rule.get("condition", {}) or {}
                    min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

                    stmt = (
                        select(
                            *[c.label(f) for c, f in zip(group_cols, group_fields, strict=False)],
                            func.count().label("count"),
                        )
                        .where(and_(*filters))
                        .group_by(*group_cols)
                    )

                    rows = db.execute(stmt).all()

                    for row in rows:
                        group_key = {f: row._mapping.get(f) for f in group_fields}
                        count = int(row.count)
                        _events_scanned += count

                        src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)

                        src_ip, dst_ip, enrichment = _enrich_alert_ips(
                            db,
                            rule_id,
                            match or {},
                            group_key,
                            since,
                            until,
                            src_ip,
                            dst_ip,
                            dst_port,
                        )

                        sup_ctx = _build_rule_context(
                            group_key=group_key,
                            match=match or {},
                            rule_id=str(rule_id),
                            severity=severity,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            agent_ctx_map=agent_ctx_map,
                        )
                        eval_cfg = _resolve_tuning_eval(
                            rule,
                            ctx=sup_ctx,
                            base_min_events=min_events,
                            base_condition=condition,
                            base_cooldown_seconds=int(cooldown.total_seconds()),
                            base_severity=severity,
                        )
                        eff_min_events = int(eval_cfg.get("min_events") or 0)
                        eff_condition = eval_cfg.get("condition") if isinstance(eval_cfg.get("condition"), dict) else condition
                        eff_cooldown = timedelta(seconds=max(0, int(eval_cfg.get("cooldown_seconds") or 0)))
                        eff_severity = str(eval_cfg.get("severity") or severity)
                        sup_ctx["severity"] = eff_severity

                        if eff_min_events and count < eff_min_events:
                            continue
                        if not _evaluate_condition(count, eff_condition):
                            continue

                        last_at = _recent_alert_last_at(recent_idx, rule_id, src_ip, dst_ip, dst_port)
                        if last_at and eff_cooldown.total_seconds() > 0 and (now - last_at) < eff_cooldown:
                            continue

                        allowlisted, _ = _is_tuning_allowlisted(rule, sup_ctx)
                        if allowlisted:
                            continue

                        suppressed, _ = _is_suppressed(rule, sup_ctx, now)
                        if suppressed:
                            _suppressions_applied += 1
                            continue

                        details = {
                            "type": rule_type,
                            "group_by": group_fields,
                            "group_key": group_key,
                            "count": count,
                            "window_seconds": int(window.total_seconds()),
                            "enrichment": enrichment,
                            "rule_meta": {
                                "pack": rule.get("pack"),
                                "category": rule.get("category"),
                                "rule_version": int(rule.get("rule_version") or 1),
                            },
                        }
                        if eval_cfg.get("applied_scopes"):
                            details["tuning"] = {
                                "applied_scopes": list(eval_cfg.get("applied_scopes") or []),
                                "effective_min_events": eff_min_events,
                                "effective_condition": eff_condition,
                                "effective_cooldown_seconds": int(eff_cooldown.total_seconds()),
                                "effective_severity": eff_severity,
                            }
                        if enrichment.get("src_ips"):
                            details["src_ips"] = enrichment["src_ips"]
                            details["unique_src_ips"] = enrichment.get("unique_src_ips", 0)

                        if mitre:
                            details["mitre"] = mitre
                        alert = AlertModel(
                            rule_id=rule_id,
                            severity=eff_severity,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            mitre_tactic=mitre.get("tactic"),
                            mitre_technique_id=mitre.get("technique_id"),
                            mitre_technique=mitre.get("technique"),
                            confidence=int(mitre.get("confidence", 50) or 50),
                            description=description,
                            details=details,
                            detector_type="rule",
                            rule_version=int(rule.get("rule_version") or 1),
                            rule_hash=_content_hash(rule),
                        )
                        db.add(alert)
                        created_alerts.append(alert)
                        _index_add(recent_idx, rule_id, src_ip, dst_ip, dst_port)

                elif rule_type == "distinct_count":
                    condition = rule.get("condition", {}) or {}
                    min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

                    distinct_field = rule.get("distinct_field")
                    if not isinstance(distinct_field, str) or distinct_field not in _ALLOWED_EVENT_FIELDS:
                        continue

                    distinct_col = _safe_col(distinct_field)
                    filters2 = list(filters)
                    filters2.append(distinct_col.is_not(None))

                    group_by = rule.get("group_by")
                    group_fields = group_by if isinstance(group_by, list) else [group_by] if isinstance(group_by, str) else []
                    group_fields = [f for f in group_fields if isinstance(f, str) and f in _ALLOWED_EVENT_FIELDS]
                    if not group_fields:
                        continue

                    group_cols = [_safe_col(f) for f in group_fields]

                    stmt = (
                        select(
                            *[c.label(f) for c, f in zip(group_cols, group_fields, strict=False)],
                            func.count(func.distinct(distinct_col)).label("distinct_count"),
                            func.count().label("event_count"),
                        )
                        .where(and_(*filters2))
                        .group_by(*group_cols)
                    )

                    rows = db.execute(stmt).all()

                    for row in rows:
                        group_key = {f: row._mapping.get(f) for f in group_fields}
                        distinct_count = int(row.distinct_count)
                        event_count = int(row.event_count)
                        _events_scanned += event_count

                        src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)

                        src_ip, dst_ip, enrichment = _enrich_alert_ips(
                            db,
                            rule_id,
                            match or {},
                            group_key,
                            since,
                            until,
                            src_ip,
                            dst_ip,
                            dst_port,
                        )

                        sup_ctx = _build_rule_context(
                            group_key=group_key,
                            match=match or {},
                            rule_id=str(rule_id),
                            severity=severity,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            agent_ctx_map=agent_ctx_map,
                        )
                        eval_cfg = _resolve_tuning_eval(
                            rule,
                            ctx=sup_ctx,
                            base_min_events=min_events,
                            base_condition=condition,
                            base_cooldown_seconds=int(cooldown.total_seconds()),
                            base_severity=severity,
                        )
                        eff_min_events = int(eval_cfg.get("min_events") or 0)
                        eff_condition = eval_cfg.get("condition") if isinstance(eval_cfg.get("condition"), dict) else condition
                        eff_cooldown = timedelta(seconds=max(0, int(eval_cfg.get("cooldown_seconds") or 0)))
                        eff_severity = str(eval_cfg.get("severity") or severity)
                        sup_ctx["severity"] = eff_severity

                        if eff_min_events and event_count < eff_min_events:
                            continue
                        if not _evaluate_condition(distinct_count, eff_condition):
                            continue

                        last_at = _recent_alert_last_at(recent_idx, rule_id, src_ip, dst_ip, dst_port)
                        if last_at and eff_cooldown.total_seconds() > 0 and (now - last_at) < eff_cooldown:
                            continue

                        allowlisted, _ = _is_tuning_allowlisted(rule, sup_ctx)
                        if allowlisted:
                            continue

                        suppressed, _ = _is_suppressed(rule, sup_ctx, now)
                        if suppressed:
                            _suppressions_applied += 1
                            continue

                        details = {
                            "type": rule_type,
                            "group_by": group_fields,
                            "group_key": group_key,
                            "distinct_field": distinct_field,
                            "distinct_count": distinct_count,
                            "event_count": event_count,
                            "window_seconds": int(window.total_seconds()),
                            "enrichment": enrichment,
                            "rule_meta": {
                                "pack": rule.get("pack"),
                                "category": rule.get("category"),
                                "rule_version": int(rule.get("rule_version") or 1),
                            },
                        }
                        if eval_cfg.get("applied_scopes"):
                            details["tuning"] = {
                                "applied_scopes": list(eval_cfg.get("applied_scopes") or []),
                                "effective_min_events": eff_min_events,
                                "effective_condition": eff_condition,
                                "effective_cooldown_seconds": int(eff_cooldown.total_seconds()),
                                "effective_severity": eff_severity,
                            }
                        if enrichment.get("src_ips"):
                            details["src_ips"] = enrichment["src_ips"]
                            details["unique_src_ips"] = enrichment.get("unique_src_ips", 0)

                        if mitre:
                            details["mitre"] = mitre
                        alert = AlertModel(
                            rule_id=rule_id,
                            severity=eff_severity,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            mitre_tactic=mitre.get("tactic"),
                            mitre_technique_id=mitre.get("technique_id"),
                            mitre_technique=mitre.get("technique"),
                            confidence=int(mitre.get("confidence", 50) or 50),
                            description=description,
                            details=details,
                            detector_type="rule",
                            rule_version=int(rule.get("rule_version") or 1),
                            rule_hash=_content_hash(rule),
                        )
                        db.add(alert)
                        created_alerts.append(alert)
                        _index_add(recent_idx, rule_id, src_ip, dst_ip, dst_port)

                elif rule_type == "multi_distinct":
                    condition = rule.get("condition", {}) or {}
                    min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

                    group_by = rule.get("group_by")
                    group_fields = group_by if isinstance(group_by, list) else [group_by] if isinstance(group_by, str) else []
                    group_fields = [f for f in group_fields if isinstance(f, str) and f in _ALLOWED_EVENT_FIELDS]
                    if not group_fields:
                        continue

                    distinct_conditions = rule.get("distinct_conditions") or []
                    if not isinstance(distinct_conditions, list) or len(distinct_conditions) == 0:
                        continue

                    dcs = []
                    for dc in distinct_conditions:
                        if not isinstance(dc, dict):
                            continue
                        f = dc.get("field")
                        if not isinstance(f, str) or f not in _ALLOWED_EVENT_FIELDS:
                            continue
                        dcs.append(dc)
                    if not dcs:
                        continue

                    group_cols = [_safe_col(f) for f in group_fields]
                    sel = [c.label(f) for c, f in zip(group_cols, group_fields, strict=False)]
                    sel.append(func.count().label("event_count"))
                    for i, dc in enumerate(dcs):
                        f = dc.get("field")
                        sel.append(func.count(func.distinct(_safe_col(f))).label(f"d{i}"))

                    stmt = select(*sel).where(and_(*filters)).group_by(*group_cols)
                    rows = db.execute(stmt).all()

                    for row in rows:
                        group_key = {f: row._mapping.get(f) for f in group_fields}
                        event_count = int(row.event_count)
                        _events_scanned += event_count

                        src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)

                        src_ip, dst_ip, enrichment = _enrich_alert_ips(
                            db,
                            rule_id,
                            match or {},
                            group_key,
                            since,
                            until,
                            src_ip,
                            dst_ip,
                            dst_port,
                        )

                        sup_ctx = _build_rule_context(
                            group_key=group_key,
                            match=match or {},
                            rule_id=str(rule_id),
                            severity=severity,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            agent_ctx_map=agent_ctx_map,
                        )
                        eval_cfg = _resolve_tuning_eval(
                            rule,
                            ctx=sup_ctx,
                            base_min_events=min_events,
                            base_condition=condition,
                            base_cooldown_seconds=int(cooldown.total_seconds()),
                            base_severity=severity,
                        )
                        eff_min_events = int(eval_cfg.get("min_events") or 0)
                        eff_cooldown = timedelta(seconds=max(0, int(eval_cfg.get("cooldown_seconds") or 0)))
                        eff_severity = str(eval_cfg.get("severity") or severity)
                        sup_ctx["severity"] = eff_severity

                        if eff_min_events and event_count < eff_min_events:
                            continue

                        distinct_result: Dict[str, int] = {}
                        ok = True
                        for i, dc in enumerate(dcs):
                            value = int(row._mapping.get(f"d{i}") or 0)
                            f = dc.get("field")
                            distinct_result[f] = value
                            if not _evaluate_condition(value, dc):
                                ok = False
                                break
                        if not ok:
                            continue

                        last_at = _recent_alert_last_at(recent_idx, rule_id, src_ip, dst_ip, dst_port)
                        if last_at and eff_cooldown.total_seconds() > 0 and (now - last_at) < eff_cooldown:
                            continue

                        allowlisted, _ = _is_tuning_allowlisted(rule, sup_ctx)
                        if allowlisted:
                            continue

                        suppressed, _ = _is_suppressed(rule, sup_ctx, now)
                        if suppressed:
                            _suppressions_applied += 1
                            continue

                        details = {
                            "type": rule_type,
                            "group_by": group_fields,
                            "group_key": group_key,
                            "event_count": event_count,
                            "distinct": distinct_result,
                            "window_seconds": int(window.total_seconds()),
                            "enrichment": enrichment,
                            "rule_meta": {
                                "pack": rule.get("pack"),
                                "category": rule.get("category"),
                                "rule_version": int(rule.get("rule_version") or 1),
                            },
                        }
                        if eval_cfg.get("applied_scopes"):
                            details["tuning"] = {
                                "applied_scopes": list(eval_cfg.get("applied_scopes") or []),
                                "effective_min_events": eff_min_events,
                                "effective_condition": condition,
                                "effective_cooldown_seconds": int(eff_cooldown.total_seconds()),
                                "effective_severity": eff_severity,
                            }
                        if enrichment.get("src_ips"):
                            details["src_ips"] = enrichment["src_ips"]
                            details["unique_src_ips"] = enrichment.get("unique_src_ips", 0)

                        if mitre:
                            details["mitre"] = mitre
                        alert = AlertModel(
                            rule_id=rule_id,
                            severity=eff_severity,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            mitre_tactic=mitre.get("tactic"),
                            mitre_technique_id=mitre.get("technique_id"),
                            mitre_technique=mitre.get("technique"),
                            confidence=int(mitre.get("confidence", 50) or 50),
                            description=description,
                            details=details,
                            detector_type="rule",
                            rule_version=int(rule.get("rule_version") or 1),
                            rule_hash=_content_hash(rule),
                        )
                        db.add(alert)
                        created_alerts.append(alert)
                        _index_add(recent_idx, rule_id, src_ip, dst_ip, dst_port)

                health_results.append(RuleExecResult(
                    rule_id=rule_id,
                    rule_version=int(rule.get("rule_version") or 1),
                    content_hash=_content_hash(rule),
                    duration_ms=int((time.monotonic() - t_start) * 1000),
                    alerts_created=len(created_alerts) - _alerts_before,
                    suppressions_applied=_suppressions_applied,
                    events_scanned=_events_scanned,
                ))

            except Exception as exc:
                log_event(
                    logger, "error", "rule_exec_error",
                    rule_id=rule_id, rule_type=rule_type, schema_version=1, error=repr(exc),
                )
                health_results.append(RuleExecResult(
                    rule_id=rule_id,
                    rule_version=int(rule.get("rule_version") or 1),
                    content_hash=_content_hash(rule),
                    duration_ms=int((time.monotonic() - t_start) * 1000),
                    alerts_created=len(created_alerts) - _alerts_before,
                    error=exc,
                ))

        try:
            _, heuristic_alerts = _emit_heuristic_signals(db, now)
            if heuristic_alerts:
                for al in heuristic_alerts:
                    al.detector_type = "heuristic"
                    db.add(al)
                created_alerts.extend(heuristic_alerts)
        except Exception as exc:
            log_event(logger, "error", "heuristic_signals_error", error=repr(exc))

        try:
            correlated = _correlate_ddos_incidents(db, now, created_alerts)
            if correlated:
                created_alerts.extend(correlated)
        except Exception as exc:
            log_event(logger, "error", "ddos_correlation_error", error=repr(exc))

        if created_alerts:
            try:
                db.flush()
                for alert in created_alerts:
                    for spec in extract_evidence_specs(alert):
                        db.add(AlertEvidenceModel(alert_id=alert.id, **spec))
            except Exception as exc:
                log_event(logger, "error", "evidence_flush_error", error=repr(exc))

        flush_cycle_health(db, health_results, existing_health, now)
        db.commit()
        for alert in created_alerts:
            publish_alert_created_from_row(alert)
    finally:
        db.close()

    return created_alerts


def run_all_rules():
    return run_rules_once()
