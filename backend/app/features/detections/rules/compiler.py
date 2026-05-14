"""V2 detection rule compiler and executor.

Translates normalized v2 rule dicts (with parsed DetectionBlock) into
SQLAlchemy queries against NetEventModel and returns AlertModel instances.
"""

from __future__ import annotations

import operator as _py_op
from datetime import datetime, timedelta
from functools import reduce
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, case, func, not_, or_, select
from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel
from app.features.detections.domain.condition_ast import (
    BinaryExpression,
    DetectionBlock,
    DetectionSelection,
    FieldPredicate,
    PatternReference,
    SelectionReference,
    UnaryExpression,
)
from app.features.events.worker_runtime import NetEventModel
from app.workers.intelligence.rules.conditions import (
    _ALLOWED_EVENT_FIELDS,
    _enrich_alert_ips,
    _evaluate_condition,
    _extract_alert_key,
    _parse_window,
    _safe_col,
)
from app.workers.intelligence.rules.dedup import _index_add, _recent_alert_last_at
from app.workers.intelligence.rules.mitre import _extract_mitre_meta
from app.workers.intelligence.rules.suppression import _is_suppressed
from app.workers.intelligence.rules.tuning import (
    _build_rule_context,
    _is_tuning_allowlisted,
    _resolve_tuning_eval,
)


def _v2_mitre_meta(rule: Dict[str, Any]) -> Dict[str, Any]:
    attack = rule.get("attack")
    if isinstance(attack, dict) and attack:
        return _extract_mitre_meta({"mitre": attack})
    return _extract_mitre_meta(rule)


def _v2_resolve_params(
    rule: Dict[str, Any],
) -> Tuple[timedelta, timedelta, Dict[str, Any], int, str]:
    agg = rule.get("aggregation") or {}
    suppression = rule.get("suppression") or {}

    window_s = agg.get("window") or rule.get("window") or "5m"
    cooldown_s = suppression.get("cooldown") or rule.get("cooldown") or "10m"
    min_events = int(agg.get("min_events") or rule.get("min_events") or 0)
    condition = agg.get("condition") or rule.get("condition") or {}
    severity = str(rule.get("severity") or "low").strip().lower()

    try:
        window = timedelta(seconds=_parse_window(window_s))
    except Exception:
        window = timedelta(minutes=5)
    try:
        cooldown = timedelta(seconds=_parse_window(cooldown_s))
    except Exception:
        cooldown = timedelta(minutes=10)

    return window, cooldown, condition, min_events, severity


def _v2_suppressions(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    # DB suppressions (written by apply_tuning_and_suppressions) take precedence over YAML.
    if "suppressions" in rule:
        return list(rule["suppressions"] or [])
    suppression = rule.get("suppression") or {}
    return list(suppression.get("rules") or [])


def _predicate_to_sqla(pred: FieldPredicate):
    if pred.runtime_field not in _ALLOWED_EVENT_FIELDS:
        raise ValueError(f"Unsupported runtime field in v2 predicate: {pred.runtime_field}")
    col = _safe_col(pred.runtime_field)
    op = pred.operator
    val = pred.value

    if op == "eq":
        return col == val
    if op == "neq":
        return col != val
    if op == "gt":
        return col > val
    if op == "gte":
        return col >= val
    if op == "lt":
        return col < val
    if op == "lte":
        return col <= val
    if op == "in":
        items = list(val) if isinstance(val, (list, tuple)) else [val]
        return col.in_(items)
    if op == "not_in":
        items = list(val) if isinstance(val, (list, tuple)) else [val]
        return or_(col.is_(None), ~col.in_(items))
    if op == "contains":
        if isinstance(val, (list, tuple)):
            return or_(*[func.lower(col).like(f"%{v.lower()}%") for v in val])
        return func.lower(col).like(f"%{str(val).lower()}%")
    if op == "not_contains":
        if isinstance(val, (list, tuple)):
            return or_(col.is_(None), and_(*[~func.lower(col).like(f"%{v.lower()}%") for v in val]))
        return or_(col.is_(None), ~func.lower(col).like(f"%{str(val).lower()}%"))
    if op == "contains_all":
        items = list(val) if isinstance(val, (list, tuple)) else [val]
        return and_(*[func.lower(col).like(f"%{v.lower()}%") for v in items])
    if op == "startswith":
        if isinstance(val, (list, tuple)):
            return or_(*[func.lower(col).like(f"{v.lower()}%") for v in val])
        return func.lower(col).like(f"{str(val).lower()}%")
    if op == "endswith":
        if isinstance(val, (list, tuple)):
            return or_(*[func.lower(col).like(f"%{v.lower()}") for v in val])
        return func.lower(col).like(f"%{str(val).lower()}")
    if op == "exists":
        return col.is_not(None)
    if op == "not_exists":
        return col.is_(None)
    return col == val


def _selection_to_sqla(sel: DetectionSelection):
    parts = [_predicate_to_sqla(p) for p in sel.predicates]
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return and_(*parts)


def _expression_to_sqla(node: Any, sel_map: Dict[str, DetectionSelection]):
    if isinstance(node, SelectionReference):
        return _selection_to_sqla(sel_map[node.name])

    if isinstance(node, BinaryExpression):
        left = _expression_to_sqla(node.left, sel_map)
        right = _expression_to_sqla(node.right, sel_map)
        if node.operator == "and":
            return and_(left, right)
        if node.operator == "or":
            return or_(left, right)

    if isinstance(node, UnaryExpression) and node.operator == "not":
        return not_(_expression_to_sqla(node.operand, sel_map))

    if isinstance(node, PatternReference):
        matched = [_selection_to_sqla(sel_map[name]) for name in node.matches]
        if not matched:
            return None
        if node.quantifier == "all" or node.quantifier == len(node.matches):
            return and_(*matched)
        if node.quantifier == 1:
            return or_(*matched)
        # At least N of M using a sum of CASE WHEN expressions.
        cases = [case((f, 1), else_=0) for f in matched]
        return reduce(_py_op.add, cases) >= int(node.quantifier)

    raise ValueError(f"Unsupported condition AST node: {type(node).__name__}")


def compile_detection_filters(
    detection: DetectionBlock,
    since: datetime,
    until: datetime,
) -> List:
    filters: List = [
        NetEventModel.timestamp >= since,
        NetEventModel.timestamp < until,
    ]
    sel_map = {sel.name: sel for sel in detection.selections}
    expr = _expression_to_sqla(detection.condition.expression, sel_map)
    if expr is not None:
        filters.append(expr)
    return filters


def _build_v2_details(
    *,
    agg_type: str,
    group_fields: List[str],
    group_key: Dict[str, Any],
    window: timedelta,
    enrichment: Dict[str, Any],
    rule: Dict[str, Any],
    eval_cfg: Dict[str, Any],
    eff_min_events: int,
    eff_condition: Dict[str, Any],
    eff_cooldown: timedelta,
    eff_severity: str,
    mitre: Dict[str, Any],
    count: Optional[int] = None,
    distinct_field: Optional[str] = None,
    distinct_count: Optional[int] = None,
    event_count: Optional[int] = None,
    distinct_results: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    details: Dict[str, Any] = {
        "schema_version": 2,
        "type": agg_type,
        "group_by": group_fields,
        "group_key": group_key,
        "window_seconds": int(window.total_seconds()),
        "enrichment": enrichment,
        "rule_meta": {
            "pack": rule.get("pack"),
            "category": rule.get("category"),
            "rule_version": int(rule.get("rule_version") or 1),
        },
    }
    if count is not None:
        details["count"] = count
    if distinct_field is not None:
        details["distinct_field"] = distinct_field
    if distinct_count is not None:
        details["distinct_count"] = distinct_count
    if event_count is not None:
        details["event_count"] = event_count
    if distinct_results is not None:
        details["distinct"] = distinct_results
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
    return details


def _run_governance(
    *,
    db: Session,
    rule: Dict[str, Any],
    rule_id: str,
    group_key: Dict[str, Any],
    match_hints: Dict[str, Any],
    since: datetime,
    until: datetime,
    base_condition: Dict[str, Any],
    base_min_events: int,
    cooldown: timedelta,
    severity: str,
    now: datetime,
    recent_idx: Dict,
    agent_ctx_map: Dict[str, Dict[str, Any]],
    effective_suppressions: List[Dict[str, Any]],
    count_value: int,
    min_events_check: int,
) -> Optional[Tuple[Optional[str], Optional[str], Optional[int], Dict[str, Any], Dict[str, Any], timedelta, str]]:
    """Run governance checks for a row.

    Returns (src_ip, dst_ip, dst_port, enrichment, eval_cfg, eff_cooldown, eff_severity)
    if the row passes all checks, or None if it should be skipped.
    """
    src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match_hints)
    src_ip, dst_ip, enrichment = _enrich_alert_ips(
        db, rule_id, match_hints, group_key, since, until, src_ip, dst_ip, dst_port
    )

    sup_ctx = _build_rule_context(
        group_key=group_key,
        match=match_hints,
        rule_id=rule_id,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        agent_ctx_map=agent_ctx_map,
    )
    eval_cfg = _resolve_tuning_eval(
        rule,
        ctx=sup_ctx,
        base_min_events=base_min_events,
        base_condition=base_condition,
        base_cooldown_seconds=int(cooldown.total_seconds()),
        base_severity=severity,
    )
    eff_min_events = int(eval_cfg.get("min_events") or 0)
    eff_condition = eval_cfg.get("condition") if isinstance(eval_cfg.get("condition"), dict) else base_condition
    eff_cooldown = timedelta(seconds=max(0, int(eval_cfg.get("cooldown_seconds") or 0)))
    eff_severity = str(eval_cfg.get("severity") or severity)
    sup_ctx["severity"] = eff_severity

    if eff_min_events and min_events_check < eff_min_events:
        return None
    if not _evaluate_condition(count_value, eff_condition):
        return None

    last_at = _recent_alert_last_at(recent_idx, rule_id, src_ip, dst_ip, dst_port)
    if last_at and eff_cooldown.total_seconds() > 0 and (now - last_at) < eff_cooldown:
        return None

    allowlisted, _ = _is_tuning_allowlisted(rule, sup_ctx)
    if allowlisted:
        return None

    rule_for_sup = {**rule, "suppressions": effective_suppressions}
    suppressed, _ = _is_suppressed(rule_for_sup, sup_ctx, now)
    if suppressed:
        return None

    return src_ip, dst_ip, dst_port, enrichment, eval_cfg, eff_min_events, eff_condition, eff_cooldown, eff_severity


def execute_v2_rule(
    db: Session,
    rule: Dict[str, Any],
    now: datetime,
    recent_idx: Dict,
    agent_ctx_map: Dict[str, Dict[str, Any]],
) -> List[AlertModel]:
    detection = rule.get("detection")
    if not isinstance(detection, DetectionBlock):
        return []

    agg = rule.get("aggregation") or {}
    agg_type = str(agg.get("type") or "").strip().lower()
    if agg_type not in ("threshold", "cardinality", "multi_cardinality"):
        return []

    rule_id = str(rule.get("id") or "").strip()
    if not rule_id:
        return []

    window, cooldown, base_condition, base_min_events, severity = _v2_resolve_params(rule)
    effective_suppressions = _v2_suppressions(rule)
    mitre = _v2_mitre_meta(rule)
    description = str(rule.get("description") or "")

    since = now - window
    until = now

    try:
        filters = compile_detection_filters(detection, since, until)
    except Exception:
        return []

    group_by_raw = agg.get("group_by")
    group_fields = (
        group_by_raw if isinstance(group_by_raw, list)
        else [group_by_raw] if isinstance(group_by_raw, str)
        else []
    )
    group_fields = [f for f in group_fields if isinstance(f, str) and f in _ALLOWED_EVENT_FIELDS]
    if not group_fields:
        return []

    group_cols = [_safe_col(f) for f in group_fields]

    logsource = rule.get("logsource") or {}
    match_hints: Dict[str, Any] = {}
    if logsource.get("event_type"):
        match_hints["event_type"] = logsource["event_type"]

    created: List[AlertModel] = []

    if agg_type == "threshold":
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

            result = _run_governance(
                db=db,
                rule=rule,
                rule_id=rule_id,
                group_key=group_key,
                match_hints=match_hints,
                since=since,
                until=until,
                base_condition=base_condition,
                base_min_events=base_min_events,
                cooldown=cooldown,
                severity=severity,
                now=now,
                recent_idx=recent_idx,
                agent_ctx_map=agent_ctx_map,
                effective_suppressions=effective_suppressions,
                count_value=count,
                min_events_check=count,
            )
            if result is None:
                continue

            src_ip, dst_ip, dst_port, enrichment, eval_cfg, eff_min_events, eff_condition, eff_cooldown, eff_severity = result
            details = _build_v2_details(
                agg_type=agg_type,
                group_fields=group_fields,
                group_key=group_key,
                window=window,
                enrichment=enrichment,
                rule=rule,
                eval_cfg=eval_cfg,
                eff_min_events=eff_min_events,
                eff_condition=eff_condition,
                eff_cooldown=eff_cooldown,
                eff_severity=eff_severity,
                mitre=mitre,
                count=count,
            )
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
            )
            db.add(alert)
            created.append(alert)
            _index_add(recent_idx, rule_id, src_ip, dst_ip, dst_port)

    elif agg_type == "cardinality":
        distinct_field = str(agg.get("field") or "").strip()
        if not distinct_field or distinct_field not in _ALLOWED_EVENT_FIELDS:
            return []

        distinct_col = _safe_col(distinct_field)
        card_filters = list(filters) + [distinct_col.is_not(None)]

        stmt = (
            select(
                *[c.label(f) for c, f in zip(group_cols, group_fields, strict=False)],
                func.count(func.distinct(distinct_col)).label("distinct_count"),
                func.count().label("event_count"),
            )
            .where(and_(*card_filters))
            .group_by(*group_cols)
        )
        rows = db.execute(stmt).all()

        for row in rows:
            group_key = {f: row._mapping.get(f) for f in group_fields}
            distinct_count = int(row.distinct_count)
            event_count = int(row.event_count)

            result = _run_governance(
                db=db,
                rule=rule,
                rule_id=rule_id,
                group_key=group_key,
                match_hints=match_hints,
                since=since,
                until=until,
                base_condition=base_condition,
                base_min_events=base_min_events,
                cooldown=cooldown,
                severity=severity,
                now=now,
                recent_idx=recent_idx,
                agent_ctx_map=agent_ctx_map,
                effective_suppressions=effective_suppressions,
                count_value=distinct_count,
                min_events_check=event_count,
            )
            if result is None:
                continue

            src_ip, dst_ip, dst_port, enrichment, eval_cfg, eff_min_events, eff_condition, eff_cooldown, eff_severity = result
            details = _build_v2_details(
                agg_type=agg_type,
                group_fields=group_fields,
                group_key=group_key,
                window=window,
                enrichment=enrichment,
                rule=rule,
                eval_cfg=eval_cfg,
                eff_min_events=eff_min_events,
                eff_condition=eff_condition,
                eff_cooldown=eff_cooldown,
                eff_severity=eff_severity,
                mitre=mitre,
                distinct_field=distinct_field,
                distinct_count=distinct_count,
                event_count=event_count,
            )
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
            )
            db.add(alert)
            created.append(alert)
            _index_add(recent_idx, rule_id, src_ip, dst_ip, dst_port)

    elif agg_type == "multi_cardinality":
        distinct_conditions_raw = agg.get("distinct_conditions") or []
        if not isinstance(distinct_conditions_raw, list) or not distinct_conditions_raw:
            return []

        dcs = [
            dc for dc in distinct_conditions_raw
            if isinstance(dc, dict) and isinstance(dc.get("field"), str) and dc["field"] in _ALLOWED_EVENT_FIELDS
        ]
        if not dcs:
            return []

        sel = [c.label(f) for c, f in zip(group_cols, group_fields, strict=False)]
        sel.append(func.count().label("event_count"))
        for i, dc in enumerate(dcs):
            sel.append(func.count(func.distinct(_safe_col(dc["field"]))).label(f"d{i}"))

        stmt = select(*sel).where(and_(*filters)).group_by(*group_cols)
        rows = db.execute(stmt).all()

        for row in rows:
            group_key = {f: row._mapping.get(f) for f in group_fields}
            event_count = int(row.event_count)

            distinct_results: Dict[str, int] = {}
            ok = True
            for i, dc in enumerate(dcs):
                dc_value = int(row._mapping.get(f"d{i}") or 0)
                distinct_results[dc["field"]] = dc_value
                if not _evaluate_condition(dc_value, dc):
                    ok = False
                    break
            if not ok:
                continue

            result = _run_governance(
                db=db,
                rule=rule,
                rule_id=rule_id,
                group_key=group_key,
                match_hints=match_hints,
                since=since,
                until=until,
                base_condition=base_condition,
                base_min_events=base_min_events,
                cooldown=cooldown,
                severity=severity,
                now=now,
                recent_idx=recent_idx,
                agent_ctx_map=agent_ctx_map,
                effective_suppressions=effective_suppressions,
                count_value=event_count,
                min_events_check=event_count,
            )
            if result is None:
                continue

            src_ip, dst_ip, dst_port, enrichment, eval_cfg, eff_min_events, eff_condition, eff_cooldown, eff_severity = result
            details = _build_v2_details(
                agg_type=agg_type,
                group_fields=group_fields,
                group_key=group_key,
                window=window,
                enrichment=enrichment,
                rule=rule,
                eval_cfg=eval_cfg,
                eff_min_events=eff_min_events,
                eff_condition=eff_condition,
                eff_cooldown=eff_cooldown,
                eff_severity=eff_severity,
                mitre=mitre,
                event_count=event_count,
                distinct_results=distinct_results,
            )
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
            )
            db.add(alert)
            created.append(alert)
            _index_add(recent_idx, rule_id, src_ip, dst_ip, dst_port)

    return created
