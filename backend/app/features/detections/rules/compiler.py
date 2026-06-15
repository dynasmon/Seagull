from __future__ import annotations

import operator as _py_op
from datetime import datetime, timedelta
from functools import reduce
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, case, func, not_, or_

from app.features.detections.domain.condition_ast import (
    BinaryExpression,
    DetectionBlock,
    DetectionSelection,
    FieldPredicate,
    PatternReference,
    SelectionReference,
    UnaryExpression,
)
from app.features.detections.domain.scoring import build_rule_provenance
from app.features.events.worker_runtime import NetEventModel
from app.workers.intelligence.rules.conditions import (
    _ALLOWED_EVENT_FIELDS,
    _parse_window,
    _safe_col,
)
from app.workers.intelligence.rules.mitre import _extract_mitre_meta


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
        "rule_meta": build_rule_provenance(rule),
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
