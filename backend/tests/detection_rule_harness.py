from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Tuple

from app.schemas.events import NetEvent
from app.workers.rules_loader import load_rules


_ALLOWED_EVENT_FIELDS = {
    "agent_id",
    "event_type",
    "src_ip",
    "dst_ip",
    "dst_port",
    "src_port",
    "proto",
    "bytes",
}


def _parse_window(raw: Any) -> int:
    s = str(raw or "").strip().lower()
    if s.endswith("ms"):
        return int(float(s[:-2]) / 1000.0)
    if s.endswith("s"):
        return int(float(s[:-1]))
    if s.endswith("m"):
        return int(float(s[:-1]) * 60)
    if s.endswith("h"):
        return int(float(s[:-1]) * 3600)
    return int(float(s or 0))


def _coerce_num(v: Any) -> float | None:
    if isinstance(v, bool) or v is None:
        return None
    try:
        return float(v)
    except Exception:
        return None


def _eq(a: Any, b: Any) -> bool:
    if isinstance(b, bool):
        return str(a).strip().lower() == ("true" if b else "false")
    return str(a) == str(b)


def _parse_field_op(raw_key: str) -> Tuple[str | None, str | None]:
    for suffix, op in (
        ("_not_in", "not_in"),
        ("_in", "in"),
        ("_gte", "gte"),
        ("_gt", "gt"),
        ("_lte", "lte"),
        ("_lt", "lt"),
        ("_neq", "neq"),
    ):
        if raw_key.endswith(suffix):
            return raw_key[: -len(suffix)], op
    return None, None


def _evaluate_op(actual: Any, op: str, expected: Any) -> bool:
    if op in {"in", "not_in"}:
        items = expected if isinstance(expected, list) else [expected]
        matched = any(_eq(actual, x) for x in items)
        return matched if op == "in" else (not matched)

    if op in {"gte", "gt", "lte", "lt"}:
        lhs = _coerce_num(actual)
        rhs = _coerce_num(expected)
        if lhs is None or rhs is None:
            return False
        if op == "gte":
            return lhs >= rhs
        if op == "gt":
            return lhs > rhs
        if op == "lte":
            return lhs <= rhs
        return lhs < rhs

    if op == "neq":
        return not _eq(actual, expected)

    return _eq(actual, expected)


def _event_matches(match: Dict[str, Any], event: Dict[str, Any]) -> bool:
    extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}

    for key, expected in (match or {}).items():
        if key in _ALLOWED_EVENT_FIELDS:
            if not _eq(event.get(key), expected):
                return False
            continue

        base, op = _parse_field_op(key)
        if base and op and base in _ALLOWED_EVENT_FIELDS:
            if not _evaluate_op(event.get(base), op, expected):
                return False
            continue

        if not key.startswith("extra_"):
            continue

        extra_key = key[len("extra_") :]
        op_key = "eq"
        for suffix, op_name in (
            ("_not_in", "not_in"),
            ("_in", "in"),
            ("_gte", "gte"),
            ("_gt", "gt"),
            ("_lte", "lte"),
            ("_lt", "lt"),
            ("_neq", "neq"),
        ):
            if extra_key.endswith(suffix):
                extra_key = extra_key[: -len(suffix)]
                op_key = op_name
                break

        if not _evaluate_op(extra.get(extra_key), op_key, expected):
            return False

    return True


def _group_key(fields: List[str], event: Dict[str, Any]) -> Tuple[Any, ...]:
    return tuple(event.get(f) for f in fields)


def _condition_ok(value: int, condition: Dict[str, Any]) -> bool:
    op = str((condition or {}).get("operator") or ">=").strip()
    target = int((condition or {}).get("value") or 0)
    if op == ">=":
        return value >= target
    if op == ">":
        return value > target
    if op == "<=":
        return value <= target
    if op == "<":
        return value < target
    if op == "==":
        return value == target
    if op == "!=":
        return value != target
    return value >= target


def evaluate_rule(rule: Dict[str, Any], events: Iterable[Dict[str, Any]], now: datetime) -> List[Dict[str, Any]]:
    window = timedelta(seconds=max(1, _parse_window(rule.get("window") or "5m")))
    since = now - window

    group_fields = rule.get("group_by")
    if isinstance(group_fields, str):
        group_fields = [group_fields]
    if not isinstance(group_fields, list):
        return []
    group_fields = [f for f in group_fields if f in _ALLOWED_EVENT_FIELDS]
    if not group_fields:
        return []

    normalized_events: list[Dict[str, Any]] = []
    for raw in events:
        parsed = NetEvent(**raw)
        ev = parsed.dict() if hasattr(parsed, "dict") else parsed.model_dump()
        ts = ev["timestamp"]
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        ts = ts.astimezone(timezone.utc)
        if ts < since or ts > now:
            continue
        if _event_matches(rule.get("match") or {}, ev):
            normalized_events.append(ev)

    if not normalized_events:
        return []

    min_events = int(rule.get("min_events") or rule.get("condition", {}).get("min_events") or 0)
    condition = rule.get("condition") or {}

    by_group: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)
    for ev in normalized_events:
        by_group[_group_key(group_fields, ev)].append(ev)

    hits: list[Dict[str, Any]] = []
    rtype = str(rule.get("type") or "").strip()

    for gk, rows in by_group.items():
        if min_events and len(rows) < min_events:
            continue

        if rtype == "aggregate_count":
            val = len(rows)
            if _condition_ok(val, condition):
                hits.append({"group_key": dict(zip(group_fields, gk)), "count": val})
            continue

        if rtype == "distinct_count":
            df = str(rule.get("distinct_field") or "")
            if df not in _ALLOWED_EVENT_FIELDS:
                continue
            vals = {r.get(df) for r in rows if r.get(df) is not None}
            val = len(vals)
            if _condition_ok(val, condition):
                hits.append({"group_key": dict(zip(group_fields, gk)), "distinct_count": val, "event_count": len(rows)})
            continue

        if rtype == "multi_distinct":
            dcs = rule.get("distinct_conditions")
            if not isinstance(dcs, list) or not dcs:
                continue
            ok = True
            dist: Dict[str, int] = {}
            for dc in dcs:
                field = str((dc or {}).get("field") or "")
                if field not in _ALLOWED_EVENT_FIELDS:
                    ok = False
                    break
                val = len({r.get(field) for r in rows if r.get(field) is not None})
                dist[field] = val
                if not _condition_ok(val, dc or {}):
                    ok = False
                    break
            if ok:
                hits.append({"group_key": dict(zip(group_fields, gk)), "distinct": dist, "event_count": len(rows)})

    return hits


def load_rule_index(rules_dir: str) -> Dict[str, Dict[str, Any]]:
    rules = load_rules(include_disabled=True, with_source=True, rules_dir=rules_dir, apply_env_filters=False)
    return {str(r.get("id")): r for r in rules if r.get("id")}
