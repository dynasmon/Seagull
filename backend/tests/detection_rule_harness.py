from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Tuple

from app.features.events.schemas import NetEvent
from app.workers.intelligence.rules.loader import load_rules


_ALLOWED_EVENT_FIELDS = {
    "agent_id",
    "event_type",
    "timestamp",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "proto",
    "bytes",
    "app_proto",
    "app_proto_reason",
    "app_proto_conf_band",
    "dns_qname",
    "http_host",
    "http_method",
    "tls_sni",
    "tls_alpn_first",
    "ja3",
    "ja4",
    "ja4_ptype",
    "ssh_action",
    "ssh_username",
    "proc_pid",
    "proc_ppid",
    "proc_name",
    "proc_exe",
    "proc_parent_name",
    "fim_path",
    "fim_category",
    "heuristic_name",
    "heuristic_confidence",
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
        ("_not_contains", "not_contains"),
        ("_contains_all", "contains_all"),
        ("_contains", "contains"),
        ("_startswith", "startswith"),
        ("_endswith", "endswith"),
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
    if op in {"contains", "not_contains", "contains_all", "startswith", "endswith"}:
        terms = expected if isinstance(expected, list) else [expected]
        terms_n = [str(x).strip().lower() for x in terms if str(x).strip()]
        if not terms_n:
            return False
        text = str(actual or "").lower()
        if op == "contains":
            return any(t in text for t in terms_n)
        if op == "contains_all":
            return all(t in text for t in terms_n)
        if op == "not_contains":
            return all(t not in text for t in terms_n)
        if op == "startswith":
            return any(text.startswith(t) for t in terms_n)
        return any(text.endswith(t) for t in terms_n)

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
            ("_not_contains", "not_contains"),
            ("_contains_all", "contains_all"),
            ("_contains", "contains"),
            ("_startswith", "startswith"),
            ("_endswith", "endswith"),
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


def _hot_fields(event_type: str, extra: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(extra, dict):
        extra = {}
    out: Dict[str, Any] = {
        "app_proto": extra.get("app_proto"),
        "app_proto_reason": extra.get("app_proto_reason"),
        "app_proto_conf_band": extra.get("app_proto_conf_band"),
        "dns_qname": str(extra.get("dns_qname") or "").lower() or None,
        "http_host": str(extra.get("http_host") or "").lower() or None,
        "http_method": str(extra.get("http_method") or "").upper() or None,
        "tls_sni": str(extra.get("tls_sni") or "").lower() or None,
        "tls_alpn_first": str(extra.get("tls_alpn_first") or "").lower() or None,
        "ja3": extra.get("ja3"),
        "ja4": extra.get("ja4"),
        "ja4_ptype": extra.get("ja4_ptype"),
        "ssh_action": None,
        "ssh_username": None,
        "proc_pid": None,
        "proc_ppid": None,
        "proc_name": None,
        "proc_exe": None,
        "proc_parent_name": None,
        "fim_path": None,
        "fim_category": None,
        "heuristic_name": None,
        "heuristic_confidence": None,
    }
    if event_type == "ssh_auth":
        out["ssh_action"] = extra.get("action")
        out["ssh_username"] = extra.get("username")
    if event_type == "proc_exec":
        out["proc_name"] = extra.get("exe_name") or extra.get("comm") or extra.get("binary")
        out["proc_exe"] = extra.get("exe_path")
        try:
            out["proc_pid"] = int(extra.get("pid"))
        except Exception:
            pass
        try:
            out["proc_ppid"] = int(extra.get("ppid"))
        except Exception:
            pass
        out["proc_parent_name"] = extra.get("parent_exe_name") or extra.get("parent_comm")
    if event_type in {"fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"}:
        out["fim_path"] = extra.get("path")
        out["fim_category"] = extra.get("path_category")
    if event_type in {"beacon_suspect", "c2_suspect", "exfil_suspect", "egress_anomaly"}:
        out["heuristic_name"] = extra.get("heuristic_name") or extra.get("heuristic_kind") or extra.get("reason_kind")
        try:
            out["heuristic_confidence"] = int(extra.get("confidence"))
        except Exception:
            out["heuristic_confidence"] = None
    return out


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
        extra = ev.get("extra") if isinstance(ev.get("extra"), dict) else {}
        ev.update(_hot_fields(str(ev.get("event_type") or ""), extra))
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
