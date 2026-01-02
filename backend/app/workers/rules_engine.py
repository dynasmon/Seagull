from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

from sqlalchemy import and_, cast, func, select, String


from app.core.db import SessionLocal
from app.models.alerts import AlertModel
from app.models.events import NetEventModel
from app.workers.rules_loader import load_rules


_ALLOWED_EVENT_FIELDS = {
    "event_type",
    "proto",
    "agent_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "bytes",
}


def parse_window(window_str: str) -> timedelta:
    window_str = (window_str or "").strip().lower()
    if len(window_str) < 2:
        raise ValueError(f"Invalid window: {window_str!r}")

    unit = window_str[-1]
    raw = window_str[:-1].strip()
    try:
        value = int(raw)
    except Exception as e:
        raise ValueError(f"Invalid window value: {window_str!r}") from e

    if value <= 0:
        raise ValueError(f"Window must be > 0: {window_str!r}")

    if unit == "s":
        return timedelta(seconds=value)
    if unit == "m":
        return timedelta(minutes=value)
    if unit == "h":
        return timedelta(hours=value)
    if unit == "d":
        return timedelta(days=value)

    raise ValueError(f"Unsupported window unit: {unit} in {window_str}")


def _normalize_group_by(group_by: Any) -> List[str]:
    if isinstance(group_by, str):
        return [group_by]
    if isinstance(group_by, list) and all(isinstance(x, str) for x in group_by):
        return group_by
    raise ValueError(f"Invalid group_by: expected str|list[str], got {type(group_by).__name__}")


def _safe_col(field: str):
    if field not in _ALLOWED_EVENT_FIELDS:
        raise ValueError(f"Unsupported field: {field}")
    return getattr(NetEventModel, field)


def _is_safe_extra_key(k: str) -> bool:
    # Keep it strict to avoid weird JSON path abuse
    return k.replace("_", "").isalnum()


def _extra_text_col(extra_key: str):
    col = NetEventModel.extra[extra_key]
    if hasattr(col, "as_string"):
        return col.as_string()
    return cast(col, String)

def _build_match_filters(rule: Dict[str, Any]):
    match = rule.get("match", {}) or {}
    filters = []

    for key, val in match.items():
        # extra_*_in support (JSON)
        if key.startswith("extra_") and key.endswith("_in"):
            extra_key = key[len("extra_") : -3]
            if _is_safe_extra_key(extra_key) and isinstance(val, list) and val:
                filters.append(_extra_text_col(extra_key).in_([str(x) for x in val]))
            continue

        # extra_*_not_in support (JSON)
        if key.startswith("extra_") and key.endswith("_not_in"):
            extra_key = key[len("extra_") : -7]
            if _is_safe_extra_key(extra_key) and isinstance(val, list) and val:
                filters.append(~_extra_text_col(extra_key).in_([str(x) for x in val]))
            continue

        # extra_* equality support (JSON)
        if key.startswith("extra_"):
            extra_key = key[len("extra_") :]
            if _is_safe_extra_key(extra_key) and val is not None:
                filters.append(_extra_text_col(extra_key) == str(val))
            continue

        # base fields
        if key.endswith("_in"):
            base = key[:-3]
            if base in _ALLOWED_EVENT_FIELDS and isinstance(val, list) and val:
                filters.append(_safe_col(base).in_(val))
            continue

        if key.endswith("_not_in"):
            base = key[:-7]
            if base in _ALLOWED_EVENT_FIELDS and isinstance(val, list) and val:
                filters.append(~_safe_col(base).in_(val))
            continue

        if key in _ALLOWED_EVENT_FIELDS:
            filters.append(_safe_col(key) == val)

    return filters


def _evaluate_condition(value: int, condition: Dict[str, Any]) -> bool:
    op = condition.get("operator")
    threshold = int(condition.get("value", 0))

    if op == ">=":
        return value >= threshold
    if op == ">":
        return value > threshold
    if op == "==":
        return value == threshold
    if op == "<=":
        return value <= threshold
    if op == "<":
        return value < threshold

    raise ValueError(f"Unsupported operator in condition: {op}")


def _extract_alert_key(group_key: Dict[str, Any], match: Dict[str, Any]) -> Tuple[str | None, str | None, int | None]:
    src_ip = group_key.get("src_ip") if "src_ip" in group_key else match.get("src_ip")
    dst_ip = group_key.get("dst_ip") if "dst_ip" in group_key else match.get("dst_ip")

    dst_port = group_key.get("dst_port") if "dst_port" in group_key else match.get("dst_port")
    if isinstance(dst_port, str) and dst_port.isdigit():
        dst_port = int(dst_port)
    if not isinstance(dst_port, int):
        dst_port = None

    return src_ip, dst_ip, dst_port


def _build_recent_alert_index(db, rule_id: str, threshold: datetime) -> Dict[str, Any]:
    stmt = (
        select(AlertModel.src_ip, AlertModel.dst_ip, AlertModel.dst_port)
        .where(AlertModel.rule_id == rule_id)
        .where(AlertModel.created_at >= threshold)
    )
    rows = db.execute(stmt).all()

    idx = {
        "any": False,
        "src": set(),
        "dst": set(),
        "dport": set(),
        "src_dst": set(),
        "src_dport": set(),
        "dst_dport": set(),
        "src_dst_dport": set(),
    }

    if not rows:
        return idx

    idx["any"] = True
    for r in rows:
        src_ip, dst_ip, dport = r[0], r[1], r[2]
        if src_ip is not None:
            idx["src"].add(src_ip)
        if dst_ip is not None:
            idx["dst"].add(dst_ip)
        if dport is not None:
            idx["dport"].add(int(dport))

        if src_ip is not None and dst_ip is not None:
            idx["src_dst"].add((src_ip, dst_ip))
        if src_ip is not None and dport is not None:
            idx["src_dport"].add((src_ip, int(dport)))
        if dst_ip is not None and dport is not None:
            idx["dst_dport"].add((dst_ip, int(dport)))
        if src_ip is not None and dst_ip is not None and dport is not None:
            idx["src_dst_dport"].add((src_ip, dst_ip, int(dport)))

    return idx


def _recent_alert_exists_cached(idx: Dict[str, Any], src_ip: str | None, dst_ip: str | None, dst_port: int | None) -> bool:
    if src_ip is not None and dst_ip is not None and dst_port is not None:
        return (src_ip, dst_ip, dst_port) in idx["src_dst_dport"]
    if src_ip is not None and dst_ip is not None:
        return (src_ip, dst_ip) in idx["src_dst"]
    if src_ip is not None and dst_port is not None:
        return (src_ip, dst_port) in idx["src_dport"]
    if dst_ip is not None and dst_port is not None:
        return (dst_ip, dst_port) in idx["dst_dport"]
    if src_ip is not None:
        return src_ip in idx["src"]
    if dst_ip is not None:
        return dst_ip in idx["dst"]
    if dst_port is not None:
        return dst_port in idx["dport"]
    return bool(idx["any"])


def _index_add(idx: Dict[str, Any], src_ip: str | None, dst_ip: str | None, dst_port: int | None) -> None:
    idx["any"] = True

    if src_ip is not None:
        idx["src"].add(src_ip)
    if dst_ip is not None:
        idx["dst"].add(dst_ip)
    if dst_port is not None:
        idx["dport"].add(int(dst_port))

    if src_ip is not None and dst_ip is not None:
        idx["src_dst"].add((src_ip, dst_ip))
    if src_ip is not None and dst_port is not None:
        idx["src_dport"].add((src_ip, int(dst_port)))
    if dst_ip is not None and dst_port is not None:
        idx["dst_dport"].add((dst_ip, int(dst_port)))
    if src_ip is not None and dst_ip is not None and dst_port is not None:
        idx["src_dst_dport"].add((src_ip, dst_ip, int(dst_port)))


def run_all_rules() -> List[AlertModel]:
    rules = load_rules()
    print(f"[RULES] Loaded {len(rules)} rule(s) from YAML")
    if not rules:
        return []

    db = SessionLocal()
    created_alerts: List[AlertModel] = []

    try:
        now = datetime.utcnow()

        for rule in rules:
            rule_id = rule.get("id")
            rule_type = rule.get("type")
            if not rule_id or not rule_type:
                print(f"[RULES] invalid rule missing id/type: {rule}. Skipping")
                continue

            severity = rule.get("severity", "medium")
            description = rule.get("description", "")
            match = rule.get("match", {}) or {}

            window = parse_window(rule.get("window", "10m"))
            cooldown_str = rule.get("cooldown")
            cooldown = parse_window(cooldown_str) if isinstance(cooldown_str, str) else window

            recent_threshold = now - cooldown
            recent_idx = _build_recent_alert_index(db, rule_id, recent_threshold)

            time_threshold = now - window

            filters = _build_match_filters(rule)
            filters.append(NetEventModel.timestamp >= time_threshold)

            try:
                group_fields = _normalize_group_by(rule.get("group_by"))
            except Exception as e:
                print(f"[RULES] Rule={rule_id} invalid group_by: {e}. Skipping")
                continue

            group_cols = []
            bad = False
            for f in group_fields:
                if f not in _ALLOWED_EVENT_FIELDS:
                    bad = True
                    break
                c = _safe_col(f)
                group_cols.append(c)
                filters.append(c.is_not(None))

            if bad:
                print(f"[RULES] Rule={rule_id} unsupported group_by fields={group_fields}. Skipping")
                continue

            print(f"[RULES] Evaluating rule={rule_id}, type={rule_type}, window={window}, cooldown={cooldown}, group_by={group_fields}")

            if rule_type == "aggregate_count":
                condition = rule.get("condition", {}) or {}
                min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

                stmt = (
                    select(
                        *[c.label(f) for c, f in zip(group_cols, group_fields)],
                        func.count().label("count"),
                    )
                    .where(and_(*filters))
                    .group_by(*group_cols)
                )

                rows = db.execute(stmt).all()
                print(f"[RULES] Rule={rule_id} aggregate_count: {len(rows)} group(s) found")

                for row in rows:
                    group_key = {f: row._mapping.get(f) for f in group_fields}
                    count = int(row.count)

                    if min_events and count < min_events:
                        continue
                    if not _evaluate_condition(count, condition):
                        continue

                    src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)

                    if _recent_alert_exists_cached(recent_idx, src_ip, dst_ip, dst_port):
                        continue

                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        description=description,
                        details={
                            "type": rule_type,
                            "group_by": group_fields,
                            "group_key": group_key,
                            "count": count,
                            "window_seconds": int(window.total_seconds()),
                        },
                    )
                    db.add(alert)
                    created_alerts.append(alert)
                    _index_add(recent_idx, src_ip, dst_ip, dst_port)

            elif rule_type == "distinct_count":
                condition = rule.get("condition", {}) or {}
                min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

                distinct_field = rule.get("distinct_field")
                if not isinstance(distinct_field, str) or distinct_field not in _ALLOWED_EVENT_FIELDS:
                    print(f"[RULES] Rule={rule_id} invalid distinct_field={distinct_field!r}. Skipping")
                    continue

                distinct_col = _safe_col(distinct_field)
                filters2 = list(filters)
                filters2.append(distinct_col.is_not(None))

                stmt = (
                    select(
                        *[c.label(f) for c, f in zip(group_cols, group_fields)],
                        func.count(func.distinct(distinct_col)).label("distinct_count"),
                        func.count().label("event_count"),
                    )
                    .where(and_(*filters2))
                    .group_by(*group_cols)
                )

                rows = db.execute(stmt).all()
                print(f"[RULES] Rule={rule_id} distinct_count: {len(rows)} group(s) found")

                for row in rows:
                    group_key = {f: row._mapping.get(f) for f in group_fields}
                    distinct_count = int(row.distinct_count)
                    event_count = int(row.event_count)

                    if min_events and event_count < min_events:
                        continue
                    if not _evaluate_condition(distinct_count, condition):
                        continue

                    src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)

                    if _recent_alert_exists_cached(recent_idx, src_ip, dst_ip, dst_port):
                        continue

                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        description=description,
                        details={
                            "type": rule_type,
                            "group_by": group_fields,
                            "group_key": group_key,
                            "distinct_field": distinct_field,
                            "distinct_count": distinct_count,
                            "event_count": event_count,
                            "window_seconds": int(window.total_seconds()),
                        },
                    )
                    db.add(alert)
                    created_alerts.append(alert)
                    _index_add(recent_idx, src_ip, dst_ip, dst_port)

            elif rule_type == "multi_distinct":
                distinct_conditions = rule.get("distinct_conditions", []) or []
                if not isinstance(distinct_conditions, list) or not distinct_conditions:
                    print(f"[RULES] Rule={rule_id} missing distinct_conditions. Skipping")
                    continue

                min_events = int(rule.get("min_events") or 0)

                selects = [c.label(f) for c, f in zip(group_cols, group_fields)]
                filters2 = list(filters)

                metric_labels = []
                for dc in distinct_conditions:
                    field = dc.get("field")
                    if not isinstance(field, str) or field not in _ALLOWED_EVENT_FIELDS:
                        print(f"[RULES] Rule={rule_id} invalid distinct field in multi_distinct: {field!r}. Skipping")
                        metric_labels = None
                        break
                    col = _safe_col(field)
                    filters2.append(col.is_not(None))
                    label = f"distinct_{field}"
                    selects.append(func.count(func.distinct(col)).label(label))
                    metric_labels.append((field, label, dc))

                if metric_labels is None:
                    continue

                selects.append(func.count().label("event_count"))
                stmt = select(*selects).where(and_(*filters2)).group_by(*group_cols)

                rows = db.execute(stmt).all()
                print(f"[RULES] Rule={rule_id} multi_distinct: {len(rows)} group(s) found")

                for row in rows:
                    group_key = {f: row._mapping.get(f) for f in group_fields}
                    event_count = int(row._mapping.get("event_count") or 0)
                    if min_events and event_count < min_events:
                        continue

                    ok = True
                    metrics = {}
                    for field, label, dc in metric_labels:
                        v = int(row._mapping.get(label) or 0)
                        metrics[field] = v
                        if not _evaluate_condition(v, dc):
                            ok = False
                            break
                    if not ok:
                        continue

                    src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)

                    if _recent_alert_exists_cached(recent_idx, src_ip, dst_ip, dst_port):
                        continue

                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        description=description,
                        details={
                            "type": rule_type,
                            "group_by": group_fields,
                            "group_key": group_key,
                            "metrics": metrics,
                            "event_count": event_count,
                            "distinct_conditions": distinct_conditions,
                            "window_seconds": int(window.total_seconds()),
                        },
                    )
                    db.add(alert)
                    created_alerts.append(alert)
                    _index_add(recent_idx, src_ip, dst_ip, dst_port)

            else:
                print(f"[RULES] Rule={rule_id} has unsupported type={rule_type}, skipping")
                continue

        if created_alerts:
            db.commit()
            for a in created_alerts:
                db.refresh(a)

        print(f"[RULES] Created {len(created_alerts)} alert(s) in this cycle")
        return created_alerts

    finally:
        db.close()
