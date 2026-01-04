import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import yaml
from sqlalchemy import and_, cast, func, select, or_
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import Float

from app.core.db import SessionLocal
from app.models.alerts import AlertModel
from app.models.events import NetEventModel
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

_ALLOWED_GROUP_FIELDS = _ALLOWED_EVENT_FIELDS


def _safe_col(field: str):
    if field not in _ALLOWED_EVENT_FIELDS:
        raise ValueError(f"Invalid field: {field}")
    return getattr(NetEventModel, field)


def _evaluate_condition(value: int, condition: Dict) -> bool:
    op = (condition.get("operator") or ">=").strip()
    target = int(condition.get("value") or 0)

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

    return False


def _extract_alert_key(group_key: Dict, match: Dict) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    src_ip = group_key.get("src_ip") if "src_ip" in group_key else match.get("src_ip")
    dst_ip = group_key.get("dst_ip") if "dst_ip" in group_key else match.get("dst_ip")

    dst_port = group_key.get("dst_port") if "dst_port" in group_key else match.get("dst_port")
    if dst_port is not None:
        try:
            dst_port = int(dst_port)
        except Exception:
            dst_port = None

    return src_ip, dst_ip, dst_port


def _recent_alert_index(db: Session, horizon: timedelta) -> Dict[Tuple[Optional[str], Optional[str], Optional[int]], datetime]:
    threshold = datetime.utcnow() - horizon

    stmt = (
        select(AlertModel.src_ip, AlertModel.dst_ip, AlertModel.dst_port, func.max(AlertModel.created_at))
        .where(AlertModel.created_at >= threshold)
        .group_by(AlertModel.src_ip, AlertModel.dst_ip, AlertModel.dst_port)
    )

    idx: Dict[Tuple[Optional[str], Optional[str], Optional[int]], datetime] = {}
    for src_ip, dst_ip, dst_port, last_at in db.execute(stmt).all():
        idx[(src_ip, dst_ip, int(dst_port) if dst_port is not None else None)] = last_at

    return idx


def _recent_alert_exists_cached(idx: Dict, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]) -> bool:
    return (src_ip, dst_ip, dst_port) in idx


def _index_add(idx: Dict, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]):
    idx[(src_ip, dst_ip, dst_port)] = datetime.utcnow()


def _parse_extra_key(raw_key: str) -> Tuple[str, str]:
    k = raw_key[len("extra_") :]

    for suffix, op in (
        ("_not_in", "not_in"),
        ("_in", "in"),
        ("_gte", "gte"),
        ("_gt", "gt"),
        ("_lte", "lte"),
        ("_lt", "lt"),
        ("_neq", "neq"),
    ):
        if k.endswith(suffix):
            return k[: -len(suffix)], op

    return k, "eq"


from sqlalchemy import func

def _extra_text_col(extra_key: str):
    expr = NetEventModel.extra[extra_key]

    if hasattr(expr, "as_string"):
        return expr.as_string()

    if hasattr(expr, "astext"):
        return expr.astext

    return func.jsonb_extract_path_text(NetEventModel.extra, extra_key)


def _extra_numeric_col(extra_key: str):
    text_col = _extra_text_col(extra_key)
    is_numeric = text_col.op("~")(r"^-?\d+(\.\d+)?$")
    return is_numeric, cast(text_col, Float)


def _build_match_filters(match: Dict, since: datetime, until: datetime) -> List:
    filters = [NetEventModel.timestamp >= since, NetEventModel.timestamp < until]

    for key, val in (match or {}).items():
        if key in _ALLOWED_EVENT_FIELDS:
            col = _safe_col(key)
            filters.append(col == val)
            continue

        if not key.startswith("extra_"):
            continue

        extra_key, op = _parse_extra_key(key)
        text_col = _extra_text_col(extra_key)

        if op in ("in", "not_in"):
            if not isinstance(val, list):
                continue
            needle = [str(v) for v in val]
            if op == "in":
                filters.append(text_col.in_(needle))
            else:
                filters.append(~text_col.in_(needle))
            continue

        if op in ("gte", "gt", "lte", "lt"):
            try:
                target = float(val)
            except Exception:
                continue
            is_numeric, num_col = _extra_numeric_col(extra_key)
            filters.append(is_numeric)
            if op == "gte":
                filters.append(num_col >= target)
            elif op == "gt":
                filters.append(num_col > target)
            elif op == "lte":
                filters.append(num_col <= target)
            else:
                filters.append(num_col < target)
            continue

        if op == "neq":
            filters.append(text_col != str(val).lower() if isinstance(val, bool) else text_col != str(val))
            continue

        if isinstance(val, bool):
            filters.append(text_col == ("true" if val else "false"))
        else:
            filters.append(text_col == str(val))

    return filters


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

    for a in ddos_alerts:
        group_key = (a.details or {}).get("group_key") or {}
        dst_ip = a.dst_ip or group_key.get("dst_ip")
        dst_port = a.dst_port or group_key.get("dst_port")

        stmt = (
            select(AlertModel.rule_id, func.count().label("cnt"))
            .where(AlertModel.created_at >= since)
            .where(AlertModel.dst_ip == dst_ip)
            .where(or_(
                AlertModel.rule_id.like("%ssh%"),
                AlertModel.rule_id.like("%scan%"),
                AlertModel.rule_id.like("%port_scan%"),
            ))
            .group_by(AlertModel.rule_id)
        )

        if dst_port is not None:
            try:
                dst_port_int = int(dst_port)
                stmt = stmt.where(or_(AlertModel.dst_port.is_(None), AlertModel.dst_port == dst_port_int))
            except Exception:
                pass

        rows = db.execute(stmt).all()
        if not rows:
            continue

        correlated = {r.rule_id: int(r.cnt) for r in rows if r.rule_id}
        total = sum(correlated.values())
        if total <= 0:
            continue

        incident_rule_id = "incident_ddos_correlated_v1"

        cooldown_since = now - timedelta(minutes=10)
        existing = (
            db.execute(
                select(func.count())
                .select_from(AlertModel)
                .where(AlertModel.rule_id == incident_rule_id)
                .where(AlertModel.created_at >= cooldown_since)
                .where(AlertModel.dst_ip == dst_ip)
                .where(AlertModel.dst_port == a.dst_port)
            ).scalar()
            or 0
        )
        if int(existing) > 0:
            continue

        incident = AlertModel(
            rule_id=incident_rule_id,
            severity="critical",
            src_ip=None,
            dst_ip=dst_ip,
            dst_port=a.dst_port,
            description="Potential incident: DDoS/DoS correlated with additional hostile activity",
            details={
                "type": "correlation",
                "window_seconds": int(horizon.total_seconds()),
                "correlated_rules": correlated,
                "base_rule_id": a.rule_id,
            },
        )
        db.add(incident)
        out.append(incident)

    return out


def run_all_rules() -> List[AlertModel]:
    rules = load_rules()

    now = datetime.utcnow()
    created_alerts: List[AlertModel] = []

    db = SessionLocal()
    try:
        recent_idx = _recent_alert_index(db, timedelta(minutes=2))

        for rule in rules:
            if not rule.get("enabled", True):
                continue

            rule_id = rule.get("id")
            rule_type = rule.get("type")
            severity = rule.get("severity", "low")
            description = rule.get("description", "")

            window_s = rule.get("window", "5m")
            cooldown_s = rule.get("cooldown", "10m")

            try:
                window = timedelta(seconds=_parse_window(window_s))
                cooldown = timedelta(seconds=_parse_window(cooldown_s))
            except Exception:
                window = timedelta(minutes=5)
                cooldown = timedelta(minutes=10)

            since = now - window
            until = now

            match = rule.get("match", {}) or {}
            group_fields = rule.get("group_by", []) or []

            if isinstance(group_fields, str):
                group_fields = [group_fields]

            group_fields = [f for f in group_fields if f in _ALLOWED_GROUP_FIELDS]

            try:
                group_cols = [_safe_col(f) for f in group_fields]
            except Exception:
                group_cols = []
                group_fields = []

            filters = _build_match_filters(match, since, until)

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

            else:
                continue

        try:
            correlated = _correlate_ddos_incidents(db, now, created_alerts)
            if correlated:
                created_alerts.extend(correlated)
        except Exception:
            pass

        db.commit()
        return created_alerts

    finally:
        db.close()


def _parse_window(s: str) -> int:
    s = str(s).strip().lower()
    if s.endswith("ms"):
        return int(float(s[:-2]) / 1000.0)
    if s.endswith("s"):
        return int(float(s[:-1]))
    if s.endswith("m"):
        return int(float(s[:-1]) * 60)
    if s.endswith("h"):
        return int(float(s[:-1]) * 3600)
    return int(float(s))
