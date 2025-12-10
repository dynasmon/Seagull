from datetime import datetime, timedelta
from typing import Any, Dict, List

from sqlalchemy import and_, func, select

from app.core.db import SessionLocal
from app.models.events import NetEventModel
from app.models.alerts import AlertModel
from app.workers.rules_loader import load_rules


def parse_window(window_str: str) -> timedelta:
    """
    Parse a window string such as '10m', '1h', '2d' into a timedelta.
    """
    unit = window_str[-1]
    value = int(window_str[:-1])

    if unit == "m":
        return timedelta(minutes=value)
    elif unit == "h":
        return timedelta(hours=value)
    elif unit == "d":
        return timedelta(days=value)
    else:
        raise ValueError(f"Unsupported window unit: {unit} in {window_str}")


def _build_match_filters(rule: Dict[str, Any]):
    match = rule.get("match", {}) or {}
    filters = []

    for key, val in match.items():
        if key == "event_type":
            filters.append(NetEventModel.event_type == val)
        elif key == "dst_port":
            filters.append(NetEventModel.dst_port == val)
        elif key == "proto":
            filters.append(NetEventModel.proto == val)
        elif key == "src_ip":
            filters.append(NetEventModel.src_ip == val)
        elif key == "dst_ip":
            filters.append(NetEventModel.dst_ip == val)
        elif key == "agent_id":
            filters.append(NetEventModel.agent_id == val)
            
    return filters


def _evaluate_condition(value: int, condition: Dict[str, Any]) -> bool:
    op = condition.get("operator")
    threshold = int(condition.get("value", 0))

    if op == ">=":
        return value >= threshold
    elif op == ">":
        return value > threshold
    elif op == "==":
        return value == threshold
    elif op == "<=":
        return value <= threshold
    elif op == "<":
        return value < threshold

    raise ValueError(f"Unsupported operator in condition: {op}")


def _recent_alert_exists(
    db,
    rule_id: str,
    src_ip: str | None,
    dst_ip: str | None,
    cooldown: timedelta,
) -> bool:
    """
    Check if there is a recent alert for this (rule_id, src_ip, dst_ip)
    within the cooldown window.
    """
    threshold = datetime.utcnow() - cooldown

    stmt = (
        select(func.count())
        .select_from(AlertModel)
        .where(AlertModel.rule_id == rule_id)
        .where(AlertModel.created_at >= threshold)
    )

    if src_ip is not None:
        stmt = stmt.where(AlertModel.src_ip == src_ip)

    if dst_ip is not None:
        stmt = stmt.where(AlertModel.dst_ip == dst_ip)

    count = db.execute(stmt).scalar() or 0
    return count > 0


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
            rule_id = rule["id"]
            rule_type = rule["type"]
            severity = rule.get("severity", "medium")
            description = rule.get("description", "")
            group_by = rule.get("group_by")
            window = parse_window(rule.get("window", "10m"))

            # cooldown pode ser menor/maior que a janela; se não vier, usa window.
            cooldown_str = rule.get("cooldown")
            cooldown = parse_window(cooldown_str) if isinstance(cooldown_str, str) else window

            condition = rule.get("condition", {})

            time_threshold = now - window

            filters = _build_match_filters(rule)
            filters.append(NetEventModel.timestamp >= time_threshold)

            print(
                f"[RULES] Evaluating rule={rule_id}, "
                f"type={rule_type}, window={window}, cooldown={cooldown}, group_by={group_by}"
            )

            if rule_type == "aggregate_count":
                group_col = getattr(NetEventModel, group_by)
                stmt = (
                    select(
                        group_col.label("key"),
                        func.count().label("count"),
                    )
                    .where(and_(*filters))
                    .group_by(group_col)
                )

                rows = db.execute(stmt).all()
                print(f"[RULES] Rule={rule_id} aggregate_count: {len(rows)} group(s) found")

                for row in rows:
                    key = row.key
                    count = int(row.count)

                    if not _evaluate_condition(count, condition):
                        continue

                    src_ip = key if group_by == "src_ip" else None
                    dst_ip = key if group_by == "dst_ip" else None

                    if _recent_alert_exists(db, rule_id, src_ip, dst_ip, cooldown):
                        print(
                            f"[RULES] Rule={rule_id} key={key} skipped due to cooldown "
                            f"(existing recent alert)"
                        )
                        continue

                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=None,
                        description=description,
                        details={
                            "type": rule_type,
                            "group_by": group_by,
                            "key": key,
                            "count": count,
                            "time_window_minutes": int(window.total_seconds() / 60),
                        },
                    )
                    db.add(alert)
                    created_alerts.append(alert)

            elif rule_type == "distinct_count":
                distinct_field = rule.get("distinct_field")
                group_col = getattr(NetEventModel, group_by)
                distinct_col = getattr(NetEventModel, distinct_field)

                stmt = (
                    select(
                        group_col.label("key"),
                        func.count(func.distinct(distinct_col)).label("distinct_count"),
                        func.count().label("event_count"),
                    )
                    .where(and_(*filters))
                    .group_by(group_col)
                )

                rows = db.execute(stmt).all()
                print(f"[RULES] Rule={rule_id} distinct_count: {len(rows)} group(s) found")

                for row in rows:
                    key = row.key
                    distinct_count = int(row.distinct_count)
                    event_count = int(row.event_count)

                    if not _evaluate_condition(distinct_count, condition):
                        continue

                    src_ip = key if group_by == "src_ip" else None
                    dst_ip = key if group_by == "dst_ip" else None

                    if _recent_alert_exists(db, rule_id, src_ip, dst_ip, cooldown):
                        print(
                            f"[RULES] Rule={rule_id} key={key} skipped due to cooldown "
                            f"(existing recent alert)"
                        )
                        continue

                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=None,
                        description=description,
                        details={
                            "type": rule_type,
                            "group_by": group_by,
                            "key": key,
                            "distinct_count": distinct_count,
                            "event_count": event_count,
                            "distinct_field": distinct_field,
                            "time_window_minutes": int(window.total_seconds() / 60),
                        },
                    )
                    db.add(alert)
                    created_alerts.append(alert)

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
