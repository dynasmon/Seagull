from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query, Depends, HTTPException
from sqlalchemy import select, func

from app.core.db import SessionLocal
from app.models.events import NetEventModel
from app.models.alerts import AlertModel
from app.models.alert_rule_overrides import AlertRuleOverrideModel
from app.schemas.alerts import AlertOut
from app.schemas.alert_rules import RuleOut, RuleOverrideIn
from app.workers.rules_engine import run_all_rules
from app.workers.rules_registry import apply_override, fetch_overrides, load_baseline_rules, normalize_rule_list

from app.core.portal_auth import require_admin


router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
    dependencies=[Depends(require_admin)],
)


@router.post("/run/ssh-bruteforce", response_model=List[AlertOut])
def run_ssh_bruteforce_rule(
    minutes: int = Query(10, ge=1, le=1440, description="Time window in minutes"),
    min_events: int = Query(20, ge=1, le=100000, description="Minimum number of events per source IP"),
):
    """
    Simple detection rule:
    - Look at 'flow' events to destination port 22 (SSH)
    - Within the provided time window
    - Group by source IP
    - If a source IP has >= min_events, create an alert
    """
    db = SessionLocal()
    try:
        time_threshold = datetime.utcnow() - timedelta(minutes=minutes)

        stmt = (
            select(
                NetEventModel.src_ip.label("src_ip"),
                func.count().label("count"),
            )
            .where(NetEventModel.event_type == "flow")
            .where(NetEventModel.dst_port == 22)
            .where(NetEventModel.timestamp >= time_threshold)
            .where(NetEventModel.src_ip.is_not(None))
            .group_by(NetEventModel.src_ip)
            .having(func.count() >= min_events)
        )

        rows = db.execute(stmt).all()

        alerts: List[AlertModel] = []

        for row in rows:
            src_ip = row.src_ip
            count = row.count

            alert = AlertModel(
                rule_id="ssh_bruteforce_v1",
                severity="medium",
                src_ip=src_ip,
                dst_ip=None,
                dst_port=22,
                description="Possible SSH brute force or port scanning activity detected",
                details={
                    "time_window_minutes": minutes,
                    "min_events": min_events,
                    "event_count": int(count),
                    "dst_port": 22,
                },
            )
            db.add(alert)
            alerts.append(alert)

        if alerts:
            db.commit()
            for a in alerts:
                db.refresh(a)

        return alerts
    finally:
        db.close()


@router.post("/run/port-scan", response_model=List[AlertOut])
def run_port_scan_rule(
    minutes: int = Query(10, ge=1, le=1440, description="Time window in minutes"),
    min_distinct_ports: int = Query(
        20,
        ge=1,
        le=65535,
        description="Minimum number of distinct destination ports per source IP",
    ),
):
    """
    Vertical port scan detection:
    - Look at TCP 'flow' events
    - Within the provided time window
    - Group by source IP
    - Count distinct destination ports
    - If distinct ports >= min_distinct_ports, create an alert
    """
    db = SessionLocal()
    try:
        time_threshold = datetime.utcnow() - timedelta(minutes=minutes)

        stmt = (
            select(
                NetEventModel.src_ip.label("src_ip"),
                func.count(func.distinct(NetEventModel.dst_port)).label("distinct_ports"),
                func.count().label("event_count"),
            )
            .where(NetEventModel.event_type == "flow")
            .where(NetEventModel.proto == "tcp")
            .where(NetEventModel.timestamp >= time_threshold)
            .where(NetEventModel.src_ip.is_not(None))
            .where(NetEventModel.dst_port.is_not(None))
            .group_by(NetEventModel.src_ip)
            .having(func.count(func.distinct(NetEventModel.dst_port)) >= min_distinct_ports)
        )

        rows = db.execute(stmt).all()

        alerts: List[AlertModel] = []

        for row in rows:
            src_ip = row.src_ip
            distinct_ports = int(row.distinct_ports)
            event_count = int(row.event_count)

            alert = AlertModel(
                rule_id="port_scan_v1",
                severity="high",
                src_ip=src_ip,
                dst_ip=None,
                dst_port=None,
                description="Possible TCP vertical port scan detected",
                details={
                    "time_window_minutes": minutes,
                    "min_distinct_ports": min_distinct_ports,
                    "distinct_ports": distinct_ports,
                    "event_count": event_count,
                },
            )
            db.add(alert)
            alerts.append(alert)

        if alerts:
            db.commit()
            for a in alerts:
                db.refresh(a)

        return alerts
    finally:
        db.close()


@router.post("/run/horizontal-scan", response_model=List[AlertOut])
def run_horizontal_scan_rule(
    minutes: int = Query(10, ge=1, le=1440, description="Time window in minutes"),
    min_distinct_targets: int = Query(
        10,
        ge=1,
        le=100000,
        description="Minimum number of distinct destination IPs per source IP",
    ),
    dst_port: int = Query(
        22,
        ge=1,
        le=65535,
        description="Destination port to focus on (e.g., 22 for SSH, 80 for HTTP)",
    ),
):
    """
    Horizontal scan detection:
    - Look at 'flow' events to a specific destination port
    - Within the provided time window
    - Group by (source IP, destination port)
    - Count distinct destination IPs
    - If distinct destination IPs >= min_distinct_targets, create an alert
    """
    db = SessionLocal()
    try:
        time_threshold = datetime.utcnow() - timedelta(minutes=minutes)

        stmt = (
            select(
                NetEventModel.src_ip.label("src_ip"),
                NetEventModel.dst_port.label("dst_port"),
                func.count(func.distinct(NetEventModel.dst_ip)).label("distinct_targets"),
                func.count().label("event_count"),
            )
            .where(NetEventModel.event_type == "flow")
            .where(NetEventModel.timestamp >= time_threshold)
            .where(NetEventModel.src_ip.is_not(None))
            .where(NetEventModel.dst_ip.is_not(None))
            .where(NetEventModel.dst_port == dst_port)
            .group_by(NetEventModel.src_ip, NetEventModel.dst_port)
            .having(func.count(func.distinct(NetEventModel.dst_ip)) >= min_distinct_targets)
        )

        rows = db.execute(stmt).all()

        alerts: List[AlertModel] = []

        for row in rows:
            src_ip = row.src_ip
            dst_p = int(row.dst_port)
            distinct_targets = int(row.distinct_targets)
            event_count = int(row.event_count)

            alert = AlertModel(
                rule_id="horizontal_scan_v1",
                severity="medium",
                src_ip=src_ip,
                dst_ip=None,
                dst_port=dst_p,
                description="Possible horizontal scan against multiple targets on the same port",
                details={
                    "time_window_minutes": minutes,
                    "min_distinct_targets": min_distinct_targets,
                    "distinct_targets": distinct_targets,
                    "event_count": event_count,
                    "dst_port": dst_p,
                },
            )
            db.add(alert)
            alerts.append(alert)

        if alerts:
            db.commit()
            for a in alerts:
                db.refresh(a)

        return alerts
    finally:
        db.close()


@router.post("/run/new-hosts", response_model=List[AlertOut])
def run_new_hosts_rule(
    minutes: int = Query(
        60,
        ge=1,
        le=10080,
        description="Time window in minutes in which a host is considered 'new' if first seen",
    ),
    min_events: int = Query(
        1,
        ge=1,
        le=100000,
        description="Minimum number of events for the host in the window",
    ),
):
    """
    New hosts detection:
    - Check all events for source and destination IPs
    - For each host, compute first_seen = MIN(timestamp)
    - If first_seen is within the time window (last N minutes) and it has at least min_events, create an alert.
    """
    db = SessionLocal()
    try:
        time_threshold = datetime.utcnow() - timedelta(minutes=minutes)

        alerts: List[AlertModel] = []

        # New source hosts
        stmt_src = (
            select(
                NetEventModel.src_ip.label("ip"),
                func.min(NetEventModel.timestamp).label("first_seen"),
                func.count().label("event_count"),
            )
            .where(NetEventModel.src_ip.is_not(None))
            .group_by(NetEventModel.src_ip)
            .having(func.min(NetEventModel.timestamp) >= time_threshold)
            .having(func.count() >= min_events)
        )

        rows_src = db.execute(stmt_src).all()

        for row in rows_src:
            ip = row.ip
            first_seen = row.first_seen
            event_count = int(row.event_count)

            alert = AlertModel(
                rule_id="new_host_seen_v1",
                severity="low",
                src_ip=ip,
                dst_ip=None,
                dst_port=None,
                description="New source host observed in network events",
                details={
                    "role": "src",
                    "first_seen": first_seen.isoformat() if first_seen else None,
                    "event_count": event_count,
                    "time_window_minutes": minutes,
                    "min_events": min_events,
                },
            )
            db.add(alert)
            alerts.append(alert)

        # New destination hosts
        stmt_dst = (
            select(
                NetEventModel.dst_ip.label("ip"),
                func.min(NetEventModel.timestamp).label("first_seen"),
                func.count().label("event_count"),
            )
            .where(NetEventModel.dst_ip.is_not(None))
            .group_by(NetEventModel.dst_ip)
            .having(func.min(NetEventModel.timestamp) >= time_threshold)
            .having(func.count() >= min_events)
        )

        rows_dst = db.execute(stmt_dst).all()

        for row in rows_dst:
            ip = row.ip
            first_seen = row.first_seen
            event_count = int(row.event_count)

            alert = AlertModel(
                rule_id="new_host_seen_v1",
                severity="low",
                src_ip=None,
                dst_ip=ip,
                dst_port=None,
                description="New destination host observed in network events",
                details={
                    "role": "dst",
                    "first_seen": first_seen.isoformat() if first_seen else None,
                    "event_count": event_count,
                    "time_window_minutes": minutes,
                    "min_events": min_events,
                },
            )
            db.add(alert)
            alerts.append(alert)

        if alerts:
            db.commit()
            for a in alerts:
                db.refresh(a)

        return alerts
    finally:
        db.close()

@router.get("/recent", response_model=List[AlertOut])
def get_recent_alerts(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of alerts to return"),
):
    """
    Return the most recent alerts.
    """
    db = SessionLocal()
    try:
        stmt = (
            select(AlertModel)
            .order_by(AlertModel.created_at.desc())
            .limit(limit)
        )
        result = db.execute(stmt)
        alerts = result.scalars().all()
        return alerts
    finally:
        db.close()

@router.post("/run/all", response_model=List[AlertOut])
def run_all_rules_endpoint():
    """
    Run all enabled rules loaded from YAML and return the alerts created
    during this execution.
    """
    alerts = run_all_rules()
    return alerts


@router.get("/rules", response_model=List[RuleOut])
def list_alert_rules():
    """List baseline rules merged with DB overrides (effective view)."""
    db = SessionLocal()
    try:
        base_rules = normalize_rule_list(load_baseline_rules(include_disabled=True))
        overrides = fetch_overrides(db)

        out: List[RuleOut] = []
        for base in base_rules:
            rid = base.get("id")
            if not rid:
                continue

            row = overrides.get(rid)
            effective, override_payload = apply_override(base, row)

            out.append(
                RuleOut(
                    id=rid,
                    name=effective.get("name") or base.get("name"),
                    description=effective.get("description") or base.get("description"),
                    source_file=base.get("source_file"),
                    enabled=bool(effective.get("enabled", True)),
                    severity=str(effective.get("severity") or "low"),
                    type=effective.get("type"),
                    window=effective.get("window"),
                    cooldown=effective.get("cooldown"),
                    has_override=row is not None,
                    updated_at=getattr(row, "updated_at", None) if row is not None else None,
                    base=base,
                    override=override_payload,
                    effective=effective,
                )
            )

        # Deterministic ordering: stable by rule id
        out.sort(key=lambda r: (r.severity, r.id))
        return out
    finally:
        db.close()


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def patch_alert_rule(rule_id: str, body: RuleOverrideIn):
    """Upsert overrides for a given rule."""
    base_rules = normalize_rule_list(load_baseline_rules(include_disabled=True))
    base = next((r for r in base_rules if r.get("id") == rule_id), None)
    if not base:
        raise HTTPException(status_code=404, detail="Rule not found")

    db = SessionLocal()
    try:
        row: Optional[AlertRuleOverrideModel] = db.get(AlertRuleOverrideModel, rule_id)
        if row is None:
            row = AlertRuleOverrideModel(rule_id=rule_id, condition={}, schedule={}, patch={})
            db.add(row)

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

        row.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(row)

        effective, override_payload = apply_override(base, row)

        return RuleOut(
            id=rule_id,
            name=effective.get("name") or base.get("name"),
            description=effective.get("description") or base.get("description"),
            source_file=base.get("source_file"),
            enabled=bool(effective.get("enabled", True)),
            severity=str(effective.get("severity") or "low"),
            type=effective.get("type"),
            window=effective.get("window"),
            cooldown=effective.get("cooldown"),
            has_override=True,
            updated_at=row.updated_at,
            base=base,
            override=override_payload,
            effective=effective,
        )
    finally:
        db.close()


@router.delete("/rules/{rule_id}", status_code=204)
def delete_alert_rule_override(rule_id: str):
    """Remove all overrides for a rule (reverts to baseline YAML)."""
    db = SessionLocal()
    try:
        row = db.get(AlertRuleOverrideModel, rule_id)
        if row is not None:
            db.delete(row)
            db.commit()
        return None
    finally:
        db.close()