from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query, Depends, HTTPException, Request
from sqlalchemy import and_, func, or_, select

from app.core.audit import audit_actor, write_audit_event
from app.core.db import SessionLocal
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.features.events.models import NetEventModel
from app.features.alerts.models import AlertModel
from app.features.alerts.models import AlertRuleOverrideModel
from app.features.alerts.models import AlertRuleSuppressionHistoryModel, AlertRuleSuppressionModel
from app.features.alerts.models import AlertRuleTuningHistoryModel, AlertRuleTuningModel
from app.features.alerts.schemas import AlertOut
from app.shared.schemas import CursorPage
from app.features.alerts.schemas import RuleGovernanceHistoryOut, RuleOut, RuleOverrideIn
from app.shared.taxonomy.schemas import MitreCoverageResponse, MitreTacticCoverage, MitreTechniqueStat
from app.shared.taxonomy.catalog import technique_name
from app.workers.rules_engine import run_all_rules
from app.workers.rules_registry import (
    apply_override,
    apply_tuning_and_suppressions,
    fetch_overrides,
    fetch_suppressions,
    fetch_tuning,
    load_baseline_rules,
    normalize_rule_list,
)

from app.core.portal_auth import PortalPrincipal, require_admin


router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
    dependencies=[Depends(require_admin)],
)


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
        # keep storage semantics aligned with existing UTC-naive timestamps
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


@router.get("", response_model=CursorPage[AlertOut])
def list_alerts(
    page_size: int = Query(50, ge=1, le=200, description="Page size (max 200)"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    severity: Optional[str] = Query(None, min_length=1, max_length=16, description="Optional severity filter"),
    rule_id: Optional[str] = Query(None, min_length=1, max_length=64, description="Optional rule id filter"),
    tactic: Optional[str] = Query(None, min_length=1, max_length=64, description="Optional MITRE tactic filter"),
    technique_id: Optional[str] = Query(None, min_length=1, max_length=32, description="Optional MITRE technique id filter"),
    min_confidence: Optional[int] = Query(None, ge=0, le=100, description="Optional minimum confidence (0..100)"),
):
    """Cursor-paginated alerts timeline.

    Returns the most recent alerts first (DESC). To fetch the next page, pass the
    `next_cursor` from the previous response.

    This endpoint is the recommended replacement for `/alerts/recent` when you
    want a paginated UI.
    """

    db = SessionLocal()
    try:
        stmt = select(AlertModel).order_by(AlertModel.created_at.desc(), AlertModel.id.desc())

        if severity:
            stmt = stmt.where(AlertModel.severity == severity)
        if rule_id:
            stmt = stmt.where(AlertModel.rule_id == rule_id)

        if tactic:
            stmt = stmt.where(AlertModel.mitre_tactic == tactic)
        if technique_id:
            stmt = stmt.where(AlertModel.mitre_technique_id == technique_id)
        if min_confidence is not None:
            stmt = stmt.where(AlertModel.confidence >= int(min_confidence))

        if cursor:
            c_ts, c_id = parse_cursor_ts_id(cursor)
            stmt = stmt.where(
                or_(
                    AlertModel.created_at < c_ts,
                    and_(AlertModel.created_at == c_ts, AlertModel.id < c_id),
                )
            )

        rows = db.execute(stmt.limit(page_size + 1)).scalars().all()

        has_more = len(rows) > page_size
        items = rows[:page_size]

        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = make_cursor_ts_id(last.created_at, last.id)

        return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)
    finally:
        db.close()




@router.get("/mitre/coverage", response_model=MitreCoverageResponse)
def mitre_coverage(
    minutes: int = Query(1440, ge=1, le=43200, description="Lookback window in minutes"),
):
    """Aggregate alert coverage by MITRE tactic/technique.

    This endpoint is designed to power heatmaps, executive reporting, and quick
    triage pivots in the portal.
    """

    db = SessionLocal()
    try:
        threshold = datetime.utcnow() - timedelta(minutes=int(minutes))

        stmt = (
            select(
                AlertModel.mitre_tactic.label("tactic"),
                AlertModel.mitre_technique_id.label("technique_id"),
                AlertModel.mitre_technique.label("technique"),
                func.count().label("cnt"),
                func.max(AlertModel.confidence).label("max_conf"),
                func.avg(AlertModel.confidence).label("avg_conf"),
            )
            .where(AlertModel.created_at >= threshold)
            .where(AlertModel.mitre_tactic.is_not(None))
            .where(AlertModel.mitre_technique_id.is_not(None))
            .group_by(AlertModel.mitre_tactic, AlertModel.mitre_technique_id, AlertModel.mitre_technique)
            .order_by(AlertModel.mitre_tactic.asc(), func.count().desc())
        )

        rows = db.execute(stmt).all()

        # Group by tactic
        by_tactic = {}
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

        tactics = []
        for tactic, b in by_tactic.items():
            # sort techniques by count desc
            b["techniques"].sort(key=lambda x: (-int(x.count), x.technique_id))
            avg_conf = (b["sum_conf"] / b["sum_cnt"]) if b["sum_cnt"] else 0.0
            tactics.append(
                MitreTacticCoverage(
                    tactic=tactic,
                    total=int(b["total"]),
                    max_confidence=int(b["max_conf"]),
                    avg_confidence=float(avg_conf),
                    techniques=b["techniques"],
                )
            )

        # stable order
        tactics.sort(key=lambda x: (-int(x.total), x.tactic))

        return MitreCoverageResponse(window_minutes=int(minutes), total_alerts=int(total_alerts), tactics=tactics)
    finally:
        db.close()

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
                mitre_tactic="credential_access",
                mitre_technique_id="T1110.001",
                mitre_technique=(technique_name("T1110.001") or "Brute Force: Password Guessing"),
                confidence=70,
                description="Possible SSH brute force or port scanning activity detected",
                details={
                    "mitre": {"tactic": "credential_access", "technique_id": "T1110.001", "technique": (technique_name("T1110.001") or "Brute Force: Password Guessing"), "confidence": 70},
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
                mitre_tactic="discovery",
                mitre_technique_id="T1046",
                mitre_technique=(technique_name("T1046") or "Network Service Scanning"),
                confidence=80,
                description="Possible TCP vertical port scan detected",
                details={
                    "mitre": {"tactic": "discovery", "technique_id": "T1046", "technique": (technique_name("T1046") or "Network Service Scanning"), "confidence": 80},
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
                mitre_tactic="discovery",
                mitre_technique_id="T1046",
                mitre_technique=(technique_name("T1046") or "Network Service Scanning"),
                confidence=75,
                description="Possible horizontal scan against multiple targets on the same port",
                details={
                    "mitre": {"tactic": "discovery", "technique_id": "T1046", "technique": (technique_name("T1046") or "Network Service Scanning"), "confidence": 75},
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
                mitre_tactic="discovery",
                mitre_technique_id="T1018",
                mitre_technique=(technique_name("T1018") or "Remote System Discovery"),
                confidence=40,
                description="New source host observed in network events",
                details={
                    "mitre": {"tactic": "discovery", "technique_id": "T1018", "technique": (technique_name("T1018") or "Remote System Discovery"), "confidence": 40},
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
                mitre_tactic="discovery",
                mitre_technique_id="T1018",
                mitre_technique=(technique_name("T1018") or "Remote System Discovery"),
                confidence=40,
                description="New destination host observed in network events",
                details={
                    "mitre": {"tactic": "discovery", "technique_id": "T1018", "technique": (technique_name("T1018") or "Remote System Discovery"), "confidence": 40},
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
        tunings = fetch_tuning(db)
        suppressions = fetch_suppressions(db)

        out: List[RuleOut] = []
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
                RuleOut(
                    id=rid,
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
                    has_override=has_any_override,
                    updated_at=updated_at,
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
def patch_alert_rule(rule_id: str, body: RuleOverrideIn, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    """Upsert overrides for a given rule."""
    base_rules = normalize_rule_list(load_baseline_rules(include_disabled=True))
    base = next((r for r in base_rules if r.get("id") == rule_id), None)
    if not base:
        raise HTTPException(status_code=404, detail="Rule not found")

    db = SessionLocal()
    try:
        row_existing: Optional[AlertRuleOverrideModel] = db.get(AlertRuleOverrideModel, rule_id)
        row = row_existing
        if row is None:
            row = AlertRuleOverrideModel(rule_id=rule_id, condition={}, schedule={}, patch={})
            db.add(row)

        before = {
            "override": _rule_override_snapshot(row_existing),
            "tuning": _rule_tuning_snapshot(db.get(AlertRuleTuningModel, rule_id)),
            "suppressions": _rule_suppression_snapshot(
                db.query(AlertRuleSuppressionModel).filter(AlertRuleSuppressionModel.rule_id == rule_id).all()
            ),
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
            trow = db.get(AlertRuleTuningModel, rule_id)
            if body.tuning is None:
                if trow is not None:
                    db.add(
                        AlertRuleTuningHistoryModel(
                            rule_id=rule_id,
                            action="deleted",
                            snapshot={"tuning": trow.tuning or {}},
                            actor_user_id=admin.id,
                            actor_username=admin.username,
                        )
                    )
                    db.delete(trow)
            else:
                action = "created" if trow is None else "updated"
                if trow is None:
                    trow = AlertRuleTuningModel(rule_id=rule_id, tuning={})
                    db.add(trow)
                trow.tuning = body.tuning or {}
                trow.updated_at = datetime.utcnow()
                trow.updated_by_user_id = admin.id
                trow.updated_by_username = admin.username
                db.add(
                    AlertRuleTuningHistoryModel(
                        rule_id=rule_id,
                        action=action,
                        snapshot={"tuning": trow.tuning or {}},
                        actor_user_id=admin.id,
                        actor_username=admin.username,
                    )
                )

        if "suppressions" in fields:
            existing = db.query(AlertRuleSuppressionModel).filter(AlertRuleSuppressionModel.rule_id == rule_id).all()
            for s in existing:
                db.add(
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
                    )
                )
                db.delete(s)

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
                db.add(srow)
                db.flush()
                db.add(
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
                    )
                )

        row.updated_at = datetime.utcnow()

        after = {
            "override": _rule_override_snapshot(row),
            "tuning": _rule_tuning_snapshot(db.get(AlertRuleTuningModel, rule_id)),
            "suppressions": _rule_suppression_snapshot(
                db.query(AlertRuleSuppressionModel).filter(AlertRuleSuppressionModel.rule_id == rule_id).all()
            ),
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

        db.commit()
        db.refresh(row)

        effective, override_payload = apply_override(base, row)
        effective = apply_tuning_and_suppressions(
            effective,
            tuning_row=db.get(AlertRuleTuningModel, rule_id),
            suppression_rows=db.query(AlertRuleSuppressionModel).filter(AlertRuleSuppressionModel.rule_id == rule_id).all(),
        )

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
            has_override=True,
            updated_at=row.updated_at,
            base=base,
            override=override_payload,
            effective=effective,
        )
    finally:
        db.close()


@router.delete("/rules/{rule_id}", status_code=204)
def delete_alert_rule_override(rule_id: str, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    """Remove all overrides for a rule (reverts to baseline YAML)."""
    db = SessionLocal()
    try:
        row = db.get(AlertRuleOverrideModel, rule_id)
        before = {
            "override": _rule_override_snapshot(row),
            "tuning": _rule_tuning_snapshot(db.get(AlertRuleTuningModel, rule_id)),
            "suppressions": _rule_suppression_snapshot(
                db.query(AlertRuleSuppressionModel).filter(AlertRuleSuppressionModel.rule_id == rule_id).all()
            ),
        }
        if row is not None:
            db.delete(row)
        trow = db.get(AlertRuleTuningModel, rule_id)
        if trow is not None:
            db.add(
                AlertRuleTuningHistoryModel(
                    rule_id=rule_id,
                    action="deleted",
                    snapshot={"tuning": trow.tuning or {}},
                    actor_user_id=admin.id,
                    actor_username=admin.username,
                )
            )
            db.delete(trow)
        sups = db.query(AlertRuleSuppressionModel).filter(AlertRuleSuppressionModel.rule_id == rule_id).all()
        for s in sups:
            db.add(
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
                )
            )
            db.delete(s)
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
        db.commit()
        return None
    finally:
        db.close()


@router.get("/rules/{rule_id}/history", response_model=List[RuleGovernanceHistoryOut])
def get_alert_rule_history(rule_id: str, limit: int = Query(100, ge=1, le=500)):
    db = SessionLocal()
    try:
        rows_t = (
            db.query(AlertRuleTuningHistoryModel)
            .filter(AlertRuleTuningHistoryModel.rule_id == rule_id)
            .order_by(AlertRuleTuningHistoryModel.created_at.desc(), AlertRuleTuningHistoryModel.id.desc())
            .limit(limit)
            .all()
        )
        rows_s = (
            db.query(AlertRuleSuppressionHistoryModel)
            .filter(AlertRuleSuppressionHistoryModel.rule_id == rule_id)
            .order_by(AlertRuleSuppressionHistoryModel.created_at.desc(), AlertRuleSuppressionHistoryModel.id.desc())
            .limit(limit)
            .all()
        )

        out: List[RuleGovernanceHistoryOut] = []
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
    finally:
        db.close()
