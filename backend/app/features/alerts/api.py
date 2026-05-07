from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.core.db.session import managed_session
from app.core.db import get_db
from app.features.auth.session import PortalPrincipal, require_admin
from app.features.alerts.schemas import AlertEvidenceOut, AlertOut, AlertTriageIn
from app.features.alerts.schemas import RuleGovernanceHistoryOut, RuleOut, RuleOverrideIn
from app.features.alerts.service import (
    delete_alert_rule_override,
    get_alert,
    get_alert_evidence,
    get_alert_rule_history,
    get_recent_alerts,
    list_alert_rules,
    list_alerts,
    mitre_coverage,
    patch_alert_rule,
    run_all_rules_now,
    run_horizontal_scan_rule,
    run_new_hosts_rule,
    run_port_scan_rule,
    run_ssh_bruteforce_rule,
    triage_alert,
)
from app.shared.schemas import CursorPage
from app.shared.taxonomy.schemas import MitreCoverageResponse


router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
    dependencies=[Depends(require_admin)],
)


@router.get("", response_model=CursorPage[AlertOut])
def list_alerts_endpoint(
    page_size: int = Query(50, ge=1, le=200, description="Page size (max 200)"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    severity: Optional[str] = Query(None, min_length=1, max_length=16, description="Optional severity filter"),
    rule_id: Optional[str] = Query(None, min_length=1, max_length=64, description="Optional rule id filter"),
    tactic: Optional[str] = Query(None, min_length=1, max_length=64, description="Optional MITRE tactic filter"),
    technique_id: Optional[str] = Query(None, min_length=1, max_length=32, description="Optional MITRE technique id filter"),
    min_confidence: Optional[int] = Query(None, ge=0, le=100, description="Optional minimum confidence (0..100)"),
    status_filter: Optional[str] = Query(None, alias="status", min_length=1, max_length=16, description="Optional lifecycle status filter"),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return list_alerts(
            db_session,
            page_size=page_size,
            cursor=cursor,
            severity=severity,
            rule_id=rule_id,
            tactic=tactic,
            technique_id=technique_id,
            min_confidence=min_confidence,
            status=status_filter,
        )


@router.get("/mitre/coverage", response_model=MitreCoverageResponse)
def mitre_coverage_endpoint(
    minutes: int = Query(1440, ge=1, le=43200, description="Lookback window in minutes"),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return mitre_coverage(db_session, minutes=minutes)


@router.post("/run/ssh-bruteforce", response_model=List[AlertOut])
def run_ssh_bruteforce_rule_endpoint(
    minutes: int = Query(10, ge=1, le=1440, description="Time window in minutes"),
    min_events: int = Query(20, ge=1, le=100000, description="Minimum number of events per source IP"),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return run_ssh_bruteforce_rule(db_session, minutes=minutes, min_events=min_events)


@router.post("/run/port-scan", response_model=List[AlertOut])
def run_port_scan_rule_endpoint(
    minutes: int = Query(10, ge=1, le=1440, description="Time window in minutes"),
    min_distinct_ports: int = Query(
        20,
        ge=1,
        le=65535,
        description="Minimum number of distinct destination ports per source IP",
    ),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return run_port_scan_rule(db_session, minutes=minutes, min_distinct_ports=min_distinct_ports)


@router.post("/run/horizontal-scan", response_model=List[AlertOut])
def run_horizontal_scan_rule_endpoint(
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
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return run_horizontal_scan_rule(
            db_session,
            minutes=minutes,
            min_distinct_targets=min_distinct_targets,
            dst_port=dst_port,
        )


@router.post("/run/new-hosts", response_model=List[AlertOut])
def run_new_hosts_rule_endpoint(
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
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return run_new_hosts_rule(db_session, minutes=minutes, min_events=min_events)


@router.get("/recent", response_model=List[AlertOut])
def get_recent_alerts_endpoint(
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of alerts to return"),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return get_recent_alerts(db_session, limit=limit)


@router.post("/run/all", response_model=List[AlertOut])
def run_all_rules_endpoint():
    return run_all_rules_now()


@router.get("/rules", response_model=List[RuleOut])
def list_alert_rules_endpoint(db: Session = Depends(get_db)):
    with managed_session(db) as db_session:
        return list_alert_rules(db_session)


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def patch_alert_rule_endpoint(
    rule_id: str,
    body: RuleOverrideIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return patch_alert_rule(
            db_session,
            rule_id=rule_id,
            body=body,
            request=request,
            admin=admin,
        )


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert_rule_override_endpoint(
    rule_id: str,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        delete_alert_rule_override(
            db_session,
            rule_id=rule_id,
            request=request,
            admin=admin,
        )
        return None


@router.get("/rules/{rule_id}/history", response_model=List[RuleGovernanceHistoryOut])
def get_alert_rule_history_endpoint(
    rule_id: str,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return get_alert_rule_history(db_session, rule_id=rule_id, limit=limit)


@router.get("/{alert_id}/evidence", response_model=List[AlertEvidenceOut])
def get_alert_evidence_endpoint(
    alert_id: int,
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return get_alert_evidence(db_session, alert_id)


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert_endpoint(
    alert_id: int,
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return get_alert(db_session, alert_id)


@router.patch("/{alert_id}/triage", response_model=AlertOut)
def triage_alert_endpoint(
    alert_id: int,
    body: AlertTriageIn,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        return triage_alert(
            db_session,
            alert_id=alert_id,
            body=body,
            actor_username=admin.username,
        )
