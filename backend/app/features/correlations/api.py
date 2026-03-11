from __future__ import annotations

from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from typing import Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select

from app.core.audit import audit_actor, write_audit_event
from app.core.db import SessionLocal
from app.core.portal_auth import PortalPrincipal, require_admin
from app.models.alerts import AlertModel
from app.models.correlation_rules import CorrelationRuleModel
from app.schemas.correlations import (
    CorrelationAlertRef,
    CorrelationIncidentOut,
    CorrelationRunOut,
    CorrelationRuleIn,
    CorrelationRuleOut,
)


router = APIRouter(
    prefix="/correlations",
    tags=["correlations"],
    dependencies=[Depends(require_admin)],
)


def _norm_patterns(v: Optional[Iterable[str]]) -> List[str]:
    if not v:
        return []
    out: List[str] = []
    seen = set()
    for raw in v:
        s = str(raw or "").strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def _match_any(rule_id: str, patterns: List[str]) -> bool:
    if not patterns:
        return False
    rid = str(rule_id or "")
    for p in patterns:
        # case-insensitive wildcard matching
        if fnmatchcase(rid.lower(), p.lower()):
            return True
    return False


def _passes_filter(rule_id: str, include: List[str], exclude: List[str]) -> bool:
    if exclude and _match_any(rule_id, exclude):
        return False
    if not include:
        return True
    return _match_any(rule_id, include)


def _group_value(alert: AlertModel, group_by: str) -> str:
    g = (group_by or "").lower().strip()
    src = alert.src_ip or "-"
    dst = alert.dst_ip or "-"
    port = str(alert.dst_port) if alert.dst_port is not None else "-"

    if g in ("src", "src_ip", "source"):
        return src
    if g in ("dst", "dst_ip", "destination"):
        return dst
    if g in ("dst_port", "port"):
        return port
    if g in ("src_dst", "src+dst", "pair"):
        return f"{src}→{dst}"
    if g in ("src_dst_port", "tuple"):
        return f"{src}→{dst}:{port}"
    # none / unknown
    return "all"


def _segment_by_window(alerts: List[AlertModel], window_seconds: int) -> List[List[AlertModel]]:
    """Split an ordered list of alerts into fixed-window segments.

    The segment boundary is based on the first alert in the segment, to keep
    segment duration <= window_seconds.
    """

    if not alerts:
        return []

    w = max(1, int(window_seconds))
    # Ensure ascending time
    alerts_sorted = sorted(alerts, key=lambda a: a.created_at)

    segments: List[List[AlertModel]] = []
    cur: List[AlertModel] = [alerts_sorted[0]]
    seg_start = alerts_sorted[0].created_at

    for a in alerts_sorted[1:]:
        dt = (a.created_at - seg_start).total_seconds()
        if dt <= w:
            cur.append(a)
            continue
        segments.append(cur)
        cur = [a]
        seg_start = a.created_at

    if cur:
        segments.append(cur)
    return segments


def _compute_stage_hits(seg: List[AlertModel], stages: List[dict]) -> Dict[str, int]:
    hits: Dict[str, int] = {}
    for st in stages or []:
        name = str((st or {}).get("name") or "").strip() or "stage"
        pats = _norm_patterns((st or {}).get("patterns") or [])
        if not pats:
            hits[name] = 0
            continue
        hits[name] = sum(1 for a in seg if _match_any(a.rule_id, pats))
    return hits


def _stage_requirements_met(hits: Dict[str, int], stages: List[dict]) -> bool:
    for st in stages or []:
        name = str((st or {}).get("name") or "").strip() or "stage"
        min_count = int((st or {}).get("min_count") or 1)
        if hits.get(name, 0) < max(1, min_count):
            return False
    return True


def _alert_ref(a: AlertModel) -> CorrelationAlertRef:
    return CorrelationAlertRef(
        id=a.id,
        created_at=a.created_at,
        rule_id=a.rule_id,
        severity=a.severity,
        src_ip=a.src_ip,
        dst_ip=a.dst_ip,
        dst_port=a.dst_port,
        description=a.description,
    )


@router.get("/rules", response_model=List[CorrelationRuleOut])
def list_correlation_rules():
    db = SessionLocal()
    try:
        rows = db.execute(select(CorrelationRuleModel).order_by(CorrelationRuleModel.id.asc())).scalars().all()
        return rows
    finally:
        db.close()


@router.post("/rules", response_model=CorrelationRuleOut)
def create_correlation_rule(payload: CorrelationRuleIn, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        m = CorrelationRuleModel(
            name=payload.name,
            description=payload.description,
            enabled=bool(payload.enabled),
            severity=payload.severity,
            strategy=payload.strategy,
            group_by=payload.group_by,
            window_seconds=int(payload.window_seconds),
            min_alerts=int(payload.min_alerts),
            include_patterns=_norm_patterns(payload.include_patterns),
            exclude_patterns=_norm_patterns(payload.exclude_patterns),
            stages=[s.dict() for s in (payload.stages or [])],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(m)
        db.flush()
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="correlation_rule.create",
            resource_type="correlation_rule",
            resource_id=str(m.id),
            outcome="success",
            before={},
            after={
                "id": m.id,
                "name": m.name,
                "enabled": bool(m.enabled),
                "severity": m.severity,
                "strategy": m.strategy,
                "group_by": m.group_by,
                "window_seconds": int(m.window_seconds),
                "min_alerts": int(m.min_alerts),
                "include_patterns": m.include_patterns,
                "exclude_patterns": m.exclude_patterns,
                "stages": m.stages,
            },
        )
        db.commit()
        db.refresh(m)
        return m
    finally:
        db.close()


@router.put("/rules/{rule_id}", response_model=CorrelationRuleOut)
def update_correlation_rule(rule_id: int, payload: CorrelationRuleIn, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        m = db.get(CorrelationRuleModel, rule_id)
        if not m:
            raise HTTPException(status_code=404, detail="Correlation rule not found")

        before = {
            "id": m.id,
            "name": m.name,
            "enabled": bool(m.enabled),
            "severity": m.severity,
            "strategy": m.strategy,
            "group_by": m.group_by,
            "window_seconds": int(m.window_seconds),
            "min_alerts": int(m.min_alerts),
            "include_patterns": m.include_patterns,
            "exclude_patterns": m.exclude_patterns,
            "stages": m.stages,
        }
        m.name = payload.name
        m.description = payload.description
        m.enabled = bool(payload.enabled)
        m.severity = payload.severity
        m.strategy = payload.strategy
        m.group_by = payload.group_by
        m.window_seconds = int(payload.window_seconds)
        m.min_alerts = int(payload.min_alerts)
        m.include_patterns = _norm_patterns(payload.include_patterns)
        m.exclude_patterns = _norm_patterns(payload.exclude_patterns)
        m.stages = [s.dict() for s in (payload.stages or [])]
        m.updated_at = datetime.utcnow()

        db.add(m)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="correlation_rule.update",
            resource_type="correlation_rule",
            resource_id=str(m.id),
            outcome="success",
            before=before,
            after={
                "id": m.id,
                "name": m.name,
                "enabled": bool(m.enabled),
                "severity": m.severity,
                "strategy": m.strategy,
                "group_by": m.group_by,
                "window_seconds": int(m.window_seconds),
                "min_alerts": int(m.min_alerts),
                "include_patterns": m.include_patterns,
                "exclude_patterns": m.exclude_patterns,
                "stages": m.stages,
            },
        )
        db.commit()
        db.refresh(m)
        return m
    finally:
        db.close()


@router.delete("/rules/{rule_id}")
def delete_correlation_rule(rule_id: int, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        m = db.get(CorrelationRuleModel, rule_id)
        if not m:
            raise HTTPException(status_code=404, detail="Correlation rule not found")
        before = {
            "id": m.id,
            "name": m.name,
            "enabled": bool(m.enabled),
            "severity": m.severity,
            "strategy": m.strategy,
            "group_by": m.group_by,
            "window_seconds": int(m.window_seconds),
            "min_alerts": int(m.min_alerts),
            "include_patterns": m.include_patterns,
            "exclude_patterns": m.exclude_patterns,
            "stages": m.stages,
        }
        db.delete(m)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="correlation_rule.delete",
            resource_type="correlation_rule",
            resource_id=str(rule_id),
            outcome="success",
            before=before,
            after={},
        )
        db.commit()
        return {"ok": True}
    finally:
        db.close()


@router.post("/run", response_model=CorrelationRunOut)
def run_correlations(
    limit: int = Query(500, ge=1, le=5000, description="How many recent alerts to scan"),
    max_age_minutes: int = Query(1440, ge=1, le=60 * 24 * 14, description="Ignore alerts older than this"),
    sample_limit: int = Query(25, ge=1, le=200, description="How many alerts to include per incident"),
):
    """Run correlation rules against recent alerts.

    This is a synchronous, on-demand compute endpoint intended for small/medium
    environments (portal use). In larger deployments, move this into a worker
    and persist incident rows.
    """
    db = SessionLocal()
    try:
        rules = (
            db.execute(
                select(CorrelationRuleModel)
                .where(CorrelationRuleModel.enabled.is_(True))
                .order_by(CorrelationRuleModel.id.asc())
            )
            .scalars()
            .all()
        )

        min_ts = datetime.utcnow() - timedelta(minutes=max_age_minutes)
        alerts = (
            db.execute(
                select(AlertModel)
                .where(AlertModel.created_at >= min_ts)
                .order_by(AlertModel.created_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )

        # Compute incidents
        incidents: List[CorrelationIncidentOut] = []

        for r in rules:
            include = _norm_patterns(getattr(r, "include_patterns", None) or [])
            exclude = _norm_patterns(getattr(r, "exclude_patterns", None) or [])
            strategy = str(getattr(r, "strategy", "burst") or "burst").lower()
            group_by = str(getattr(r, "group_by", "src_ip") or "src_ip")
            window_seconds = int(getattr(r, "window_seconds", 600) or 600)
            min_alerts = int(getattr(r, "min_alerts", 2) or 2)
            stages = list(getattr(r, "stages", None) or [])

            # Group alerts by key
            grouped: Dict[str, List[AlertModel]] = {}
            for a in alerts:
                if not _passes_filter(a.rule_id, include, exclude):
                    continue
                gv = _group_value(a, group_by)
                grouped.setdefault(gv, []).append(a)

            for gv, rows in grouped.items():
                segments = _segment_by_window(rows, window_seconds)
                for seg in segments:
                    if not seg:
                        continue
                    if len(seg) < min_alerts:
                        continue

                    stage_hits = _compute_stage_hits(seg, stages) if strategy == "chain" else {}
                    if strategy == "chain" and not _stage_requirements_met(stage_hits, stages):
                        continue

                    start = min(a.created_at for a in seg)
                    end = max(a.created_at for a in seg)
                    unique_rules = sorted({a.rule_id for a in seg})
                    incident_id = f"cr{r.id}:{gv}:{start.isoformat()}"

                    # Sort newest first for sample
                    sample = sorted(seg, key=lambda a: a.created_at, reverse=True)[: max(1, int(sample_limit))]

                    incidents.append(
                        CorrelationIncidentOut(
                            id=incident_id,
                            correlation_rule_id=r.id,
                            correlation_rule_name=r.name,
                            severity=r.severity,
                            group_by=group_by,
                            group_value=gv,
                            started_at=start,
                            ended_at=end,
                            alert_count=len(seg),
                            unique_rules=unique_rules,
                            stage_hits=stage_hits,
                            sample_alerts=[_alert_ref(x) for x in sample],
                        )
                    )

        # Show newest incidents first
        incidents.sort(key=lambda x: x.started_at, reverse=True)
        return CorrelationRunOut(rules_evaluated=len(rules), alerts_scanned=len(alerts), incidents=incidents)
    finally:
        db.close()
