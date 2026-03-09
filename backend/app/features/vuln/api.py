from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Float, and_, case, cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import insert

from app.core.agent_auth import AgentPrincipal, get_current_agent
from app.core.db import SessionLocal
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.portal_auth import require_admin
from app.core.config import settings
from app.models.agents import AgentModel
from app.models.vuln import VulnFindingModel, VulnScanModel
from app.schemas.pagination import CursorPage
from app.schemas.vuln import (
    VulnAssetRiskOut,
    VulnFindingOut,
    VulnFindingPatchIn,
    VulnIngestBatch,
    VulnIngestResult,
    VulnManualScanIn,
    VulnManualScanOut,
    VulnPostureOut,
    VulnRiskItemOut,
    VulnScanOut,
    VulnSummaryOut,
)


router = APIRouter(
    prefix="/vuln",
    tags=["vuln"],
)


SEVERITY_RANK: Dict[str, int] = {
    "unknown": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _severity_rank(s: str) -> int:
    return int(SEVERITY_RANK.get((s or "").strip().lower(), 0))


def _sha256_hex(s: str) -> str:
    return sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _fingerprint(
    *,
    asset_key: str,
    source: str,
    external_id: Optional[str],
    cve: Optional[str],
    title: str,
    location: Optional[str],
) -> str:
    # Use the most stable identifiers available.
    key = external_id or cve or title
    raw = "|".join(
        [
            (asset_key or "").strip().lower(),
            (source or "").strip().lower(),
            (key or "").strip().lower(),
            (location or "").strip().lower(),
        ]
    )
    return _sha256_hex(raw)


def _truncate_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    max_bytes = int(settings.NETWATCH_VULN_MAX_EVIDENCE_BYTES or 32768)
    if max_bytes < 1024:
        max_bytes = 1024

    try:
        raw = json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return {"truncated": True, "reason": "evidence_not_json_serializable"}

    b = raw.encode("utf-8", errors="ignore")
    if len(b) <= max_bytes:
        return evidence

    preview = b[: min(len(b), 2048)].decode("utf-8", errors="ignore")
    return {
        "truncated": True,
        "original_size_bytes": len(b),
        "sha256": sha256(b).hexdigest(),
        "keys": list(evidence.keys())[:50],
        "preview": preview,
    }


def _env_int(name: str, default: int) -> int:
    raw = getattr(settings, name, None)
    if raw is None:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = getattr(settings, name, None)
    if raw is None:
        return default
    v = str(raw).strip().lower()
    if v in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _cvss_numeric_expr(vf=VulnFindingModel):
    return case(
        (vf.cvss.op("~")(r"^[0-9]+(\.[0-9]+)?$"), cast(vf.cvss, Float)),
        else_=0.0,
    )


def _has_fix_expr(vf=VulnFindingModel):
    return or_(
        vf.evidence["osv"]["fixed"].astext.is_not(None),
        and_(vf.remediation.is_not(None), func.btrim(vf.remediation) != ""),
    )


def _internet_exposed_expr(vf=VulnFindingModel):
    return func.upper(func.coalesce(vf.cvss, "")).like("%AV:N%")


def _risk_score_expr(now: datetime, vf=VulnFindingModel):
    cvss_num = _cvss_numeric_expr(vf)
    cve_present = and_(vf.cve.is_not(None), func.btrim(vf.cve) != "")
    has_fix = _has_fix_expr(vf)
    internet_exposed = _internet_exposed_expr(vf)

    cvss_points = case(
        (cvss_num >= 9.0, 16.0),
        (cvss_num >= 7.0, 10.0),
        (cvss_num >= 4.0, 5.0),
        else_=0.0,
    )


def _normalize_cfg_map(v: Any) -> Dict[str, Any]:
    if isinstance(v, dict):
        return dict(v)
    return {}


    recency_points = case(
        (vf.last_seen_at >= now - timedelta(hours=24), 8.0),
        (vf.last_seen_at >= now - timedelta(days=7), 4.0),
        else_=0.0,
    )

    return func.least(
        100.0,
        (
            cast(vf.severity_rank, Float) * 18.0
            + cast(func.least(func.greatest(vf.confidence, 0), 100), Float) * 0.12
            + cast(func.least(func.greatest(vf.occurrences, 1), 50), Float) * 0.45
            + case((cve_present, 6.0), else_=0.0)
            + cvss_points
            + case((internet_exposed, 6.0), else_=0.0)
            + case((has_fix, 4.0), else_=0.0)
            + recency_points
        ),
    )


@router.post(
    "/ingest",
    response_model=VulnIngestResult,
    status_code=status.HTTP_201_CREATED,
)
def ingest_findings(
    payload: VulnIngestBatch,
    agent: AgentPrincipal = Depends(get_current_agent),
):
    """Ingest vulnerability findings from an agent.

    The design goal is to keep the backend source-of-truth in Postgres, while
    allowing multiple scanners (host package scanners, network scanners, web
    template engines, etc.) to feed a single deduplicated findings table.

    Deduplication key: (asset_key, fingerprint)
    """

    max_findings = _env_int("NETWATCH_VULN_MAX_FINDINGS_PER_INGEST", 2000)
    if max_findings < 1:
        max_findings = 1
    if len(payload.findings) > max_findings:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Too many findings in a single ingest (max {max_findings})",
        )

    scan_uuid: Optional[str] = None
    scan_id: Optional[int] = None

    now = _utc_now()
    auto_reopen = _env_bool("NETWATCH_VULN_AUTO_REOPEN", True)

    db = SessionLocal()
    try:
        # Upsert scan metadata (optional)
        if payload.scan is not None:
            scan_uuid = (payload.scan.scan_uuid or "").strip() or str(uuid.uuid4())
            started_at = _ensure_utc(payload.scan.started_at) or now
            finished_at = _ensure_utc(payload.scan.finished_at)

            scan_insert = insert(VulnScanModel).values(
                scan_uuid=scan_uuid,
                reporter_agent_id=agent.agent_id,
                target=payload.scan.target,
                tool=payload.scan.tool,
                tool_version=payload.scan.tool_version,
                status=payload.scan.status,
                started_at=started_at,
                finished_at=finished_at,
                scope=dict(payload.scan.scope or {}),
                config=dict(payload.scan.config or {}),
                stats=dict(payload.scan.stats or {}),
                updated_at=now,
            )
            scan_upsert = scan_insert.on_conflict_do_update(
                index_elements=[VulnScanModel.scan_uuid],
                set_={
                    "reporter_agent_id": scan_insert.excluded.reporter_agent_id,
                    "target": func.coalesce(scan_insert.excluded.target, VulnScanModel.target),
                    "tool": scan_insert.excluded.tool,
                    "tool_version": func.coalesce(scan_insert.excluded.tool_version, VulnScanModel.tool_version),
                    "status": scan_insert.excluded.status,
                    "started_at": func.least(VulnScanModel.started_at, scan_insert.excluded.started_at),
                    "finished_at": func.coalesce(scan_insert.excluded.finished_at, VulnScanModel.finished_at),
                    "scope": VulnScanModel.scope.op("||")(scan_insert.excluded.scope),
                    "config": VulnScanModel.config.op("||")(scan_insert.excluded.config),
                    "stats": VulnScanModel.stats.op("||")(scan_insert.excluded.stats),
                    "updated_at": now,
                },
            ).returning(VulnScanModel.id)
            row = db.execute(scan_upsert).first()
            scan_id = int(row[0]) if row and row[0] is not None else None

        if not payload.findings:
            db.commit()
            return VulnIngestResult(scan_id=scan_id, scan_uuid=scan_uuid, received_findings=0, stored_findings=0)

        rows: List[Dict[str, Any]] = []
        for f in payload.findings:
            fp = (f.fingerprint or "").strip()
            if not fp:
                fp = _fingerprint(
                    asset_key=f.asset_key,
                    source=f.source,
                    external_id=f.external_id,
                    cve=f.cve,
                    title=f.title,
                    location=f.location,
                )

            sev = (f.severity or "unknown").strip().lower() or "unknown"
            sev_rank = _severity_rank(sev)

            asset_key = f.asset_key.strip()
            if asset_key.lower() in {"self", "local"}:
                asset_key = f"agent:{agent.agent_id}"

            last_seen = _ensure_utc(f.last_seen_at or now) or now

            rows.append(
                {
                    "scan_id": scan_id,
                    "asset_key": asset_key,
                    "asset_agent_id": f.asset_agent_id,
                    "reporter_agent_id": agent.agent_id,
                    "target": f.target,
                    "asset": dict(f.asset or {}),
                    "source": f.source,
                    "external_id": f.external_id,
                    "fingerprint": fp,
                    "severity": sev,
                    "severity_rank": sev_rank,
                    "confidence": int(f.confidence or 0),
                    "title": f.title,
                    "description": f.description,
                    "remediation": f.remediation,
                    "cve": f.cve,
                    "cwe": f.cwe,
                    "cvss": f.cvss,
                    "location": f.location,
                    "tags": list(f.tags or []),
                    "evidence": _truncate_evidence(dict(f.evidence or {})),
                    "last_seen_at": last_seen,
                    "status": "open",
                    "is_suppressed": False,
                    "first_seen_at": now,
                    "occurrences": 1,
                    "updated_at": now,
                }
            )

        finding_insert = insert(VulnFindingModel).values(rows)
        excl = finding_insert.excluded
        finding_upsert = finding_insert.on_conflict_do_update(
            index_elements=[VulnFindingModel.asset_key, VulnFindingModel.fingerprint],
            set_={
                "scan_id": func.coalesce(excl.scan_id, VulnFindingModel.scan_id),
                "asset_agent_id": func.coalesce(excl.asset_agent_id, VulnFindingModel.asset_agent_id),
                "reporter_agent_id": func.coalesce(excl.reporter_agent_id, VulnFindingModel.reporter_agent_id),
                "target": func.coalesce(excl.target, VulnFindingModel.target),
                "asset": VulnFindingModel.asset.op("||")(excl.asset),
                "source": excl.source,
                "external_id": func.coalesce(excl.external_id, VulnFindingModel.external_id),
                "severity": case(
                    (excl.severity_rank > VulnFindingModel.severity_rank, excl.severity),
                    else_=VulnFindingModel.severity,
                ),
                "severity_rank": func.greatest(VulnFindingModel.severity_rank, excl.severity_rank),
                "confidence": func.greatest(VulnFindingModel.confidence, excl.confidence),
                "title": func.coalesce(func.nullif(excl.title, ""), VulnFindingModel.title),
                "description": func.coalesce(excl.description, VulnFindingModel.description),
                "remediation": func.coalesce(excl.remediation, VulnFindingModel.remediation),
                "cve": func.coalesce(excl.cve, VulnFindingModel.cve),
                "cwe": func.coalesce(excl.cwe, VulnFindingModel.cwe),
                "cvss": func.coalesce(excl.cvss, VulnFindingModel.cvss),
                "location": func.coalesce(excl.location, VulnFindingModel.location),
                "tags": case((func.jsonb_array_length(excl.tags) > 0, excl.tags), else_=VulnFindingModel.tags),
                "evidence": VulnFindingModel.evidence.op("||")(excl.evidence),
                "last_seen_at": func.greatest(VulnFindingModel.last_seen_at, excl.last_seen_at),
                "occurrences": VulnFindingModel.occurrences + 1,
                "status": case(
                    (
                        and_(literal(bool(auto_reopen)).is_(True), VulnFindingModel.status.in_(["fixed", "resolved"])),
                        literal("open"),
                    ),
                    else_=VulnFindingModel.status,
                ),
                "updated_at": now,
            },
        )
        db.execute(finding_upsert)
        db.commit()

        return VulnIngestResult(
            scan_id=scan_id,
            scan_uuid=scan_uuid,
            received_findings=len(payload.findings),
            stored_findings=len(payload.findings),
        )
    finally:
        db.close()


@router.post(
    "/scan-now",
    response_model=VulnManualScanOut,
    dependencies=[Depends(require_admin)],
)
def trigger_manual_scan(body: VulnManualScanIn):
    db = SessionLocal()
    try:
        row: AgentModel | None = db.query(AgentModel).filter(AgentModel.agent_id == body.agent_id).first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        if row.is_revoked:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")
        now = _utc_now()
        token = str(uuid.uuid4())

        cfg = _normalize_cfg_map(row.config)
        modules = _normalize_cfg_map(cfg.get("modules"))
        vcfg = _normalize_cfg_map(modules.get("vulnscanner"))

        # Preserve existing runtime knobs and just append the trigger token.
        if "enabled" not in vcfg:
            vcfg["enabled"] = True
        vcfg["scan_now_token"] = token
        vcfg["scan_now_at"] = now.isoformat()

        modules["vulnscanner"] = vcfg
        cfg["modules"] = modules
        row.config = cfg

        # Create a queued scan record immediately so the frontend can track progress
        # before the agent polls and starts execution.
        qscan = VulnScanModel(
            scan_uuid=token,
            reporter_agent_id=body.agent_id,
            target=f"agent:{body.agent_id}",
            tool="osv-wazuh-like",
            tool_version="1",
            status="queued",
            started_at=now,
            finished_at=None,
            scope={
                "type": "manual_trigger",
                "manual_trigger": True,
                "trigger_token": token,
            },
            config={
                "manual_trigger": True,
                "analysis_profile": str(vcfg.get("analysis_profile") or "wazuh_like_v1"),
            },
            stats={},
            updated_at=now,
        )
        db.add(qscan)

        db.add(row)
        db.commit()

        return VulnManualScanOut(
            agent_id=body.agent_id,
            trigger_token=token,
            scan_uuid=token,
            status="queued",
            queued_at=now,
        )
    finally:
        db.close()


@router.get(
    "/scans",
    response_model=CursorPage[VulnScanOut],
    dependencies=[Depends(require_admin)],
)
def list_scans(
    page_size: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
    reporter_agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    status_q: Optional[str] = Query(None, min_length=1, max_length=16),
    tool: Optional[str] = Query(None, min_length=1, max_length=64),
):
    db = SessionLocal()
    try:
        stmt = select(VulnScanModel).order_by(VulnScanModel.started_at.desc(), VulnScanModel.id.desc())
        if reporter_agent_id:
            stmt = stmt.where(VulnScanModel.reporter_agent_id == reporter_agent_id)
        if status_q:
            stmt = stmt.where(VulnScanModel.status == status_q.lower())
        if tool:
            stmt = stmt.where(VulnScanModel.tool == tool.lower())

        if cursor:
            c_ts, c_id = parse_cursor_ts_id(cursor)
            stmt = stmt.where(
                or_(
                    VulnScanModel.started_at < c_ts,
                    and_(VulnScanModel.started_at == c_ts, VulnScanModel.id < c_id),
                )
            )

        rows = db.execute(stmt.limit(page_size + 1)).scalars().all()
        has_more = len(rows) > page_size
        items = rows[:page_size]
        next_cursor = make_cursor_ts_id(items[-1].started_at, items[-1].id) if has_more and items else None
        return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)
    finally:
        db.close()


@router.get(
    "/findings",
    response_model=CursorPage[VulnFindingOut],
    dependencies=[Depends(require_admin)],
)
def list_findings(
    page_size: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
    asset_agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    reporter_agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    status_q: Optional[str] = Query(None, min_length=1, max_length=16),
    min_severity: Optional[str] = Query(None, min_length=1, max_length=16),
    cve: Optional[str] = Query(None, min_length=1, max_length=32),
    q: Optional[str] = Query(None, min_length=1, max_length=128, description="Search (title/target/cve/external_id)"),
    include_suppressed: bool = Query(False),
):
    db = SessionLocal()
    try:
        stmt = select(VulnFindingModel).order_by(VulnFindingModel.last_seen_at.desc(), VulnFindingModel.id.desc())

        if asset_agent_id:
            stmt = stmt.where(VulnFindingModel.asset_agent_id == asset_agent_id)
        if reporter_agent_id:
            stmt = stmt.where(VulnFindingModel.reporter_agent_id == reporter_agent_id)
        if status_q:
            stmt = stmt.where(VulnFindingModel.status == status_q.lower())
        if not include_suppressed:
            stmt = stmt.where(VulnFindingModel.is_suppressed.is_(False))

        if min_severity:
            stmt = stmt.where(VulnFindingModel.severity_rank >= _severity_rank(min_severity))
        if cve:
            stmt = stmt.where(VulnFindingModel.cve == cve)

        if q:
            q2 = f"%{q.strip()}%"
            stmt = stmt.where(
                or_(
                    VulnFindingModel.title.ilike(q2),
                    VulnFindingModel.target.ilike(q2),
                    VulnFindingModel.cve.ilike(q2),
                    VulnFindingModel.external_id.ilike(q2),
                )
            )

        if cursor:
            c_ts, c_id = parse_cursor_ts_id(cursor)
            stmt = stmt.where(
                or_(
                    VulnFindingModel.last_seen_at < c_ts,
                    and_(VulnFindingModel.last_seen_at == c_ts, VulnFindingModel.id < c_id),
                )
            )

        rows = db.execute(stmt.limit(page_size + 1)).scalars().all()
        has_more = len(rows) > page_size
        items = rows[:page_size]
        next_cursor = make_cursor_ts_id(items[-1].last_seen_at, items[-1].id) if has_more and items else None
        return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)
    finally:
        db.close()


@router.get(
    "/findings/{finding_id}",
    response_model=VulnFindingOut,
    dependencies=[Depends(require_admin)],
)
def get_finding(finding_id: int):
    db = SessionLocal()
    try:
        row = db.get(VulnFindingModel, finding_id)
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return row
    finally:
        db.close()


@router.patch(
    "/findings/{finding_id}",
    response_model=VulnFindingOut,
    dependencies=[Depends(require_admin)],
)
def patch_finding(finding_id: int, patch: VulnFindingPatchIn):
    db = SessionLocal()
    try:
        row: VulnFindingModel | None = db.get(VulnFindingModel, finding_id)
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

        if patch.status is not None:
            row.status = patch.status
        if patch.is_suppressed is not None:
            row.is_suppressed = bool(patch.is_suppressed)
        row.updated_at = _utc_now()

        db.add(row)
        db.commit()
        db.refresh(row)
        return row
    finally:
        db.close()


@router.get(
    "/summary",
    response_model=VulnSummaryOut,
    dependencies=[Depends(require_admin)],
)
def summary(
    active_within_days: int = Query(30, ge=1, le=365),
    include_suppressed: bool = Query(False),
):
    """High-level vulnerability overview.

    `active_within_days` counts findings with `last_seen_at` within the window.
    """

    db = SessionLocal()
    try:
        now = _utc_now()
        since = now - timedelta(days=int(active_within_days))

        conds = [VulnFindingModel.last_seen_at >= since]
        if not include_suppressed:
            conds.append(VulnFindingModel.is_suppressed.is_(False))

        total_open = (
            db.execute(
                select(func.count())
                .select_from(VulnFindingModel)
                .where(*conds)
                .where(VulnFindingModel.status == "open")
            ).scalar_one()
            or 0
        )

        total_suppressed = (
            db.execute(
                select(func.count())
                .select_from(VulnFindingModel)
                .where(VulnFindingModel.last_seen_at >= since)
                .where(VulnFindingModel.is_suppressed.is_(True))
            ).scalar_one()
            or 0
        )

        by_sev_rows = db.execute(
            select(VulnFindingModel.severity, func.count())
            .select_from(VulnFindingModel)
            .where(*conds)
            .group_by(VulnFindingModel.severity)
        ).all()
        by_severity = {str(k or "unknown"): int(v or 0) for (k, v) in by_sev_rows}

        by_status_rows = db.execute(
            select(VulnFindingModel.status, func.count())
            .select_from(VulnFindingModel)
            .where(*conds)
            .group_by(VulnFindingModel.status)
        ).all()
        by_status = {str(k or "unknown"): int(v or 0) for (k, v) in by_status_rows}

        # If include_suppressed=false, the totals reflect only the visible set.
        # total_suppressed is reported separately across all active findings.
        return VulnSummaryOut(
            generated_at=now,
            total_open=int(total_open),
            total_suppressed=int(total_suppressed),
            by_severity=by_severity,
            by_status=by_status,
        )
    finally:
        db.close()


@router.get(
    "/posture",
    response_model=VulnPostureOut,
    dependencies=[Depends(require_admin)],
)
def posture(
    active_within_days: int = Query(30, ge=1, le=365),
    include_suppressed: bool = Query(False),
    top_n: int = Query(15, ge=5, le=50),
):
    """Actionable vulnerability posture with risk-based prioritization."""

    db = SessionLocal()
    try:
        now = _utc_now()
        since = now - timedelta(days=int(active_within_days))
        stale_before = now - timedelta(days=30)
        vf = VulnFindingModel
        risk_expr = _risk_score_expr(now, vf).label("risk_score")
        cvss_num = _cvss_numeric_expr(vf).label("cvss_score")
        has_fix = _has_fix_expr(vf).label("has_fix")
        internet_exposed = _internet_exposed_expr(vf).label("internet_exposed")
        exploit_likely = or_(
            _cvss_numeric_expr(vf) >= 7.0,
            _internet_exposed_expr(vf),
            and_(vf.cve.is_not(None), func.btrim(vf.cve) != "", vf.severity_rank >= 3),
        ).label("exploit_likely")

        base_conds = [vf.status == "open", vf.last_seen_at >= since]
        if not include_suppressed:
            base_conds.append(vf.is_suppressed.is_(False))

        base = (
            select(
                vf.id.label("id"),
                vf.asset_key.label("asset_key"),
                vf.asset_agent_id.label("asset_agent_id"),
                vf.target.label("target"),
                vf.title.label("title"),
                vf.cve.label("cve"),
                vf.severity.label("severity"),
                vf.severity_rank.label("severity_rank"),
                vf.confidence.label("confidence"),
                vf.occurrences.label("occurrences"),
                vf.last_seen_at.label("last_seen_at"),
                vf.remediation.label("remediation"),
                vf.cvss.label("cvss"),
                cvss_num,
                has_fix,
                internet_exposed,
                exploit_likely,
                risk_expr,
            )
            .where(*base_conds)
            .subquery("base")
        )

        totals = (
            db.execute(
                select(
                    func.count().label("total_open"),
                    func.sum(case((base.c.severity == "critical", 1), else_=0)).label("critical_open"),
                    func.sum(case((base.c.severity == "high", 1), else_=0)).label("high_open"),
                    func.sum(case((base.c.exploit_likely.is_(True), 1), else_=0)).label("exploitable_open"),
                    func.sum(case((base.c.has_fix.is_(True), 1), else_=0)).label("fixable_open"),
                    func.sum(case((base.c.last_seen_at < stale_before, 1), else_=0)).label("stale_open"),
                    func.coalesce(func.avg(base.c.risk_score), 0.0).label("mean_risk"),
                    func.coalesce(func.percentile_cont(0.95).within_group(base.c.risk_score), 0.0).label("p95_risk"),
                )
            )
            .mappings()
            .first()
            or {}
        )

        top_rows = db.execute(
            select(
                base.c.id,
                base.c.asset_key,
                base.c.asset_agent_id,
                base.c.target,
                base.c.title,
                base.c.cve,
                base.c.severity,
                base.c.confidence,
                base.c.occurrences,
                base.c.last_seen_at,
                base.c.remediation,
                base.c.cvss,
                base.c.cvss_score,
                base.c.has_fix,
                base.c.internet_exposed,
                base.c.exploit_likely,
                base.c.risk_score,
            )
            .order_by(base.c.risk_score.desc(), base.c.last_seen_at.desc(), base.c.id.desc())
            .limit(int(top_n))
        ).mappings().all()

        asset_rows = db.execute(
            select(
                base.c.asset_key,
                func.max(base.c.asset_agent_id).label("asset_agent_id"),
                func.count().label("open_findings"),
                func.sum(case((base.c.severity_rank >= 3, 1), else_=0)).label("critical_high"),
                func.coalesce(func.max(base.c.risk_score), 0.0).label("max_risk"),
                func.coalesce(func.avg(base.c.risk_score), 0.0).label("avg_risk"),
                func.max(base.c.last_seen_at).label("last_seen_at"),
            )
            .group_by(base.c.asset_key)
            .order_by(
                func.max(base.c.risk_score).desc(),
                func.sum(case((base.c.severity_rank >= 3, 1), else_=0)).desc(),
                func.count().desc(),
            )
            .limit(10)
        ).mappings().all()

        return VulnPostureOut(
            generated_at=now,
            active_within_days=int(active_within_days),
            total_open=int(totals.get("total_open") or 0),
            critical_open=int(totals.get("critical_open") or 0),
            high_open=int(totals.get("high_open") or 0),
            exploitable_open=int(totals.get("exploitable_open") or 0),
            fixable_open=int(totals.get("fixable_open") or 0),
            stale_open=int(totals.get("stale_open") or 0),
            mean_risk=float(totals.get("mean_risk") or 0.0),
            p95_risk=float(totals.get("p95_risk") or 0.0),
            top_risks=[VulnRiskItemOut(**dict(r)) for r in top_rows],
            top_assets=[VulnAssetRiskOut(**dict(r)) for r in asset_rows],
        )
    finally:
        db.close()
