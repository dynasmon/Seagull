from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select, text

from app.core.agent_auth import AgentPrincipal, get_current_agent
from app.core.db import SessionLocal
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.portal_auth import require_admin
from app.models.vuln import VulnFindingModel, VulnScanModel
from app.schemas.pagination import CursorPage
from app.schemas.vuln import (
    VulnAssetRiskOut,
    VulnFindingOut,
    VulnFindingPatchIn,
    VulnIngestBatch,
    VulnIngestResult,
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
    max_bytes = int((os.getenv("NETWATCH_VULN_MAX_EVIDENCE_BYTES") or "32768").strip() or "32768")
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
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _risk_score_sql() -> str:
    """Return SQL expression (0-100) for finding risk prioritization."""

    # Model:
    # - severity dominates baseline
    # - confidence + recurrence + recency raise urgency
    # - CVSS/exposure/CVE/fixability improve exploitability/actionability ranking
    return """
        LEAST(
          100.0,
          (
            (vf.severity_rank::float * 18.0)
            + (LEAST(GREATEST(vf.confidence, 0), 100)::float * 0.12)
            + (LEAST(GREATEST(vf.occurrences, 1), 50)::float * 0.45)
            + (CASE WHEN vf.cve IS NOT NULL AND btrim(vf.cve) <> '' THEN 6.0 ELSE 0.0 END)
            + (
                CASE
                  WHEN vf.cvss ~ '^[0-9]+(\\.[0-9]+)?$' THEN
                    CASE
                      WHEN (vf.cvss::double precision) >= 9.0 THEN 16.0
                      WHEN (vf.cvss::double precision) >= 7.0 THEN 10.0
                      WHEN (vf.cvss::double precision) >= 4.0 THEN 5.0
                      ELSE 0.0
                    END
                  ELSE 0.0
                END
              )
            + (
                CASE
                  WHEN upper(COALESCE(vf.cvss, '')) LIKE '%AV:N%' THEN 6.0
                  ELSE 0.0
                END
              )
            + (
                CASE
                  WHEN (
                    (vf.evidence -> 'osv' ->> 'fixed') IS NOT NULL
                    OR (vf.remediation IS NOT NULL AND btrim(vf.remediation) <> '')
                  ) THEN 4.0
                  ELSE 0.0
                END
              )
            + (
                CASE
                  WHEN vf.last_seen_at >= ((now() AT TIME ZONE 'utc') - interval '24 hours') THEN 8.0
                  WHEN vf.last_seen_at >= ((now() AT TIME ZONE 'utc') - interval '7 days') THEN 4.0
                  ELSE 0.0
                END
              )
          )
        )
    """


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

            stmt = text(
                """
                INSERT INTO vuln_scans (
                    scan_uuid, reporter_agent_id, target, tool, tool_version, status,
                    started_at, finished_at, scope, config, stats, updated_at
                )
                VALUES (
                    :scan_uuid, :reporter_agent_id, :target, :tool, :tool_version, :status,
                    :started_at, :finished_at,
                    CAST(:scope AS jsonb), CAST(:config AS jsonb), CAST(:stats AS jsonb),
                    now()
                )
                ON CONFLICT (scan_uuid)
                DO UPDATE SET
                    reporter_agent_id = EXCLUDED.reporter_agent_id,
                    target = COALESCE(EXCLUDED.target, vuln_scans.target),
                    tool = EXCLUDED.tool,
                    tool_version = COALESCE(EXCLUDED.tool_version, vuln_scans.tool_version),
                    status = EXCLUDED.status,
                    started_at = LEAST(vuln_scans.started_at, EXCLUDED.started_at),
                    finished_at = COALESCE(EXCLUDED.finished_at, vuln_scans.finished_at),
                    scope = vuln_scans.scope || EXCLUDED.scope,
                    config = vuln_scans.config || EXCLUDED.config,
                    stats = vuln_scans.stats || EXCLUDED.stats,
                    updated_at = now()
                RETURNING id;
                """
            )

            row = db.execute(
                stmt,
                {
                    "scan_uuid": scan_uuid,
                    "reporter_agent_id": agent.agent_id,
                    "target": payload.scan.target,
                    "tool": payload.scan.tool,
                    "tool_version": payload.scan.tool_version,
                    "status": payload.scan.status,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "scope": json.dumps(payload.scan.scope or {}, ensure_ascii=False),
                    "config": json.dumps(payload.scan.config or {}, ensure_ascii=False),
                    "stats": json.dumps(payload.scan.stats or {}, ensure_ascii=False),
                },
            ).first()
            scan_id = int(row[0]) if row and row[0] is not None else None

        if not payload.findings:
            db.commit()
            return VulnIngestResult(scan_id=scan_id, scan_uuid=scan_uuid, received_findings=0, stored_findings=0)

        # Bulk upsert findings (fast path)
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
            # Default convention for local host scanning.
            if asset_key.lower() in {"self", "local"}:
                asset_key = f"agent:{agent.agent_id}"

            last_seen = f.last_seen_at or now
            last_seen = _ensure_utc(last_seen) or now

            rows.append(
                {
                    "scan_id": scan_id,
                    "asset_key": asset_key,
                    "asset_agent_id": f.asset_agent_id,
                    "reporter_agent_id": agent.agent_id,
                    "target": f.target,
                    "asset": json.dumps(f.asset or {}, ensure_ascii=False),
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
                    "tags": json.dumps(f.tags or [], ensure_ascii=False),
                    "evidence": json.dumps(_truncate_evidence(dict(f.evidence or {})), ensure_ascii=False),
                    "last_seen_at": last_seen,
                }
            )

        upsert_sql = text(
            """
            INSERT INTO vuln_findings (
                scan_id, asset_key, asset_agent_id, reporter_agent_id, target, asset,
                source, external_id, fingerprint,
                severity, severity_rank, confidence,
                title, description, remediation,
                cve, cwe, cvss,
                location, tags, evidence,
                status, is_suppressed,
                first_seen_at, last_seen_at, occurrences, updated_at
            )
            VALUES (
                :scan_id, :asset_key, :asset_agent_id, :reporter_agent_id, :target, CAST(:asset AS jsonb),
                :source, :external_id, :fingerprint,
                :severity, :severity_rank, :confidence,
                :title, :description, :remediation,
                :cve, :cwe, :cvss,
                :location, CAST(:tags AS jsonb), CAST(:evidence AS jsonb),
                'open', false,
                now(), :last_seen_at, 1, now()
            )
            ON CONFLICT (asset_key, fingerprint)
            DO UPDATE SET
                scan_id = COALESCE(EXCLUDED.scan_id, vuln_findings.scan_id),
                asset_agent_id = COALESCE(EXCLUDED.asset_agent_id, vuln_findings.asset_agent_id),
                reporter_agent_id = COALESCE(EXCLUDED.reporter_agent_id, vuln_findings.reporter_agent_id),
                target = COALESCE(EXCLUDED.target, vuln_findings.target),
                asset = vuln_findings.asset || EXCLUDED.asset,
                source = EXCLUDED.source,
                external_id = COALESCE(EXCLUDED.external_id, vuln_findings.external_id),
                severity = CASE WHEN EXCLUDED.severity_rank > vuln_findings.severity_rank THEN EXCLUDED.severity ELSE vuln_findings.severity END,
                severity_rank = GREATEST(vuln_findings.severity_rank, EXCLUDED.severity_rank),
                confidence = GREATEST(vuln_findings.confidence, EXCLUDED.confidence),
                title = COALESCE(NULLIF(EXCLUDED.title, ''), vuln_findings.title),
                description = COALESCE(EXCLUDED.description, vuln_findings.description),
                remediation = COALESCE(EXCLUDED.remediation, vuln_findings.remediation),
                cve = COALESCE(EXCLUDED.cve, vuln_findings.cve),
                cwe = COALESCE(EXCLUDED.cwe, vuln_findings.cwe),
                cvss = COALESCE(EXCLUDED.cvss, vuln_findings.cvss),
                location = COALESCE(EXCLUDED.location, vuln_findings.location),
                tags = CASE WHEN jsonb_array_length(EXCLUDED.tags) > 0 THEN EXCLUDED.tags ELSE vuln_findings.tags END,
                evidence = vuln_findings.evidence || EXCLUDED.evidence,
                last_seen_at = GREATEST(vuln_findings.last_seen_at, EXCLUDED.last_seen_at),
                occurrences = vuln_findings.occurrences + 1,
                status = CASE
                    WHEN :auto_reopen = true AND vuln_findings.status IN ('fixed', 'resolved') THEN 'open'
                    ELSE vuln_findings.status
                END,
                updated_at = now();
            """
        )

        db.execute(upsert_sql, [{**r, "auto_reopen": auto_reopen} for r in rows])
        db.commit()

        return VulnIngestResult(
            scan_id=scan_id,
            scan_uuid=scan_uuid,
            received_findings=len(payload.findings),
            stored_findings=len(payload.findings),
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
):
    db = SessionLocal()
    try:
        stmt = select(VulnScanModel).order_by(VulnScanModel.started_at.desc(), VulnScanModel.id.desc())
        if reporter_agent_id:
            stmt = stmt.where(VulnScanModel.reporter_agent_id == reporter_agent_id)
        if status_q:
            stmt = stmt.where(VulnScanModel.status == status_q.lower())

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
        risk_expr = _risk_score_sql()

        cond_sql = """
            vf.status = 'open'
            AND vf.last_seen_at >= :since
            AND (:include_suppressed = true OR vf.is_suppressed = false)
        """

        q_totals = text(
            f"""
            WITH base AS (
              SELECT
                vf.*,
                {risk_expr} AS risk_score
              FROM vuln_findings vf
              WHERE {cond_sql}
            )
            SELECT
              COUNT(*)::bigint AS total_open,
              COUNT(*) FILTER (WHERE severity = 'critical')::bigint AS critical_open,
              COUNT(*) FILTER (WHERE severity = 'high')::bigint AS high_open,
              COUNT(*) FILTER (
                WHERE (
                  (cvss ~ '^[0-9]+(\\.[0-9]+)?$' AND (cvss::double precision) >= 7.0)
                  OR upper(COALESCE(cvss, '')) LIKE '%AV:N%'
                  OR (cve IS NOT NULL AND btrim(cve) <> '' AND severity_rank >= 3)
                )
              )::bigint AS exploitable_open,
              COUNT(*) FILTER (
                WHERE (
                  (evidence -> 'osv' ->> 'fixed') IS NOT NULL
                  OR (remediation IS NOT NULL AND btrim(remediation) <> '')
                )
              )::bigint AS fixable_open,
              COUNT(*) FILTER (WHERE last_seen_at < :stale_before)::bigint AS stale_open,
              COALESCE(AVG(risk_score), 0)::double precision AS mean_risk,
              COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY risk_score), 0)::double precision AS p95_risk
            FROM base;
            """
        )
        totals = (
            db.execute(
                q_totals,
                {
                    "since": since,
                    "stale_before": stale_before,
                    "include_suppressed": include_suppressed,
                },
            )
            .mappings()
            .first()
            or {}
        )

        q_top = text(
            f"""
            SELECT
              vf.id,
              vf.asset_key,
              vf.asset_agent_id,
              vf.target,
              vf.title,
              vf.cve,
              vf.severity,
              vf.confidence,
              vf.occurrences,
              vf.last_seen_at,
              vf.remediation,
              vf.cvss,
              (
                CASE
                  WHEN vf.cvss ~ '^[0-9]+(\\.[0-9]+)?$' THEN vf.cvss::double precision
                  ELSE 0
                END
              )::double precision AS cvss_score,
              (
                (
                  (vf.evidence -> 'osv' ->> 'fixed') IS NOT NULL
                  OR (vf.remediation IS NOT NULL AND btrim(vf.remediation) <> '')
                )
              ) AS has_fix,
              (upper(COALESCE(vf.cvss, '')) LIKE '%AV:N%') AS internet_exposed,
              (
                (vf.cvss ~ '^[0-9]+(\\.[0-9]+)?$' AND (vf.cvss::double precision) >= 7.0)
                OR upper(COALESCE(vf.cvss, '')) LIKE '%AV:N%'
                OR (vf.cve IS NOT NULL AND btrim(vf.cve) <> '' AND vf.severity_rank >= 3)
              ) AS exploit_likely,
              {risk_expr}::double precision AS risk_score
            FROM vuln_findings vf
            WHERE {cond_sql}
            ORDER BY risk_score DESC, vf.last_seen_at DESC, vf.id DESC
            LIMIT :top_n;
            """
        )
        top_rows = db.execute(
            q_top,
            {
                "since": since,
                "include_suppressed": include_suppressed,
                "top_n": int(top_n),
            },
        ).mappings().all()

        q_assets = text(
            f"""
            WITH ranked AS (
              SELECT
                vf.asset_key,
                vf.asset_agent_id,
                vf.severity_rank,
                vf.last_seen_at,
                {risk_expr} AS risk_score
              FROM vuln_findings vf
              WHERE {cond_sql}
            )
            SELECT
              asset_key,
              MAX(asset_agent_id) AS asset_agent_id,
              COUNT(*)::bigint AS open_findings,
              COUNT(*) FILTER (WHERE severity_rank >= 3)::bigint AS critical_high,
              COALESCE(MAX(risk_score), 0)::double precision AS max_risk,
              COALESCE(AVG(risk_score), 0)::double precision AS avg_risk,
              MAX(last_seen_at) AS last_seen_at
            FROM ranked
            GROUP BY asset_key
            ORDER BY max_risk DESC, critical_high DESC, open_findings DESC
            LIMIT 10;
            """
        )
        asset_rows = db.execute(
            q_assets,
            {
                "since": since,
                "include_suppressed": include_suppressed,
            },
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
