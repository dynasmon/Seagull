from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Dict, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.agent_auth import AgentPrincipal
from app.core.config import settings
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.features.vuln.models import VulnScanModel
from app.features.realtime.service import publish_realtime
from app.features.vuln.repository import (
    add_agent,
    add_vuln_scan,
    apply_finding_patch,
    bulk_upsert_findings,
    commit,
    get_agent_by_agent_id,
    get_finding_by_id,
    list_findings_page,
    list_scans_page,
    posture_data,
    refresh,
    summary_counts,
    upsert_scan_metadata,
)
from app.features.vuln.schemas import (
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
from app.shared.schemas import CursorPage


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


def _normalize_cfg_map(v: Any) -> Dict[str, Any]:
    if isinstance(v, dict):
        return dict(v)
    return {}


def ingest_findings(db: Session, *, payload: VulnIngestBatch, agent: AgentPrincipal) -> VulnIngestResult:
    max_findings = max(1, _env_int("NETWATCH_VULN_MAX_FINDINGS_PER_INGEST", 2000))
    if len(payload.findings) > max_findings:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Too many findings in a single ingest (max {max_findings})",
        )

    scan_uuid: Optional[str] = None
    scan_id: Optional[int] = None
    now = _utc_now()
    auto_reopen = _env_bool("NETWATCH_VULN_AUTO_REOPEN", True)

    if payload.scan is not None:
        scan_uuid = (payload.scan.scan_uuid or "").strip() or str(uuid.uuid4())
        started_at = _ensure_utc(payload.scan.started_at) or now
        finished_at = _ensure_utc(payload.scan.finished_at)
        scan_id = upsert_scan_metadata(
            db,
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
            now=now,
        )

    if not payload.findings:
        commit(db)
        return VulnIngestResult(scan_id=scan_id, scan_uuid=scan_uuid, received_findings=0, stored_findings=0)

    rows: list[dict[str, Any]] = []
    for f in payload.findings:
        fp = (f.fingerprint or "").strip() or _fingerprint(
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

    bulk_upsert_findings(db, rows=rows, auto_reopen=auto_reopen, now=now)
    commit(db)

    try:
        publish_realtime(
            "ui.vulnerabilities.invalidate",
            {
                "reason": "findings_ingested",
                "scope": "vulnerabilities",
                "agent_id": str(agent.agent_id or "").strip(),
                "scan_uuid": scan_uuid,
                "status": str(payload.scan.status) if payload.scan is not None and payload.scan.status else None,
            },
        )
    except Exception:
        pass

    return VulnIngestResult(
        scan_id=scan_id,
        scan_uuid=scan_uuid,
        received_findings=len(payload.findings),
        stored_findings=len(payload.findings),
    )


def trigger_manual_scan(db: Session, *, body: VulnManualScanIn) -> VulnManualScanOut:
    row = get_agent_by_agent_id(db, body.agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    if row.is_revoked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")

    now = _utc_now()
    token = str(uuid.uuid4())

    cfg = _normalize_cfg_map(row.config)
    modules = _normalize_cfg_map(cfg.get("modules"))
    vcfg = _normalize_cfg_map(modules.get("vulnscanner"))

    if "enabled" not in vcfg:
        vcfg["enabled"] = True
    vcfg["scan_now_token"] = token
    vcfg["scan_now_at"] = now.isoformat()

    modules["vulnscanner"] = vcfg
    cfg["modules"] = modules
    row.config = cfg

    qscan = VulnScanModel(
        scan_uuid=token,
        reporter_agent_id=body.agent_id,
        target=f"agent:{body.agent_id}",
        tool="osv-wazuh-like",
        tool_version="1",
        status="queued",
        started_at=now,
        finished_at=None,
        scope={"type": "manual_trigger", "manual_trigger": True, "trigger_token": token},
        config={
            "manual_trigger": True,
            "analysis_profile": str(vcfg.get("analysis_profile") or "wazuh_like_v1"),
        },
        stats={},
        updated_at=now,
    )
    add_vuln_scan(db, qscan)
    add_agent(db, row)
    commit(db)

    try:
        publish_realtime(
            "ui.vulnerabilities.invalidate",
            {
                "reason": "manual_scan_queued",
                "scope": "vulnerabilities",
                "agent_id": str(body.agent_id or "").strip(),
                "scan_uuid": token,
                "status": "queued",
            },
        )
    except Exception:
        pass

    return VulnManualScanOut(
        agent_id=body.agent_id,
        trigger_token=token,
        scan_uuid=token,
        status="queued",
        queued_at=now,
    )


def list_scans(
    db: Session,
    *,
    page_size: int,
    cursor: str | None,
    reporter_agent_id: str | None,
    status_q: str | None,
    tool: str | None,
) -> CursorPage[VulnScanOut]:
    cursor_parsed = parse_cursor_ts_id(cursor) if cursor else None
    rows = list_scans_page(
        db,
        page_size=page_size,
        cursor_parsed=cursor_parsed,
        reporter_agent_id=reporter_agent_id,
        status_q=status_q,
        tool=tool,
    )
    has_more = len(rows) > page_size
    items = rows[:page_size]
    next_cursor = make_cursor_ts_id(items[-1].started_at, items[-1].id) if has_more and items else None
    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


def list_findings(
    db: Session,
    *,
    page_size: int,
    cursor: str | None,
    asset_agent_id: str | None,
    reporter_agent_id: str | None,
    status_q: str | None,
    min_severity: str | None,
    cve: str | None,
    q: str | None,
    include_suppressed: bool,
) -> CursorPage[VulnFindingOut]:
    cursor_parsed = parse_cursor_ts_id(cursor) if cursor else None
    min_severity_rank = _severity_rank(min_severity) if min_severity else None
    rows = list_findings_page(
        db,
        page_size=page_size,
        cursor_parsed=cursor_parsed,
        asset_agent_id=asset_agent_id,
        reporter_agent_id=reporter_agent_id,
        status_q=status_q,
        include_suppressed=include_suppressed,
        min_severity_rank=min_severity_rank,
        cve=cve,
        query_text=q,
    )
    has_more = len(rows) > page_size
    items = rows[:page_size]
    next_cursor = make_cursor_ts_id(items[-1].last_seen_at, items[-1].id) if has_more and items else None
    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


def get_finding(db: Session, *, finding_id: int):
    row = get_finding_by_id(db, finding_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return row


def patch_finding(db: Session, *, finding_id: int, patch: VulnFindingPatchIn):
    row = get_finding_by_id(db, finding_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    apply_finding_patch(
        db,
        row=row,
        status=patch.status,
        is_suppressed=patch.is_suppressed,
        updated_at=_utc_now(),
    )
    commit(db)
    refresh(db, row)
    try:
        publish_realtime(
            "ui.vulnerabilities.invalidate",
            {
                "reason": "finding_updated",
                "scope": "vulnerabilities",
                "agent_id": str(row.asset_agent_id or row.reporter_agent_id or "").strip() or None,
                "status": str(row.status or "").strip() or None,
            },
        )
    except Exception:
        pass
    return row


def summary(db: Session, *, active_within_days: int, include_suppressed: bool) -> VulnSummaryOut:
    now = _utc_now()
    since = now - timedelta(days=int(active_within_days))
    total_open, total_suppressed, by_severity, by_status = summary_counts(
        db,
        since=since,
        include_suppressed=include_suppressed,
    )
    return VulnSummaryOut(
        generated_at=now,
        total_open=total_open,
        total_suppressed=total_suppressed,
        by_severity=by_severity,
        by_status=by_status,
    )


def posture(
    db: Session,
    *,
    active_within_days: int,
    include_suppressed: bool,
    top_n: int,
) -> VulnPostureOut:
    now = _utc_now()
    since = now - timedelta(days=int(active_within_days))

    totals, top_rows, asset_rows = posture_data(
        db,
        now=now,
        since=since,
        include_suppressed=include_suppressed,
        top_n=top_n,
    )

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
        top_risks=[VulnRiskItemOut(**r) for r in top_rows],
        top_assets=[VulnAssetRiskOut(**r) for r in asset_rows],
    )
