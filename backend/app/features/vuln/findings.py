from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.agent_auth import AgentPrincipal
from app.core.config import settings
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.features.vuln.presentation import serialize_finding
from app.features.vuln.models import VulnScanModel
from app.features.vuln.repository import (
    bulk_upsert_findings,
    get_finding_by_id,
    list_findings_page,
    reconcile_resolved_findings,
)
from app.features.vuln.schemas import VulnFindingIn, VulnFindingOut
from app.shared.schemas import CursorPage


SEVERITY_RANK: dict[str, int] = {
    "unknown": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _severity_rank(severity: str) -> int:
    return int(SEVERITY_RANK.get((severity or "").strip().lower(), 0))


def _sha256_hex(value: str) -> str:
    return sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _fingerprint(
    *,
    asset_key: str,
    source: str,
    external_id: str | None,
    cve: str | None,
    title: str,
    location: str | None,
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


def _truncate_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    max_bytes = int(settings.SEAGULL_VULN_MAX_EVIDENCE_BYTES or 32768)
    if max_bytes < 1024:
        max_bytes = 1024

    try:
        raw = json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return {"truncated": True, "reason": "evidence_not_json_serializable"}

    payload = raw.encode("utf-8", errors="ignore")
    if len(payload) <= max_bytes:
        return evidence

    preview = payload[: min(len(payload), 2048)].decode("utf-8", errors="ignore")
    return {
        "truncated": True,
        "original_size_bytes": len(payload),
        "sha256": sha256(payload).hexdigest(),
        "keys": list(evidence.keys())[:50],
        "preview": preview,
    }


def _default_sources_for_tool(tool: str | None) -> list[str]:
    norm = str(tool or "").strip().lower()
    if norm == "osv-wazuh-like":
        return ["osv"]
    return []


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def persist_ingested_findings(
    db: Session,
    *,
    findings: list[VulnFindingIn],
    agent: AgentPrincipal,
    scan_row: VulnScanModel | None,
    now: datetime,
    auto_reopen: bool,
) -> tuple[int, list[int]]:
    rows: list[dict[str, Any]] = []
    observed_fingerprints: list[str] = []
    sources_seen: set[str] = set()

    for finding in findings:
        fingerprint = (finding.fingerprint or "").strip() or _fingerprint(
            asset_key=finding.asset_key,
            source=finding.source,
            external_id=finding.external_id,
            cve=finding.cve,
            title=finding.title,
            location=finding.location,
        )
        severity = (finding.severity or "unknown").strip().lower() or "unknown"
        asset_key = finding.asset_key.strip()
        if asset_key.lower() in {"self", "local"}:
            asset_key = f"agent:{agent.agent_id}"

        last_seen = _ensure_utc(finding.last_seen_at or now) or now
        sources_seen.add(finding.source)
        observed_fingerprints.append(fingerprint)
        rows.append(
            {
                "scan_id": scan_row.id if scan_row is not None else None,
                "asset_key": asset_key,
                "asset_agent_id": finding.asset_agent_id,
                "reporter_agent_id": agent.agent_id,
                "target": finding.target,
                "asset": dict(finding.asset or {}),
                "source": finding.source,
                "external_id": finding.external_id,
                "fingerprint": fingerprint,
                "severity": severity,
                "severity_rank": _severity_rank(severity),
                "confidence": int(finding.confidence or 0),
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation,
                "cve": finding.cve,
                "cwe": finding.cwe,
                "cvss": finding.cvss,
                "location": finding.location,
                "tags": list(finding.tags or []),
                "evidence": _truncate_evidence(dict(finding.evidence or {})),
                "last_seen_at": last_seen,
                "status": "open",
                "is_suppressed": False,
                "observation_state": "observed",
                "operator_disposition": "open",
                "first_seen_at": now,
                "occurrences": 1,
                "updated_at": now,
            }
        )

    changed_ids: list[int] = []
    if rows:
        changed_ids.extend(bulk_upsert_findings(db, rows=rows, auto_reopen=auto_reopen, now=now))

    if scan_row is not None and scan_row.lifecycle_state == "completed":
        sources = sorted(sources_seen) or _default_sources_for_tool(scan_row.tool)
        if sources:
            changed_ids.extend(
                reconcile_resolved_findings(
                    db,
                    reporter_agent_id=agent.agent_id,
                    observed_fingerprints=observed_fingerprints,
                    sources=sources,
                    now=now,
                )
            )

    deduped_ids: list[int] = []
    seen_ids: set[int] = set()
    for finding_id in changed_ids:
        if finding_id in seen_ids:
            continue
        seen_ids.add(finding_id)
        deduped_ids.append(finding_id)

    return len(rows), deduped_ids


def list_findings(
    db: Session,
    *,
    page_size: int,
    cursor: str | None,
    asset_agent_id: str | None,
    reporter_agent_id: str | None,
    status_q: str | None,
    observation_state_q: str | None,
    operator_disposition_q: str | None,
    min_severity: str | None = None,
    min_severity_rank: int | None = None,
    cve: str | None,
    q: str | None,
    include_suppressed: bool,
) -> CursorPage[VulnFindingOut]:
    effective_min_severity_rank = min_severity_rank
    if effective_min_severity_rank is None and min_severity is not None:
        effective_min_severity_rank = _severity_rank(min_severity)

    cursor_parsed = parse_cursor_ts_id(cursor) if cursor else None
    rows = list_findings_page(
        db,
        page_size=page_size,
        cursor_parsed=cursor_parsed,
        asset_agent_id=asset_agent_id,
        reporter_agent_id=reporter_agent_id,
        status_q=status_q,
        observation_state_q=observation_state_q,
        operator_disposition_q=operator_disposition_q,
        include_suppressed=include_suppressed,
        min_severity_rank=effective_min_severity_rank,
        cve=cve,
        query_text=q,
    )
    has_more = len(rows) > page_size
    page_rows = rows[:page_size]
    items = [VulnFindingOut(**serialize_finding(row)) for row in page_rows]
    next_cursor = make_cursor_ts_id(page_rows[-1].last_seen_at, page_rows[-1].id) if has_more and page_rows else None
    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


def get_finding(db: Session, *, finding_id: int):
    row = get_finding_by_id(db, finding_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return VulnFindingOut(**serialize_finding(row))
