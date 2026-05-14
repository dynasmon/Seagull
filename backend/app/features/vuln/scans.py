from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.api.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.config import settings
from app.features.agents.auth import AgentPrincipal
from app.features.realtime.service import publish_realtime
from app.features.vuln.domain import (
    lifecycle_state_for_phase,
    normalize_scan_lifecycle_state,
    normalize_scan_phase,
    normalize_trigger_source,
    scan_lifecycle_event,
)
from app.features.vuln.findings import persist_ingested_findings
from app.features.vuln.models import VulnScanModel
from app.features.vuln.presentation import serialize_finding, serialize_scan
from app.features.vuln.repository import (
    add_agent,
    add_vuln_scan,
    commit,
    get_agent_by_agent_id,
    get_findings_by_ids,
    get_latest_live_manual_scan_for_agent,
    get_scan_by_uuid,
    list_scans_page,
    upsert_scan_metadata,
)
from app.features.vuln.schemas import (
    VulnIngestBatch,
    VulnIngestResult,
    VulnManualScanIn,
    VulnManualScanOut,
    VulnScanOut,
)
from app.shared.schemas import CursorPage


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _env_int(name: str, default: int) -> int:
    raw = getattr(settings, name, None)
    if raw is None:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _request_token_from_scan(scan_row: VulnScanModel | None) -> str | None:
    if scan_row is None:
        return None
    if getattr(scan_row, "request_token", None):
        return str(scan_row.request_token).strip() or None
    scope = getattr(scan_row, "scope", None) or {}
    if isinstance(scope, dict):
        for key in ("request_token", "trigger_token"):
            value = str(scope.get(key) or "").strip()
            if value:
                return value
    return None


def _build_scan_lifecycle_payload(*, lifecycle_event: str, scan_row: "VulnScanModel", agent_id: str) -> dict:
    return {
        "lifecycle_event": lifecycle_event,
        "scan_uuid": scan_row.scan_uuid,
        "agent_id": str(agent_id or "").strip(),
        "scan": serialize_scan(scan_row),
    }


def _normalize_cfg_map(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _publish_finding_patch_batch(
    *,
    finding_rows: list[Any],
    agent_id: str,
    reason: str,
    scan_uuid: str | None = None,
) -> bool:
    if not finding_rows:
        return False
    try:
        publish_realtime(
            "ui.vulnerabilities.finding.patch",
            {
                "reason": reason,
                "agent_id": str(agent_id or "").strip() or None,
                "scan_uuid": scan_uuid,
                "findings": [serialize_finding(row) for row in finding_rows],
                "requires_reconcile": False,
            },
        )
        return True
    except Exception:
        return False


def _clear_agent_scan_token(db: Session, *, agent_id: str, scan_uuid: str) -> None:
    agent_row = get_agent_by_agent_id(db, agent_id)
    if agent_row is None:
        return
    cfg = _normalize_cfg_map(agent_row.config)
    modules = _normalize_cfg_map(cfg.get("modules"))
    vuln_cfg = _normalize_cfg_map(modules.get("vulnscanner"))
    stored_token = str(vuln_cfg.get("scan_now_token") or "").strip()
    if stored_token != scan_uuid:
        return
    vuln_cfg["scan_now_token"] = ""
    modules["vulnscanner"] = vuln_cfg
    cfg["modules"] = modules
    agent_row.config = cfg
    add_agent(db, agent_row)


def ingest_findings(db: Session, *, payload: VulnIngestBatch, agent: AgentPrincipal) -> VulnIngestResult:
    max_findings = max(1, _env_int("SEAGULL_VULN_MAX_FINDINGS_PER_INGEST", 2000))
    if len(payload.findings) > max_findings:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Too many findings in a single ingest (max {max_findings})",
        )

    now = _utc_now()
    scan_uuid: str | None = None
    scan_row: VulnScanModel | None = None
    previous_lifecycle_state: str | None = None
    previous_phase: str | None = None

    if payload.scan is not None:
        scan_uuid = (payload.scan.scan_uuid or "").strip() or str(uuid.uuid4())
        existing_scan = get_scan_by_uuid(db, scan_uuid)
        if existing_scan is not None:
            previous_lifecycle_state = existing_scan.lifecycle_state
            previous_phase = existing_scan.current_phase
        manual_trigger = bool(
            (payload.scan.scope or {}).get("manual_trigger")
            or (payload.scan.config or {}).get("manual_trigger")
        )
        lifecycle_state = normalize_scan_lifecycle_state(
            payload.scan.lifecycle_state
            or payload.scan.status
            or lifecycle_state_for_phase(payload.scan.current_phase)
        )
        current_phase = normalize_scan_phase(payload.scan.current_phase, fallback_state=lifecycle_state)
        trigger_source = normalize_trigger_source(payload.scan.trigger_source, manual_trigger=manual_trigger)
        scan_row = upsert_scan_metadata(
            db,
            scan_uuid=scan_uuid,
            reporter_agent_id=agent.agent_id,
            target=payload.scan.target,
            tool=payload.scan.tool,
            tool_version=payload.scan.tool_version,
            status=payload.scan.status,
            lifecycle_state=lifecycle_state,
            current_phase=current_phase,
            queued_at=_ensure_utc(payload.scan.queued_at) or _ensure_utc(payload.scan.started_at) or now,
            acknowledged_at=_ensure_utc(payload.scan.acknowledged_at),
            started_at=_ensure_utc(payload.scan.started_at),
            finished_at=_ensure_utc(payload.scan.finished_at),
            last_progress_at=_ensure_utc(payload.scan.last_progress_at),
            trigger_source=trigger_source,
            error_summary=payload.scan.error_summary,
            scope=dict(payload.scan.scope or {}),
            config=dict(payload.scan.config or {}),
            stats=dict(payload.scan.stats or {}),
            phase_timestamps=dict(payload.scan.phase_timestamps or {}),
            now=now,
        )
        if scan_row.lifecycle_state in {"completed", "failed", "cancelled"}:
            _clear_agent_scan_token(db, agent_id=agent.agent_id, scan_uuid=scan_uuid)

    stored_findings, changed_finding_ids = persist_ingested_findings(
        db,
        findings=list(payload.findings or []),
        agent=agent,
        scan_row=scan_row,
        now=now,
    )
    commit(db)

    try:
        if scan_row is not None:
            lc_event = scan_lifecycle_event(
                previous_lifecycle_state,
                previous_phase,
                scan_row.lifecycle_state,
                scan_row.current_phase,
            )
            publish_realtime(
                "ui.vulnerabilities.scan.lifecycle",
                _build_scan_lifecycle_payload(
                    lifecycle_event=lc_event,
                    scan_row=scan_row,
                    agent_id=str(agent.agent_id or "").strip(),
                ),
            )
        if changed_finding_ids:
            finding_rows = get_findings_by_ids(db, changed_finding_ids[:50])
            published_patch = _publish_finding_patch_batch(
                finding_rows=finding_rows,
                agent_id=str(agent.agent_id or "").strip(),
                reason="findings_reconciled",
                scan_uuid=scan_uuid,
            )
            if (not published_patch) or len(changed_finding_ids) > 50:
                publish_realtime(
                    "ui.vulnerabilities.invalidate",
                    {
                        "reason": "findings_ingested",
                        "scope": "vulnerabilities",
                        "agent_id": str(agent.agent_id or "").strip(),
                        "scan_uuid": scan_uuid,
                        "status": scan_row.lifecycle_state if scan_row is not None else None,
                        "phase": scan_row.current_phase if scan_row is not None else None,
                    },
                )
    except Exception:
        pass

    return VulnIngestResult(
        scan_id=scan_row.id if scan_row is not None else None,
        scan_uuid=scan_uuid,
        lifecycle_state=scan_row.lifecycle_state if scan_row is not None else None,
        current_phase=scan_row.current_phase if scan_row is not None else None,
        received_findings=len(payload.findings),
        stored_findings=stored_findings,
    )


def trigger_manual_scan(db: Session, *, body: VulnManualScanIn) -> VulnManualScanOut:
    row = get_agent_by_agent_id(db, body.agent_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    if row.is_revoked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is revoked")

    existing_scan = get_latest_live_manual_scan_for_agent(db, body.agent_id)
    if existing_scan is not None:
        scan_uuid_existing = str(existing_scan.scan_uuid)
        request_token = _request_token_from_scan(existing_scan) or scan_uuid_existing

        # Re-assert the token in agent config so the agent picks it up even if it
        # restarted after the original trigger (lastTriggerToken resets to "" on restart).
        now = _utc_now()
        cfg = _normalize_cfg_map(row.config)
        modules = _normalize_cfg_map(cfg.get("modules"))
        vuln_cfg = _normalize_cfg_map(modules.get("vulnscanner"))
        if str(vuln_cfg.get("scan_now_token") or "").strip() != scan_uuid_existing:
            vuln_cfg["enabled"] = True
            vuln_cfg["scan_now_token"] = scan_uuid_existing
            vuln_cfg["scan_now_at"] = now.isoformat()
            modules["vulnscanner"] = vuln_cfg
            cfg["modules"] = modules
            row.config = cfg
            add_agent(db, row)
            commit(db)

        return VulnManualScanOut(
            agent_id=body.agent_id,
            request_token=request_token,
            trigger_token=request_token,
            scan_uuid=scan_uuid_existing,
            request_state="existing",
            status=existing_scan.lifecycle_state,
            lifecycle_state=existing_scan.lifecycle_state,
            current_phase=existing_scan.current_phase,
            queued_at=_ensure_utc(existing_scan.queued_at) or _utc_now(),
            scan=VulnScanOut(**serialize_scan(existing_scan)),
        )

    now = _utc_now()
    request_token = str(uuid.uuid4())
    scan_uuid = str(uuid.uuid4())

    cfg = _normalize_cfg_map(row.config)
    modules = _normalize_cfg_map(cfg.get("modules"))
    vuln_cfg = _normalize_cfg_map(modules.get("vulnscanner"))

    vuln_cfg["enabled"] = True
    vuln_cfg["scan_now_token"] = scan_uuid
    vuln_cfg["scan_now_at"] = now.isoformat()

    modules["vulnscanner"] = vuln_cfg
    cfg["modules"] = modules
    row.config = cfg

    queued_scan = VulnScanModel(
        scan_uuid=scan_uuid,
        request_token=request_token,
        reporter_agent_id=body.agent_id,
        target=f"agent:{body.agent_id}",
        tool="osv-wazuh-like",
        tool_version="1",
        status="queued",
        lifecycle_state="queued",
        current_phase="queued",
        queued_at=now,
        acknowledged_at=None,
        started_at=None,
        finished_at=None,
        last_progress_at=now,
        trigger_source="manual",
        error_summary=None,
        scope={"type": "manual_trigger", "manual_trigger": True, "request_token": request_token},
        config={
            "manual_trigger": True,
            "analysis_profile": str(vuln_cfg.get("analysis_profile") or "wazuh_like_v1"),
        },
        stats={},
        phase_timestamps={"queued": now.isoformat()},
        created_at=now,
        updated_at=now,
    )
    add_vuln_scan(db, queued_scan)
    add_agent(db, row)
    commit(db)

    try:
        publish_realtime(
            "ui.vulnerabilities.scan.lifecycle",
            _build_scan_lifecycle_payload(
                lifecycle_event="queued",
                scan_row=queued_scan,
                agent_id=str(body.agent_id or "").strip(),
            ),
        )
        publish_realtime(
            "ui.vulnerabilities.invalidate",
            {
                "reason": "manual_scan_queued",
                "scope": "vulnerabilities",
                "agent_id": str(body.agent_id or "").strip(),
                "scan_uuid": scan_uuid,
                "status": "queued",
                "phase": "queued",
            },
        )
    except Exception:
        pass

    return VulnManualScanOut(
        agent_id=body.agent_id,
        request_token=request_token,
        trigger_token=request_token,
        scan_uuid=scan_uuid,
        request_state="created",
        status="queued",
        lifecycle_state="queued",
        current_phase="queued",
        queued_at=now,
        scan=VulnScanOut(**serialize_scan(queued_scan)),
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
    next_cursor = make_cursor_ts_id(items[-1].queued_at, items[-1].id) if has_more and items else None
    return CursorPage(items=[VulnScanOut(**serialize_scan(row)) for row in items], next_cursor=next_cursor, has_more=has_more)
