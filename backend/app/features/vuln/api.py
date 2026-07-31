from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.orm import Session

from app.core.api.conditional import maybe_not_modified
from app.core.api.idempotency import read_batch_id, request_fingerprint, run_once
from app.core.db import get_db, routed_db
from app.core.observability import incr_counter
from app.features.agents.auth import AgentPrincipal, get_current_agent
from app.features.auth.session import require_admin
from app.features.vuln.overview import (
    VULN_DEFAULT_ACTIVE_WITHIN_DAYS,
    VULN_DEFAULT_INCLUDE_SUPPRESSED,
    VULN_POSTURE_DEFAULT_TOP_N,
)
from app.features.vuln.schemas import (
    VulnFindingOut,
    VulnFindingPatchIn,
    VulnIngestBatch,
    VulnIngestResult,
    VulnManualScanIn,
    VulnManualScanOut,
    VulnPostureOut,
    VulnScanOut,
    VulnSummaryOut,
)
from app.features.vuln.service import (
    get_finding,
    get_vuln_posture_async,
    get_vuln_summary_async,
    ingest_findings,
    list_findings,
    list_scans,
    patch_finding,
    trigger_manual_scan,
)
from app.shared.schemas import CursorPage

router = APIRouter(
    prefix="/vuln",
    tags=["vuln"],
)


@router.post(
    "/ingest",
    response_model=VulnIngestResult,
    status_code=status.HTTP_201_CREATED,
)
def ingest_findings_endpoint(
    payload: VulnIngestBatch,
    request: Request,
    agent: AgentPrincipal = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    return run_once(
        scope="ingest_vuln",
        agent_id=agent.agent_id,
        batch_id=read_batch_id(request),
        handler=lambda: ingest_findings(db, payload=payload, agent=agent),
        request_digest=request_fingerprint(payload),
    )


@router.post(
    "/scan-now",
    response_model=VulnManualScanOut,
    dependencies=[Depends(require_admin)],
)
def trigger_manual_scan_endpoint(
    body: VulnManualScanIn,
    db: Session = Depends(get_db),
):
    return trigger_manual_scan(db, body=body)


@router.get(
    "/scans",
    response_model=CursorPage[VulnScanOut],
    dependencies=[Depends(require_admin)],
)
def list_scans_endpoint(
    page_size: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
    reporter_agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    status_q: Optional[str] = Query(None, min_length=1, max_length=32),
    tool: Optional[str] = Query(None, min_length=1, max_length=64),
    db: Session = Depends(routed_db("vuln-read")),
):
    return list_scans(
        db,
        page_size=page_size,
        cursor=cursor,
        reporter_agent_id=reporter_agent_id,
        status_q=status_q,
        tool=tool,
    )


@router.get(
    "/findings",
    response_model=CursorPage[VulnFindingOut],
    dependencies=[Depends(require_admin)],
)
def list_findings_endpoint(
    page_size: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
    asset_agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    reporter_agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    status_q: Optional[str] = Query(None, min_length=1, max_length=24),
    observation_state: Optional[str] = Query(None, min_length=1, max_length=32),
    disposition: Optional[str] = Query(None, min_length=1, max_length=32),
    min_severity: Optional[str] = Query(None, min_length=1, max_length=16),
    cve: Optional[str] = Query(None, min_length=1, max_length=32),
    q: Optional[str] = Query(None, min_length=1, max_length=128, description="Search (title/target/cve/external_id)"),
    include_suppressed: bool = Query(False),
    db: Session = Depends(routed_db("vuln-read")),
):
    return list_findings(
        db,
        page_size=page_size,
        cursor=cursor,
        asset_agent_id=asset_agent_id,
        reporter_agent_id=reporter_agent_id,
        status_q=status_q,
        observation_state_q=observation_state,
        operator_disposition_q=disposition,
        min_severity=min_severity,
        cve=cve,
        q=q,
        include_suppressed=include_suppressed,
    )


@router.get(
    "/findings/{finding_id}",
    response_model=VulnFindingOut,
    dependencies=[Depends(require_admin)],
)
def get_finding_endpoint(
    finding_id: int,
    db: Session = Depends(get_db),
):
    return get_finding(db, finding_id=finding_id)


@router.patch(
    "/findings/{finding_id}",
    response_model=VulnFindingOut,
    dependencies=[Depends(require_admin)],
)
def patch_finding_endpoint(
    finding_id: int,
    patch: VulnFindingPatchIn,
    db: Session = Depends(get_db),
):
    return patch_finding(db, finding_id=finding_id, patch=patch)


@router.get(
    "/summary",
    response_model=VulnSummaryOut,
    dependencies=[Depends(require_admin)],
)
async def summary_endpoint(
    request: Request,
    response: Response,
    active_within_days: int = Query(VULN_DEFAULT_ACTIVE_WITHIN_DAYS, ge=1, le=365),
    include_suppressed: bool = Query(VULN_DEFAULT_INCLUDE_SUPPRESSED),
):
    payload, etag, outcome = await get_vuln_summary_async(
        active_within_days=active_within_days,
        include_suppressed=include_suppressed,
    )
    response.headers["X-Cache-Outcome"] = outcome
    incr_counter("api_cache_outcome_total", route="/vuln/summary", outcome=outcome)
    not_modified = maybe_not_modified(response, request.headers.get("If-None-Match"), etag, outcome=outcome)
    if not_modified is not None:
        incr_counter("api_304_total", route="/vuln/summary")
        return not_modified
    return payload


@router.get(
    "/posture",
    response_model=VulnPostureOut,
    dependencies=[Depends(require_admin)],
)
async def posture_endpoint(
    request: Request,
    response: Response,
    active_within_days: int = Query(VULN_DEFAULT_ACTIVE_WITHIN_DAYS, ge=1, le=365),
    include_suppressed: bool = Query(VULN_DEFAULT_INCLUDE_SUPPRESSED),
    top_n: int = Query(VULN_POSTURE_DEFAULT_TOP_N, ge=5, le=50),
):
    payload, etag, outcome = await get_vuln_posture_async(
        active_within_days=active_within_days,
        include_suppressed=include_suppressed,
        top_n=top_n,
    )
    response.headers["X-Cache-Outcome"] = outcome
    incr_counter("api_cache_outcome_total", route="/vuln/posture", outcome=outcome)
    not_modified = maybe_not_modified(response, request.headers.get("If-None-Match"), etag, outcome=outcome)
    if not_modified is not None:
        incr_counter("api_304_total", route="/vuln/posture")
        return not_modified
    return payload
