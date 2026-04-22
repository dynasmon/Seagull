from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.features.realtime.service import publish_realtime
from app.features.vuln.domain import normalize_finding_observation_state, normalize_finding_operator_disposition
from app.features.vuln.presentation import serialize_finding
from app.features.vuln.repository import apply_finding_patch, commit, get_finding_by_id, refresh
from app.features.vuln.schemas import VulnFindingPatchIn


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _resolve_patch_states(current_observation_state: str, current_operator_disposition: str, patch: VulnFindingPatchIn) -> tuple[str, str]:
    next_observation_state = current_observation_state
    next_operator_disposition = current_operator_disposition

    legacy_status = str(patch.status or "").strip().lower()
    if legacy_status in {"open", "observed", "active"}:
        next_observation_state = "observed"
    elif legacy_status in {"fixed", "awaiting_verification"}:
        next_observation_state = "awaiting_verification"
    elif legacy_status in {"resolved", "closed"}:
        next_observation_state = "resolved"
    elif legacy_status in {"ignored", "suppressed"}:
        next_operator_disposition = "suppressed"
    elif legacy_status in {"accepted", "accepted_risk"}:
        next_operator_disposition = "accepted_risk"

    if patch.is_suppressed is True:
        next_operator_disposition = "suppressed"
    elif patch.is_suppressed is False and current_operator_disposition == "suppressed":
        next_operator_disposition = "open"

    if patch.operator_disposition is not None:
        next_operator_disposition = normalize_finding_operator_disposition(
            patch.operator_disposition,
            is_suppressed=patch.operator_disposition == "suppressed",
        )
    if patch.observation_state is not None:
        next_observation_state = normalize_finding_observation_state(patch.observation_state)

    return next_observation_state, next_operator_disposition


def patch_finding(db: Session, *, finding_id: int, patch: VulnFindingPatchIn):
    row = get_finding_by_id(db, finding_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    next_observation_state, next_operator_disposition = _resolve_patch_states(
        row.observation_state,
        row.operator_disposition,
        patch,
    )
    apply_finding_patch(
        db,
        row=row,
        observation_state=next_observation_state,
        operator_disposition=next_operator_disposition,
        updated_at=_utc_now(),
    )
    commit(db)
    refresh(db, row)
    try:
        publish_realtime(
            "ui.vulnerabilities.finding.patch",
            {
                "reason": "finding_updated",
                "agent_id": str(row.asset_agent_id or row.reporter_agent_id or "").strip() or None,
                "findings": [serialize_finding(row)],
                "requires_reconcile": False,
            },
        )
    except Exception:
        pass
    return row
