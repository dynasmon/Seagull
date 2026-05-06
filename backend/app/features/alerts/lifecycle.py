from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

_VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"acknowledged", "investigating", "closed"}),
    "acknowledged": frozenset({"investigating", "closed", "open"}),
    "investigating": frozenset({"closed", "open"}),
    "closed": frozenset({"open"}),
}

VALID_STATUSES = frozenset(_VALID_TRANSITIONS.keys())
VALID_DISPOSITIONS = frozenset({
    "true_positive",
    "false_positive",
    "benign",
    "duplicate",
    "expected_activity",
    "unknown",
})


class InvalidTransitionError(ValueError):
    pass


class MissingDispositionError(ValueError):
    pass


def check_transition(current: str, next_status: str) -> None:
    allowed = _VALID_TRANSITIONS.get(current, frozenset())
    if next_status not in allowed:
        raise InvalidTransitionError(
            f"Cannot transition alert from '{current}' to '{next_status}'"
        )


def apply_triage(
    row: Any,
    *,
    fields_set: set[str],
    status: Optional[str],
    disposition: Optional[str],
    priority: Optional[int],
    assigned_to: Optional[str],
    triage_notes: Optional[str],
    risk_score: Optional[int],
    investigation_id: Optional[int],
    actor_username: Optional[str],
    now: datetime,
) -> None:
    current_status = str(row.status or "open")

    if status is not None and status != current_status:
        check_transition(current_status, status)

        if status == "closed":
            eff_disposition = disposition or row.disposition
            if not eff_disposition:
                raise MissingDispositionError("A disposition is required to close an alert")
            row.disposition = eff_disposition
            row.closed_at = now
            row.closed_by = actor_username

        elif status == "acknowledged":
            if not row.acknowledged_at:
                row.acknowledged_at = now
                row.acknowledged_by = actor_username

        elif status == "open":
            row.closed_at = None
            row.closed_by = None

        row.status = status

    if "disposition" in fields_set and disposition is not None:
        row.disposition = disposition

    if "priority" in fields_set and priority is not None:
        if not 1 <= priority <= 4:
            raise ValueError("priority must be between 1 and 4")
        row.priority = priority

    if "assigned_to" in fields_set:
        row.assigned_to = assigned_to

    if "triage_notes" in fields_set:
        row.triage_notes = triage_notes

    if "risk_score" in fields_set and risk_score is not None:
        if not 0 <= risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        row.risk_score = risk_score

    if "investigation_id" in fields_set:
        row.investigation_id = investigation_id
