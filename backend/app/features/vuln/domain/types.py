from __future__ import annotations

from typing import Iterable


SCAN_LIFECYCLE_STATES: tuple[str, ...] = (
    "queued",
    "acknowledged",
    "running",
    "completed",
    "failed",
    "cancelled",
)

SCAN_PHASES: tuple[str, ...] = (
    "queued",
    "acknowledged",
    "running",
    "collecting_inventory",
    "analyzing_exposure",
    "querying_source",
    "normalizing_findings",
    "ingesting_results",
    "completed",
    "failed",
    "cancelled",
)

SCAN_TERMINAL_STATES = {"completed", "failed", "cancelled"}

LEGACY_FINDING_STATUSES: tuple[str, ...] = (
    "open",
    "fixed",
    "resolved",
    "ignored",
    "accepted",
)

FINDING_OBSERVATION_STATES: tuple[str, ...] = (
    "observed",
    "awaiting_verification",
    "resolved",
)

FINDING_OPERATOR_DISPOSITIONS: tuple[str, ...] = (
    "open",
    "accepted_risk",
    "suppressed",
)

_SCAN_LIFECYCLE_ALIASES = {
    "done": "completed",
    "finished": "completed",
    "success": "completed",
    "started": "running",
    "error": "failed",
}

_SCAN_PHASE_ALIASES = {
    "done": "completed",
    "finished": "completed",
    "success": "completed",
    "started": "running",
    "inventory": "collecting_inventory",
    "collect_inventory": "collecting_inventory",
    "collecting": "collecting_inventory",
    "analysis": "analyzing_exposure",
    "exposure": "analyzing_exposure",
    "querying": "querying_source",
    "query": "querying_source",
    "normalize": "normalizing_findings",
    "normalizing": "normalizing_findings",
    "ingesting": "ingesting_results",
    "publish_results": "ingesting_results",
    "error": "failed",
}

_FINDING_OBSERVATION_ALIASES = {
    "open": "observed",
    "active": "observed",
    "fixed": "awaiting_verification",
    "pending_verification": "awaiting_verification",
    "verified": "resolved",
    "closed": "resolved",
}

_FINDING_DISPOSITION_ALIASES = {
    "accepted": "accepted_risk",
    "accepted-risk": "accepted_risk",
    "acceptedrisk": "accepted_risk",
    "ignore": "suppressed",
    "ignored": "suppressed",
}

_LEGACY_FINDING_STATUS_ALIASES = {
    "open": "open",
    "observed": "open",
    "active": "open",
    "fixed": "fixed",
    "awaiting_verification": "fixed",
    "pending_verification": "fixed",
    "resolved": "resolved",
    "closed": "resolved",
    "ignored": "ignored",
    "suppressed": "ignored",
    "accepted": "accepted",
    "accepted_risk": "accepted",
    "accepted-risk": "accepted",
    "acceptedrisk": "accepted",
}

_SCAN_LIFECYCLE_ORDER = {
    "queued": 10,
    "acknowledged": 20,
    "running": 30,
    "completed": 100,
    "failed": 100,
    "cancelled": 100,
}

_SCAN_PHASE_ORDER = {
    "queued": 10,
    "acknowledged": 20,
    "running": 30,
    "collecting_inventory": 40,
    "analyzing_exposure": 50,
    "querying_source": 60,
    "normalizing_findings": 70,
    "ingesting_results": 80,
    "completed": 100,
    "failed": 100,
    "cancelled": 100,
}


def _normalize_choice(value: str | None, *, valid: Iterable[str], aliases: dict[str, str], default: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return default
    raw = aliases.get(raw, raw)
    return raw if raw in set(valid) else default


def normalize_scan_lifecycle_state(value: str | None) -> str:
    return _normalize_choice(
        value,
        valid=SCAN_LIFECYCLE_STATES,
        aliases=_SCAN_LIFECYCLE_ALIASES,
        default="running",
    )


def normalize_scan_phase(value: str | None, *, fallback_state: str | None = None) -> str:
    phase = _normalize_choice(
        value,
        valid=SCAN_PHASES,
        aliases=_SCAN_PHASE_ALIASES,
        default="running",
    )
    if value is None or str(value).strip() == "":
        state = normalize_scan_lifecycle_state(fallback_state)
        if state in {"queued", "acknowledged", "completed", "failed", "cancelled"}:
            return state
    return phase


def lifecycle_state_for_phase(phase: str | None) -> str:
    phase_norm = normalize_scan_phase(phase)
    if phase_norm in {"queued", "acknowledged", "completed", "failed", "cancelled"}:
        return phase_norm
    return "running"


def scan_lifecycle_rank(value: str | None) -> int:
    return _SCAN_LIFECYCLE_ORDER.get(normalize_scan_lifecycle_state(value), 0)


def scan_phase_rank(value: str | None) -> int:
    return _SCAN_PHASE_ORDER.get(normalize_scan_phase(value), 0)


def normalize_scan_filter_terms(value: str | None) -> tuple[str, ...]:
    raw = str(value or "").strip().lower()
    if not raw:
        return ()

    terms: list[str] = []
    lifecycle_term = _SCAN_LIFECYCLE_ALIASES.get(raw, raw)
    phase_term = _SCAN_PHASE_ALIASES.get(raw, raw)
    for candidate in (lifecycle_term, phase_term):
        if candidate in SCAN_LIFECYCLE_STATES or candidate in SCAN_PHASES:
            if candidate not in terms:
                terms.append(candidate)
    return tuple(terms)


def normalize_trigger_source(value: str | None, *, manual_trigger: bool = False) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"manual", "scheduled", "api", "agent"}:
        return raw
    if manual_trigger:
        return "manual"
    return "scheduled"


def normalize_finding_observation_state(value: str | None) -> str:
    return _normalize_choice(
        value,
        valid=FINDING_OBSERVATION_STATES,
        aliases=_FINDING_OBSERVATION_ALIASES,
        default="observed",
    )


def normalize_finding_observation_filter(value: str | None) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    normalized = _FINDING_OBSERVATION_ALIASES.get(raw, raw)
    return normalized if normalized in FINDING_OBSERVATION_STATES else None


def normalize_finding_operator_disposition(value: str | None, *, is_suppressed: bool = False) -> str:
    if is_suppressed:
        return "suppressed"
    return _normalize_choice(
        value,
        valid=FINDING_OPERATOR_DISPOSITIONS,
        aliases=_FINDING_DISPOSITION_ALIASES,
        default="open",
    )


def normalize_finding_disposition_filter(value: str | None) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    normalized = _FINDING_DISPOSITION_ALIASES.get(raw, raw)
    return normalized if normalized in FINDING_OPERATOR_DISPOSITIONS else None


def normalize_legacy_finding_status(value: str | None) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    normalized = _LEGACY_FINDING_STATUS_ALIASES.get(raw, raw)
    return normalized if normalized in LEGACY_FINDING_STATUSES else None


def derive_legacy_finding_status(observation_state: str | None, operator_disposition: str | None) -> str:
    observation_state_norm = normalize_finding_observation_state(observation_state)
    operator_disposition_norm = normalize_finding_operator_disposition(operator_disposition)
    if observation_state_norm == "resolved":
        return "resolved"
    if observation_state_norm == "awaiting_verification":
        return "fixed"
    if operator_disposition_norm == "suppressed":
        return "ignored"
    if operator_disposition_norm == "accepted_risk":
        return "accepted"
    return "open"


def scan_lifecycle_event(
    previous_state: str | None,
    previous_phase: str | None,
    next_state: str | None,
    next_phase: str | None,
) -> str:
    next_state_norm = normalize_scan_lifecycle_state(next_state)
    if next_state_norm in {"queued", "acknowledged", "completed", "failed", "cancelled"}:
        return next_state_norm

    previous_phase_norm = normalize_scan_phase(previous_phase, fallback_state=previous_state) if previous_phase else None
    next_phase_norm = normalize_scan_phase(next_phase, fallback_state=next_state_norm)
    if previous_phase_norm != next_phase_norm:
        return "phase_changed"
    return "progress"
