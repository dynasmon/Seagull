from app.features.vuln.domain import (
    derive_legacy_finding_status,
    lifecycle_state_for_phase,
    normalize_finding_observation_state,
    normalize_finding_operator_disposition,
    normalize_scan_lifecycle_state,
    normalize_scan_phase,
)


def test_scan_lifecycle_aliases_normalize_cleanly() -> None:
    assert normalize_scan_lifecycle_state("finished") == "completed"
    assert normalize_scan_lifecycle_state("error") == "failed"
    assert normalize_scan_phase("query") == "querying_source"
    assert lifecycle_state_for_phase("collecting_inventory") == "running"


def test_finding_state_aliases_and_legacy_statuses() -> None:
    assert normalize_finding_observation_state("fixed") == "awaiting_verification"
    assert normalize_finding_operator_disposition("accepted") == "accepted_risk"
    assert derive_legacy_finding_status("resolved", "suppressed") == "resolved"
    assert derive_legacy_finding_status("observed", "suppressed") == "ignored"
    assert derive_legacy_finding_status("observed", "accepted_risk") == "accepted"
