from app.features.vuln.domain import (
    derive_legacy_finding_status,
    lifecycle_state_for_phase,
    normalize_finding_disposition_filter,
    normalize_finding_observation_filter,
    normalize_finding_observation_state,
    normalize_finding_operator_disposition,
    normalize_legacy_finding_status,
    normalize_scan_filter_terms,
    normalize_scan_lifecycle_state,
    normalize_scan_phase,
    scan_lifecycle_event,
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


def test_vuln_filter_normalizers_preserve_compatibility_without_widening_invalid_queries() -> None:
    assert normalize_scan_filter_terms("query") == ("querying_source",)
    assert normalize_scan_filter_terms("running") == ("running",)
    assert normalize_scan_filter_terms("nonsense") == ()

    assert normalize_finding_observation_filter("fixed") == "awaiting_verification"
    assert normalize_finding_disposition_filter("accepted") == "accepted_risk"
    assert normalize_legacy_finding_status("suppressed") == "ignored"
    assert normalize_legacy_finding_status("nonsense") is None


def test_scan_lifecycle_event_prefers_terminal_and_explicit_phase_transitions() -> None:
    assert scan_lifecycle_event(None, None, "queued", "queued") == "queued"
    assert scan_lifecycle_event("queued", "queued", "acknowledged", "acknowledged") == "acknowledged"
    assert scan_lifecycle_event("running", "collecting_inventory", "running", "querying_source") == "phase_changed"
    assert scan_lifecycle_event("running", "querying_source", "running", "querying_source") == "progress"
    assert scan_lifecycle_event("running", "ingesting_results", "completed", "completed") == "completed"
