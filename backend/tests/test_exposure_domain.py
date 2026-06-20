from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.features.exposure.domain.constants import (
    RC_ACTIVE_ALERT,
    RC_ATTACK_CHAIN_PROGRESSION,
    RC_CRITICAL_CVE,
    RC_EXPLOITABILITY_SIGNAL,
    RC_LOW_EVIDENCE_CONFIDENCE,
    RC_STALE_AGENT,
    RC_VULNERABLE_PACKAGE,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from app.features.exposure.domain.evidence import (
    build_evidence_ref,
    count_evidence_by_source,
    derive_aggregate_confidence,
    evidence_refs_from_list,
    evidence_refs_to_list,
    merge_evidence_refs,
)
from app.features.exposure.domain.normalization import (
    make_edge_key,
    make_finding_key,
    make_node_key,
    normalize_asset_key,
    normalize_severity,
    severity_from_score,
    stable_hash,
    validate_asset_key,
)
from app.features.exposure.domain.recommendations import generate_recommendations
from app.features.exposure.domain.scoring import ScoringInputs, compute_risk_score

# Asset key normalization


def test_normalize_asset_key_agent_takes_priority() -> None:
    key = normalize_asset_key("abc123", ip="10.0.0.1", hostname="myhost")
    assert key == "agent:abc123"


def test_normalize_asset_key_falls_back_to_ip() -> None:
    key = normalize_asset_key(None, ip="192.168.1.1")
    assert key == "ip:192.168.1.1"


def test_normalize_asset_key_falls_back_to_hostname() -> None:
    key = normalize_asset_key(None, hostname="web-01.internal")
    assert key == "host:web-01.internal"


def test_normalize_asset_key_strips_invalid_chars() -> None:
    key = normalize_asset_key("abc!@#$%^&*()xyz")
    assert key == "agent:abcxyz"


def test_normalize_asset_key_raises_when_no_identity() -> None:
    with pytest.raises(ValueError):
        normalize_asset_key(None)


def test_validate_asset_key_accepts_valid_forms() -> None:
    assert validate_asset_key("agent:abc123") is True
    assert validate_asset_key("ip:10.0.0.1") is True
    assert validate_asset_key("host:web-01") is True
    assert validate_asset_key("url:https://example.com") is True


def test_validate_asset_key_rejects_bad_forms() -> None:
    assert validate_asset_key("random_string") is False
    assert validate_asset_key("") is False
    assert validate_asset_key("agent:") is False


# Node / edge key stability


def test_node_key_is_deterministic() -> None:
    k1 = make_node_key("asset", "agent:abc")
    k2 = make_node_key("asset", "agent:abc")
    assert k1 == k2


def test_node_key_differs_across_types() -> None:
    k1 = make_node_key("asset", "agent:abc")
    k2 = make_node_key("cve", "agent:abc")
    assert k1 != k2


def test_edge_key_is_deterministic() -> None:
    k1 = make_edge_key("node:a", "node:b", "has_cve")
    k2 = make_edge_key("node:a", "node:b", "has_cve")
    assert k1 == k2


def test_edge_key_is_directional() -> None:
    k1 = make_edge_key("node:a", "node:b", "has_cve")
    k2 = make_edge_key("node:b", "node:a", "has_cve")
    assert k1 != k2


def test_finding_key_stable() -> None:
    k1 = make_finding_key("vulnerability", "agent:abc", "vuln-42")
    k2 = make_finding_key("vulnerability", "agent:abc", "vuln-42")
    assert k1 == k2


def test_stable_hash_length() -> None:
    h = stable_hash("a", "b", "c")
    assert len(h) == 64


# Severity mapping


@pytest.mark.parametrize(
    "score, expected",
    [
        (0, SEVERITY_INFORMATIONAL),
        (19, SEVERITY_INFORMATIONAL),
        (20, SEVERITY_LOW),
        (39, SEVERITY_LOW),
        (40, SEVERITY_MEDIUM),
        (59, SEVERITY_MEDIUM),
        (60, SEVERITY_HIGH),
        (79, SEVERITY_HIGH),
        (80, SEVERITY_CRITICAL),
        (100, SEVERITY_CRITICAL),
    ],
)
def test_severity_from_score_bands(score: int, expected: str) -> None:
    assert severity_from_score(score) == expected


def test_severity_from_score_clamps_below_zero() -> None:
    assert severity_from_score(-5) == SEVERITY_INFORMATIONAL


def test_severity_from_score_clamps_above_100() -> None:
    assert severity_from_score(200) == SEVERITY_CRITICAL


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("critical", SEVERITY_CRITICAL),
        ("CRITICAL", SEVERITY_CRITICAL),
        ("high", SEVERITY_HIGH),
        ("medium", SEVERITY_MEDIUM),
        ("med", SEVERITY_MEDIUM),
        ("low", SEVERITY_LOW),
        ("informational", SEVERITY_INFORMATIONAL),
        ("info", SEVERITY_INFORMATIONAL),
        ("none", SEVERITY_INFORMATIONAL),
        ("garbage", "unknown"),
    ],
)
def test_normalize_severity_aliases(raw: str, expected: str) -> None:
    assert normalize_severity(raw) == expected


# Scoring boundaries


def _base_inputs(**kwargs) -> ScoringInputs:
    defaults = dict(
        asset_key="agent:test",
        agent_id="test",
        asset_last_seen_at=datetime.now(tz=timezone.utc),
        asset_criticality="medium",
    )
    defaults.update(kwargs)
    return ScoringInputs(**defaults)


def test_risk_score_is_zero_for_empty_inputs() -> None:
    inputs = _base_inputs()
    score, breakdown, confidence, _ = compute_risk_score(inputs)
    assert score >= 0


def test_risk_score_bounded_0_100() -> None:
    inputs = _base_inputs(
        critical_vuln_count=100,
        high_vuln_count=100,
        active_alert_count=100,
        open_attack_chain_count=10,
        max_attack_chain_score=100,
        lateral_movement_count=10,
        persistence_signal_count=10,
        exposed_service_count=20,
        has_exploitability_signal=True,
        asset_criticality="critical",
    )
    score, _, _, _ = compute_risk_score(inputs)
    assert 0 <= score <= 100


def test_critical_cve_increases_score() -> None:
    base = _base_inputs()
    with_cve = _base_inputs(critical_vuln_count=2)
    s_base, _, _, _ = compute_risk_score(base)
    s_cve, _, _, _ = compute_risk_score(with_cve)
    assert s_cve > s_base


def test_attack_chain_increases_score() -> None:
    base = _base_inputs()
    with_chain = _base_inputs(open_attack_chain_count=1, max_attack_chain_score=80)
    s_base, _, _, _ = compute_risk_score(base)
    s_chain, _, _, _ = compute_risk_score(with_chain)
    assert s_chain > s_base


def test_reason_codes_include_critical_cve() -> None:
    inputs = _base_inputs(critical_vuln_count=1)
    _, _, _, codes = compute_risk_score(inputs)
    assert RC_CRITICAL_CVE in codes
    assert RC_VULNERABLE_PACKAGE in codes


def test_reason_codes_include_active_alert() -> None:
    inputs = _base_inputs(active_alert_count=1)
    _, _, _, codes = compute_risk_score(inputs)
    assert RC_ACTIVE_ALERT in codes


def test_reason_codes_include_attack_chain() -> None:
    inputs = _base_inputs(open_attack_chain_count=1, max_attack_chain_score=50)
    _, _, _, codes = compute_risk_score(inputs)
    assert RC_ATTACK_CHAIN_PROGRESSION in codes


def test_reason_code_stale_agent_when_no_agent_id() -> None:
    inputs = _base_inputs(agent_id=None)
    _, _, _, codes = compute_risk_score(inputs)
    assert RC_STALE_AGENT in codes


def test_reason_code_low_confidence_when_base_is_low() -> None:
    inputs = _base_inputs(base_confidence=10)
    _, _, _, codes = compute_risk_score(inputs)
    assert RC_LOW_EVIDENCE_CONFIDENCE in codes


def test_exploitability_signal_reason_code() -> None:
    inputs = _base_inputs(has_exploitability_signal=True)
    _, _, _, codes = compute_risk_score(inputs)
    assert RC_EXPLOITABILITY_SIGNAL in codes


# Evidence normalization

_NOW = datetime(2026, 4, 26, 12, 0, 0, tzinfo=timezone.utc)


def test_build_evidence_ref_basic() -> None:
    ref = build_evidence_ref(
        source_type="alert",
        source_id=42,
        observed_at=_NOW,
        title="Test alert",
        summary="Summary",
    )
    assert ref.source_type == "alert"
    assert ref.source_id == "42"
    assert ref.title == "Test alert"


def test_evidence_refs_roundtrip() -> None:
    ref = build_evidence_ref(
        source_type="vulnerability",
        source_id="vuln-1",
        observed_at=_NOW,
        title="CVE-2024-1234",
    )
    serialized = evidence_refs_to_list([ref])
    deserialized = evidence_refs_from_list(serialized)
    assert len(deserialized) == 1
    assert deserialized[0].source_type == "vulnerability"
    assert deserialized[0].source_id == "vuln-1"


def test_evidence_refs_from_list_skips_invalid() -> None:
    raw = [
        {"source_type": "alert", "source_id": "1", "observed_at": _NOW.isoformat(), "title": "ok"},
        {"source_type": "alert"},  # missing source_id
        "not a dict",
    ]
    refs = evidence_refs_from_list(raw)
    assert len(refs) == 1


def test_count_evidence_by_source() -> None:
    refs = [
        build_evidence_ref(source_type="alert", source_id="1", observed_at=_NOW, title="a"),
        build_evidence_ref(source_type="alert", source_id="2", observed_at=_NOW, title="b"),
        build_evidence_ref(source_type="vulnerability", source_id="3", observed_at=_NOW, title="c"),
    ]
    counts = count_evidence_by_source(refs)
    assert counts["alert"] == 2
    assert counts["vulnerability"] == 1


def test_derive_aggregate_confidence_with_refs() -> None:
    refs = [
        build_evidence_ref(source_type="vulnerability", source_id="v1", observed_at=_NOW, title="x"),
        build_evidence_ref(source_type="alert", source_id="a1", observed_at=_NOW, title="y"),
    ]
    conf = derive_aggregate_confidence(refs, base_confidence=50)
    assert 1 <= conf <= 99


def test_derive_aggregate_confidence_no_refs() -> None:
    conf = derive_aggregate_confidence([], base_confidence=55)
    assert conf == 55


def test_merge_evidence_refs_deduplicates_by_id() -> None:
    older = build_evidence_ref(source_type="alert", source_id="1", observed_at=_NOW, title="old")
    newer = build_evidence_ref(
        source_type="alert",
        source_id="1",
        observed_at=datetime(2026, 4, 26, 13, 0, 0, tzinfo=timezone.utc),
        title="new",
    )
    merged = merge_evidence_refs([older], [newer])
    assert len(merged) == 1
    assert merged[0].title == "new"


# Recommendation generation


def test_recommendations_for_critical_cve() -> None:
    recs = generate_recommendations([RC_CRITICAL_CVE])
    assert any(r.rec_type == "patch_vulnerable_package" for r in recs)


def test_recommendations_are_prioritized() -> None:
    codes = [RC_VULNERABLE_PACKAGE, RC_ATTACK_CHAIN_PROGRESSION, RC_ACTIVE_ALERT]
    recs = generate_recommendations(codes)
    priorities = [r.priority for r in recs]
    assert priorities == sorted(priorities)


def test_recommendations_deduplicates_rec_types() -> None:
    codes = [RC_CRITICAL_CVE, RC_EXPLOITABILITY_SIGNAL, RC_VULNERABLE_PACKAGE]
    recs = generate_recommendations(codes)
    rec_types = [r.rec_type for r in recs]
    assert len(rec_types) == len(set(rec_types))


def test_recommendations_max_five() -> None:
    from app.features.exposure.domain.constants import REASON_CODES  # noqa: PLC0415
    recs = generate_recommendations(list(REASON_CODES))
    assert len(recs) <= 5


def test_empty_reason_codes_gives_no_recommendations() -> None:
    recs = generate_recommendations([])
    assert recs == []


# Model import compatibility (model_registry)


def test_model_registry_includes_exposure_import() -> None:
    import importlib  # noqa: PLC0415

    # Load the module source without triggering engine creation.
    spec = importlib.util.spec_from_file_location(
        "model_registry_source_check",
        __import__("pathlib").Path(__file__).parents[1] / "app" / "core" / "model_registry.py",
    )
    source = spec.origin
    text = __import__("pathlib").Path(source).read_text()
    assert "features.exposure" in text, "model_registry.py must import the exposure models"


def test_exposure_model_tablenames_from_source() -> None:
    import pathlib  # noqa: PLC0415

    models_src = (
        pathlib.Path(__file__).parents[1] / "app" / "features" / "exposure" / "models.py"
    ).read_text()

    for table in (
        "exposure_asset_posture",
        "exposure_nodes",
        "exposure_edges",
        "exposure_findings",
        "exposure_score_history",
    ):
        assert table in models_src, f"Table '{table}' not found in exposure/models.py"
