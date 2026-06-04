from __future__ import annotations

from app.features.correlations.engines.base import severity_score
from app.features.detections.domain.scoring import (
    ScoreSignals,
    build_rule_provenance,
    clamp_score,
    evidence_field_count,
    resolve_alert_risk_score,
    score_alert,
    score_alert_for_endpoints,
    score_alert_from_details,
    severity_baseline_score,
    severity_confidence_baseline,
)
from app.features.detections.testing.quality import collect_quality_warnings


def _factors(result):
    return {f["factor"]: f for f in result.breakdown}


def test_severity_baseline_score_values():
    assert severity_baseline_score("critical") == 95
    assert severity_baseline_score("high") == 78
    assert severity_baseline_score("medium") == 52
    assert severity_baseline_score("low") == 30
    assert severity_baseline_score("info") == 12
    assert severity_baseline_score("unknown") == 40
    assert severity_baseline_score("") == 40
    assert severity_baseline_score(None) == 40


def test_severity_score_delegates_to_baseline_unchanged():
    for sev in ("critical", "high", "medium", "low", "info", "weird", ""):
        assert severity_score(sev) == severity_baseline_score(sev)


def test_resolve_alert_risk_score_declared_fallback_and_clamp():
    assert resolve_alert_risk_score({"risk_score": 72}, "high") == 72
    assert resolve_alert_risk_score({}, "high") == 78
    assert resolve_alert_risk_score({"risk_score": None}, "medium") == 52
    assert resolve_alert_risk_score({"risk_score": 999}, "low") == 100
    assert resolve_alert_risk_score({"risk_score": -5}, "low") == 0


def test_clamp_score():
    assert clamp_score(50) == 50
    assert clamp_score(150) == 100
    assert clamp_score(-1) == 0
    assert clamp_score("nope") == 0
    assert clamp_score(72.6) == 73


def test_build_rule_provenance():
    prov = build_rule_provenance(
        {"pack": "core", "category": "auth", "rule_version": 2, "maturity": "stable", "risk_score": 72}
    )
    assert prov == {
        "pack": "core",
        "category": "auth",
        "rule_version": 2,
        "maturity": "stable",
        "risk_score": 72,
    }
    minimal = build_rule_provenance({"id": "x"})
    assert minimal["rule_version"] == 1
    assert minimal["risk_score"] is None
    assert minimal["maturity"] is None


def _rule(**kw):
    base = {
        "id": kw.get("id", "r"),
        "enabled": True,
        "severity": "high",
        "mitre": {"tactic": "execution", "technique_id": "T1059", "confidence": 80},
        "response": "Investigate and contain.",
        "false_positives": "Known administrative activity.",
        "risk_score": 70,
    }
    base.update(kw)
    return base


def test_missing_risk_score_flags_actionable_medium_plus_only():
    rules = [
        _rule(id="a", risk_score=None),
        _rule(id="b", risk_score=None, enabled=False),
        _rule(id="c", risk_score=None, status="deprecated"),
        _rule(id="d", risk_score=None, severity="low"),
        _rule(id="e", risk_score=70),
    ]
    flagged = {w["rule_id"] for w in collect_quality_warnings(rules) if w["code"] == "missing_risk_score"}
    assert flagged == {"a"}


def test_severity_confidence_mismatch():
    rules = [
        _rule(id="hi_lo", severity="high", mitre={"tactic": "t", "technique_id": "T1", "confidence": 40}),
        _rule(id="lo_hi", severity="low", mitre={"tactic": "t", "technique_id": "T1", "confidence": 90}),
        _rule(id="ok", severity="high", mitre={"tactic": "t", "technique_id": "T1", "confidence": 80}),
    ]
    flagged = {w["rule_id"] for w in collect_quality_warnings(rules) if w["code"] == "severity_confidence_mismatch"}
    assert flagged == {"hi_lo", "lo_hi"}


def test_overlap_warning_skips_deprecated_and_disabled():
    signature = {"match": {"event_type": "proc_exec", "extra_x": "y"}, "type": "aggregate_count", "group_by": ["agent_id"]}
    rules = [
        _rule(id="active1", **signature),
        _rule(id="active2", **signature),
        _rule(id="dep", status="deprecated", enabled=False, **signature),
    ]
    overlaps = [w for w in collect_quality_warnings(rules) if w["code"] == "suspicious_rule_overlap"]
    assert len(overlaps) == 1
    assert "active1" in overlaps[0]["message"] and "active2" in overlaps[0]["message"]
    assert "dep" not in overlaps[0]["message"]


# --- contextual scorer (Increment 2) ---


def test_score_alert_base_is_declared_or_severity_baseline():
    declared = score_alert(ScoreSignals(severity="high", declared_risk_score=70))
    assert declared.breakdown[0]["factor"] == "base"
    assert declared.breakdown[0]["risk_delta"] == 70
    assert declared.breakdown[0]["confidence_delta"] == severity_confidence_baseline("high")
    assert declared.breakdown[0]["detail"] == "declared risk_score 70"

    sev = score_alert(ScoreSignals(severity="medium"))
    assert sev.breakdown[0]["risk_delta"] == 52
    assert sev.breakdown[0]["confidence_delta"] == 55
    assert sev.breakdown[0]["detail"].startswith("severity 'medium'")


def test_score_alert_rule_confidence_is_confidence_base():
    assert score_alert(ScoreSignals(severity="high", rule_confidence=82)).breakdown[0]["confidence_delta"] == 82


def test_score_alert_positive_factors_raise_score():
    r = score_alert(
        ScoreSignals(
            severity="medium",
            declared_risk_score=52,
            rule_confidence=55,
            event_count=30,
            threshold=5,
            src_is_public=True,
            dst_is_internal=True,
            has_mitre=True,
            evidence_field_count=4,
            maturity="stable",
        )
    )
    factors = _factors(r)
    assert factors["aggregation_strength"]["risk_delta"] == 6
    assert factors["locality"]["risk_delta"] == 6
    assert factors["evidence_richness"]["risk_delta"] == 6
    assert factors["mitre_mapping"]["risk_delta"] == 3
    assert factors["maturity"]["risk_delta"] == 2
    assert r.risk_score == clamp_score(52 + 6 + 6 + 6 + 3 + 2)
    assert r.risk_score > 52


def test_score_alert_negative_factors_lower_score():
    r = score_alert(
        ScoreSignals(
            severity="high",
            maturity="experimental",
            src_scope="loopback",
            dst_scope="loopback",
            has_mitre=False,
            evidence_field_count=0,
        )
    )
    factors = _factors(r)
    assert factors["locality"]["risk_delta"] == -8
    assert factors["evidence_richness"]["risk_delta"] == -4
    assert factors["mitre_mapping"]["risk_delta"] == -2
    assert factors["maturity"]["risk_delta"] == -5
    assert r.risk_score == 78 - 8 - 4 - 2 - 5
    assert r.risk_score < 78


def test_fp_feedback_requires_min_samples_and_scales():
    strong = score_alert(ScoreSignals(severity="high", declared_risk_score=78, fp_close_rate=0.8, fp_close_samples=20))
    assert _factors(strong)["fp_feedback"]["risk_delta"] == -15
    too_few = score_alert(ScoreSignals(severity="high", declared_risk_score=78, fp_close_rate=0.8, fp_close_samples=3))
    assert "fp_feedback" not in _factors(too_few)
    trusted = score_alert(ScoreSignals(severity="high", declared_risk_score=78, fp_close_rate=0.05, fp_close_samples=40))
    assert _factors(trusted)["fp_feedback"]["risk_delta"] == 3


def test_score_alert_clamped_0_100():
    hi = score_alert(
        ScoreSignals(
            severity="critical",
            declared_risk_score=100,
            event_count=99,
            threshold=1,
            src_is_public=True,
            dst_is_internal=True,
            has_mitre=True,
            evidence_field_count=9,
            maturity="stable",
            correlated=True,
        )
    )
    assert hi.risk_score == 100 and hi.confidence == 100
    lo = score_alert(
        ScoreSignals(
            severity="info",
            declared_risk_score=0,
            src_scope="loopback",
            dst_scope="loopback",
            has_mitre=False,
            evidence_field_count=0,
            maturity="experimental",
            fp_close_rate=0.9,
            fp_close_samples=50,
        )
    )
    assert lo.risk_score == 0 and 0 <= lo.confidence <= 100


def test_score_alert_is_deterministic_and_serializable():
    import json

    signals = ScoreSignals(severity="high", event_count=12, threshold=3, has_mitre=True, evidence_field_count=2)
    first, second = score_alert(signals), score_alert(signals)
    assert first.risk_score == second.risk_score
    assert first.confidence == second.confidence
    assert first.breakdown == second.breakdown
    assert first.breakdown[0]["factor"] == "base"
    for factor in first.breakdown:
        assert set(factor.keys()) == {"factor", "risk_delta", "confidence_delta", "detail"}
    json.dumps(first.breakdown)


def test_evidence_field_count():
    rich = {"group_key": {"src_ip": "1.1.1.1", "dst_port": 443}, "distinct_count": 5, "enrichment": {"unique_src_ips": 4}}
    assert evidence_field_count(rich) == 4
    assert evidence_field_count({"group_key": {"src_ip": None, "x": "-"}}) == 0
    assert evidence_field_count({}) == 0


def test_score_alert_from_details_resolves_signals():
    details = {
        "type": "aggregate_count",
        "count": 40,
        "group_key": {"src_ip": "8.8.8.8", "dst_port": 443},
        "mitre": {"confidence": 70},
        "enrichment": {"unique_src_ips": 3},
    }
    r = score_alert_from_details({"risk_score": 78, "maturity": "stable"}, "high", details)
    factors = _factors(r)
    assert factors["base"]["risk_delta"] == 78
    assert factors["base"]["confidence_delta"] == 70
    assert "aggregation_strength" in factors
    assert "mitre_mapping" in factors
    assert "evidence_richness" in factors


def test_score_alert_for_endpoints_locality_and_fp_feedback():
    details = {"count": 10, "group_key": {"src_ip": "8.8.8.8"}, "mitre": {"confidence": 70}}
    external = score_alert_for_endpoints(
        {"risk_score": 78}, "rid", "high", details,
        src_ip="8.8.8.8", dst_ip="10.0.0.5", fp_rates={"rid": (0.8, 30)},
    )
    factors = _factors(external)
    assert factors["locality"]["risk_delta"] == 6
    assert factors["fp_feedback"]["risk_delta"] == -15

    loopback = score_alert_for_endpoints(
        {"risk_score": 78}, "x", "high", {"count": 1}, src_ip="127.0.0.1", dst_ip="127.0.0.1"
    )
    assert _factors(loopback)["locality"]["risk_delta"] == -8
