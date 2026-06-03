from __future__ import annotations

from app.features.correlations.engines.base import severity_score
from app.features.detections.domain.scoring import (
    build_rule_provenance,
    clamp_score,
    resolve_alert_risk_score,
    severity_baseline_score,
)
from app.features.detections.testing.quality import collect_quality_warnings


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
