"""Focused tests for rule governance validation."""
from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from app.features.alerts.governance import (
    validate_governance_request,
    validate_suppression_item,
)
from app.features.alerts.schemas import RuleOverrideIn


def _body(**kwargs) -> RuleOverrideIn:
    return RuleOverrideIn(**kwargs)


BASE_LOW = {"id": "test_rule_v1", "severity": "low"}
BASE_HIGH = {"id": "test_rule_v1", "severity": "high"}
BASE_CRITICAL = {"id": "test_rule_v1", "severity": "critical"}


# --- Override field validation ---

def test_invalid_severity_rejected() -> None:
    result = validate_governance_request(_body(severity="ultra"), base_rule=BASE_LOW)
    assert not result.ok
    assert any("severity" in e for e in result.errors)


def test_valid_severity_accepted() -> None:
    for sev in ("low", "medium", "high", "critical"):
        result = validate_governance_request(_body(severity=sev), base_rule=BASE_LOW)
        assert result.ok, f"expected ok for severity={sev}, got errors={result.errors}"


def test_invalid_window_rejected() -> None:
    result = validate_governance_request(_body(window="5 minutes"), base_rule=BASE_LOW)
    assert not result.ok
    assert any("window" in e for e in result.errors)


def test_invalid_cooldown_rejected() -> None:
    result = validate_governance_request(_body(cooldown="bad"), base_rule=BASE_LOW)
    assert not result.ok
    assert any("cooldown" in e for e in result.errors)


def test_valid_durations_accepted() -> None:
    result = validate_governance_request(_body(window="10m", cooldown="30s"), base_rule=BASE_LOW)
    assert result.ok


def test_negative_min_events_rejected() -> None:
    result = validate_governance_request(_body(min_events=-1), base_rule=BASE_LOW)
    assert not result.ok
    assert any("min_events" in e for e in result.errors)


def test_invalid_condition_operator_rejected() -> None:
    result = validate_governance_request(
        _body(condition={"operator": "~=", "value": 5}), base_rule=BASE_LOW
    )
    assert not result.ok
    assert any("condition.operator" in e for e in result.errors)


def test_invalid_condition_value_rejected() -> None:
    result = validate_governance_request(
        _body(condition={"operator": ">=", "value": "not_a_number"}), base_rule=BASE_LOW
    )
    assert not result.ok
    assert any("condition.value" in e for e in result.errors)


def test_valid_tuning_accepted() -> None:
    result = validate_governance_request(
        _body(tuning={"threshold_scopes": []}), base_rule=BASE_LOW
    )
    assert result.ok
    assert result.errors == []


def test_valid_full_override_accepted() -> None:
    result = validate_governance_request(
        _body(
            enabled=True,
            severity="medium",
            window="10m",
            cooldown="15m",
            min_events=5,
            condition={"operator": ">=", "value": 10},
        ),
        base_rule=BASE_LOW,
    )
    assert result.ok


# --- Suppression item validation ---

def test_suppression_without_reason_rejected() -> None:
    body = _body(
        suppressions=[{"until": "2099-01-01T00:00:00Z", "when": {"src_ip": "1.1.1.1"}}]
    )
    result = validate_governance_request(body, base_rule=BASE_LOW)
    assert not result.ok
    assert any("reason" in e for e in result.errors)


def test_suppression_without_expiration_rejected() -> None:
    body = _body(suppressions=[{"reason": "jump host", "when": {"src_ip": "1.1.1.1"}}])
    result = validate_governance_request(body, base_rule=BASE_LOW)
    assert not result.ok
    assert any("until" in e or "permanent" in e for e in result.errors)


def test_suppression_with_until_accepted() -> None:
    body = _body(
        suppressions=[
            {"reason": "known scanner", "until": "2099-01-01T00:00:00Z", "when": {"src_ip": "1.1.1.1"}}
        ]
    )
    result = validate_governance_request(body, base_rule=BASE_LOW)
    assert result.ok


def test_suppression_with_permanent_accepted() -> None:
    body = _body(
        suppressions=[
            {"reason": "jump host", "permanent": True, "when": {"src_ip": "10.0.0.1"}}
        ]
    )
    result = validate_governance_request(body, base_rule=BASE_LOW)
    assert result.ok


# --- High/critical broad suppression guard ---

def test_broad_suppression_on_high_rule_rejected_without_confirm() -> None:
    body = _body(suppressions=[{"reason": "silence everything", "permanent": True}])
    result = validate_governance_request(body, base_rule=BASE_HIGH)
    assert not result.ok
    assert any("confirm_high_risk" in e for e in result.errors)


def test_broad_suppression_on_critical_rule_rejected_without_confirm() -> None:
    body = _body(suppressions=[{"reason": "silence everything", "permanent": True}])
    result = validate_governance_request(body, base_rule=BASE_CRITICAL)
    assert not result.ok
    assert any("confirm_high_risk" in e for e in result.errors)


def test_broad_suppression_on_high_rule_accepted_with_confirm() -> None:
    body = _body(
        suppressions=[
            {"reason": "silence everything", "permanent": True, "confirm_high_risk": True}
        ]
    )
    result = validate_governance_request(body, base_rule=BASE_HIGH)
    assert result.ok


def test_broad_suppression_on_low_rule_accepted_without_confirm() -> None:
    body = _body(suppressions=[{"reason": "noisy rule", "permanent": True}])
    result = validate_governance_request(body, base_rule=BASE_LOW)
    assert result.ok


def test_scoped_suppression_on_high_rule_accepted_without_confirm() -> None:
    body = _body(
        suppressions=[
            {
                "reason": "trusted scanner",
                "permanent": True,
                "when": {"src_ip": "10.0.0.50"},
            }
        ]
    )
    result = validate_governance_request(body, base_rule=BASE_HIGH)
    assert result.ok


# --- validate_suppression_item directly ---

def test_suppression_item_missing_reason() -> None:
    errors = validate_suppression_item(
        {"until": "2099-01-01T00:00:00Z", "when": {"src_ip": "1.1.1.1"}},
        base_severity="low",
        idx=0,
    )
    assert any("reason" in e for e in errors)


def test_suppression_item_missing_expiration() -> None:
    errors = validate_suppression_item(
        {"reason": "ok reason", "when": {"src_ip": "1.1.1.1"}},
        base_severity="low",
        idx=0,
    )
    assert any("until" in e or "permanent" in e for e in errors)


def test_suppression_item_valid() -> None:
    errors = validate_suppression_item(
        {"reason": "ok reason", "permanent": True, "when": {"src_ip": "1.1.1.1"}},
        base_severity="low",
        idx=0,
    )
    assert errors == []


# --- patch overwriting v2 detection block ---

def test_patch_overwriting_detection_block_rejected() -> None:
    base = {"id": "v2_rule", "schema_version": 2, "severity": "medium"}
    body = _body(patch={"detection": {"condition": "broken"}})
    result = validate_governance_request(body, base_rule=base)
    assert not result.ok
    assert any("detection" in e for e in result.errors)


def test_patch_without_detection_on_v2_rule_accepted() -> None:
    from app.features.detections.domain.condition_ast import (
        DetectionBlock, DetectionCondition, SelectionReference
    )
    detection = DetectionBlock(
        selections=(),
        condition=DetectionCondition(raw="dummy", expression=SelectionReference(name="dummy")),
    )
    base = {"id": "v2_rule", "schema_version": 2, "severity": "medium", "detection": detection}
    body = _body(severity="high")
    result = validate_governance_request(body, base_rule=base)
    assert result.ok
