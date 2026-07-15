from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from app.features.detections.domain.validation import DetectionRuleValidationError
from app.features.detections.rules.loader import (
    load_and_validate_rules,
)
from app.features.detections.rules.loader import (
    load_rules as load_detection_rules,
)
from app.workers.intelligence.rules.loader import load_rules as load_worker_rules

_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def _write_v2_rule(path: Path, body: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(body), encoding="utf-8")


def test_valid_v2_rule_loads_and_normalizes(tmp_path: Path) -> None:
    _write_v2_rule(
        tmp_path / "packs" / "network" / "ssh.yml",
        [
            "pack: network",
            "category: auth",
            "rules:",
            "  - schema_version: 2",
            "    id: ssh_auth_detection_v2",
            "    name: SSH auth detection",
            "    description: Detect repeated SSH auth activity excluding known admins.",
            "    enabled: true",
            "    status: active",
            "    maturity: stable",
            "    severity: high",
            "    risk_score: 80",
            "    confidence: 90",
            "    logsource:",
            "      source: ssh_auth",
            "    attack:",
            "      tactic: credential_access",
            "      technique_id: T1110.001",
            "      technique: \"Brute Force: Password Guessing\"",
            "    detection:",
            "      selection:",
            "        event.type: ssh_auth",
            "        destination.port: 22",
            "        user.name|exists: true",
            "      filter_known_admin:",
            "        source.ip|in:",
            "          - 10.0.0.10",
            "      condition: selection and not filter_known_admin",
            "    aggregation:",
            "      type: threshold",
            "      window: 5m",
            "      group_by:",
            "        - source.ip",
            "        - destination.ip",
            "      condition:",
            "        operator: \">=\"",
            "        value: 5",
            "      min_events: 5",
            "    suppression:",
            "      cooldown: 10m",
            "    tuning: {}",
            "    response:",
            "      playbook: Investigate the source and target.",
            "    tests: []",
        ],
    )

    rules = load_detection_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=tmp_path,
        apply_env_filters=False,
        include_non_runtime=True,
    )
    assert len(rules) == 1

    rule = rules[0]
    assert int(rule["schema_version"]) == 2
    detection = rule["detection"]
    selection = next(item for item in detection.selections if item.name == "selection")
    predicates = {predicate.source_key: predicate for predicate in selection.predicates}

    assert predicates["event.type"].runtime_field == "event_type"
    assert predicates["event.type"].operator == "eq"
    assert predicates["destination.port"].runtime_field == "dst_port"
    assert predicates["destination.port"].value == 22
    assert predicates["user.name|exists"].runtime_field == "ssh_username"
    assert predicates["user.name|exists"].operator == "exists"
    assert detection.condition.raw == "selection and not filter_known_admin"
    assert rule["aggregation"]["type"] == "threshold"
    assert rule["aggregation"]["group_by"] == ["src_ip", "dst_ip"]


def test_invalid_unsupported_canonical_field_returns_structured_error(tmp_path: Path) -> None:
    _write_v2_rule(
        tmp_path / "packs" / "network" / "invalid_field.yml",
        [
            "pack: network",
            "rules:",
            "  - schema_version: 2",
            "    id: invalid_field_v2",
            "    name: Invalid field",
            "    description: Invalid field should fail.",
            "    enabled: true",
            "    status: draft",
            "    maturity: stable",
            "    severity: low",
            "    detection:",
            "      selection:",
            "        unsupported.field: value",
            "    aggregation:",
            "      type: threshold",
            "    suppression: {}",
            "    tuning: {}",
            "    response: {}",
            "    tests: []",
        ],
    )

    report = load_and_validate_rules(
        rules_dir=tmp_path,
        apply_env_filters=False,
        strict=False,
        include_non_runtime=True,
    )
    assert len(report["errors"]) == 1
    assert "Unsupported detection field: unsupported.field" in report["errors"][0]["message"]


def test_invalid_unsupported_operator_fails_and_strict_mode_raises(tmp_path: Path) -> None:
    _write_v2_rule(
        tmp_path / "packs" / "network" / "invalid_operator.yml",
        [
            "pack: network",
            "rules:",
            "  - schema_version: 2",
            "    id: invalid_operator_v2",
            "    name: Invalid operator",
            "    description: Invalid operator should fail.",
            "    enabled: true",
            "    status: draft",
            "    maturity: stable",
            "    severity: low",
            "    detection:",
            "      selection:",
            "        source.ip|regex: ^10",
            "    aggregation:",
            "      type: threshold",
            "    suppression: {}",
            "    tuning: {}",
            "    response: {}",
            "    tests: []",
        ],
    )

    report = load_and_validate_rules(
        rules_dir=tmp_path,
        apply_env_filters=False,
        strict=False,
        include_non_runtime=True,
    )
    assert len(report["errors"]) == 1
    assert "Unsupported field operator: regex" in report["errors"][0]["message"]

    with pytest.raises(DetectionRuleValidationError, match="Unsupported field operator: regex"):
        load_and_validate_rules(
            rules_dir=tmp_path,
            apply_env_filters=False,
            strict=True,
            include_non_runtime=True,
        )


def test_invalid_condition_expression_fails(tmp_path: Path) -> None:
    _write_v2_rule(
        tmp_path / "packs" / "network" / "invalid_condition.yml",
        [
            "pack: network",
            "rules:",
            "  - schema_version: 2",
            "    id: invalid_condition_v2",
            "    name: Invalid condition",
            "    description: Invalid condition should fail.",
            "    enabled: true",
            "    status: draft",
            "    maturity: stable",
            "    severity: low",
            "    detection:",
            "      selection:",
            "        event.type: ssh_auth",
            "      filter_known_admin:",
            "        source.ip|in:",
            "          - 10.0.0.10",
            "      condition: selection and or filter_known_admin",
            "    aggregation:",
            "      type: threshold",
            "    suppression: {}",
            "    tuning: {}",
            "    response: {}",
            "    tests: []",
        ],
    )

    report = load_and_validate_rules(
        rules_dir=tmp_path,
        apply_env_filters=False,
        strict=False,
        include_non_runtime=True,
    )
    assert len(report["errors"]) == 1
    assert "Unexpected token in condition: or" in report["errors"][0]["message"]


def test_v2_shorthand_parsing_supports_core_operators(tmp_path: Path) -> None:
    _write_v2_rule(
        tmp_path / "packs" / "network" / "shorthand.yml",
        [
            "pack: network",
            "rules:",
            "  - schema_version: 2",
            "    id: shorthand_v2",
            "    name: Shorthand",
            "    description: Validate shorthand parsing.",
            "    enabled: true",
            "    status: draft",
            "    maturity: stable",
            "    severity: medium",
            "    detection:",
            "      selection:",
            "        event.type: l7_flow",
            "        network.bytes|gte: 10",
            "        http.request.host|contains: admin",
            "        user.name|exists: true",
            "      condition: selection",
            "    aggregation:",
            "      type: threshold",
            "    suppression: {}",
            "    tuning: {}",
            "    response: {}",
            "    tests: []",
        ],
    )

    rule = load_detection_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=tmp_path,
        apply_env_filters=False,
        include_non_runtime=True,
    )[0]
    selection = rule["detection"].selections[0]
    predicates = {predicate.source_key: predicate for predicate in selection.predicates}

    assert predicates["event.type"].operator == "eq"
    assert predicates["network.bytes|gte"].operator == "gte"
    assert predicates["network.bytes|gte"].runtime_field == "bytes"
    assert predicates["http.request.host|contains"].operator == "contains"
    assert predicates["http.request.host|contains"].runtime_field == "http_host"
    assert predicates["user.name|exists"].operator == "exists"


def test_duplicate_rule_ids_are_reported_for_cross_version_mix(tmp_path: Path) -> None:
    _write_v2_rule(
        tmp_path / "packs" / "network" / "mixed.yml",
        [
            "pack: network",
            "rules:",
            "  - id: duplicate_rule",
            "    enabled: true",
            "    type: aggregate_count",
            "    match:",
            "      event_type: ssh_auth",
            "    group_by: src_ip",
            "    condition: {operator: \">=\", value: 1}",
            "  - schema_version: 2",
            "    id: duplicate_rule",
            "    name: Duplicate V2",
            "    description: Duplicate id should fail.",
            "    enabled: true",
            "    status: draft",
            "    maturity: stable",
            "    severity: low",
            "    detection:",
            "      selection:",
            "        event.type: ssh_auth",
            "      condition: selection",
            "    aggregation:",
            "      type: threshold",
            "    suppression: {}",
            "    tuning: {}",
            "    response: {}",
            "    tests: []",
        ],
    )

    report = load_and_validate_rules(
        rules_dir=tmp_path,
        apply_env_filters=False,
        strict=False,
        include_non_runtime=True,
    )
    assert len(report["errors"]) == 1
    assert "Duplicate rule id detected: duplicate_rule" in report["errors"][0]["message"]

    with pytest.raises(RuntimeError, match="Duplicate rule id detected: duplicate_rule"):
        load_detection_rules(
            include_disabled=True,
            with_source=True,
            rules_dir=tmp_path,
            apply_env_filters=False,
            include_non_runtime=True,
        )


def test_worker_loader_includes_v1_and_v2_rules(tmp_path: Path) -> None:
    _write_v2_rule(
        tmp_path / "packs" / "network" / "mixed_runtime.yml",
        [
            "pack: network",
            "rules:",
            "  - id: ssh_count_v1",
            "    enabled: true",
            "    type: aggregate_count",
            "    match:",
            "      event_type: ssh_auth",
            "    group_by: src_ip",
            "    condition: {operator: \">=\", value: 1}",
            "  - schema_version: 2",
            "    id: ssh_count_v2",
            "    name: SSH Count V2",
            "    description: V2 rule routed through the v2 compiler at runtime.",
            "    enabled: true",
            "    status: active",
            "    maturity: stable",
            "    severity: low",
            "    logsource:",
            "      event_type: ssh_auth",
            "    detection:",
            "      selection:",
            "        event.type: ssh_auth",
            "      condition: selection",
            "    aggregation:",
            "      type: threshold",
            "      window: 5m",
            "      group_by: [source.ip]",
            "      condition: {operator: \">=\", value: 10}",
            "    suppression: {}",
            "    tuning: {}",
            "    response: {}",
            "    tests: []",
        ],
    )

    feature_rules = load_detection_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=tmp_path,
        apply_env_filters=False,
        include_non_runtime=True,
    )
    worker_rules = load_worker_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=tmp_path,
        apply_env_filters=False,
    )

    feature_ids = {rule["id"] for rule in feature_rules}
    worker_ids = {rule["id"] for rule in worker_rules}
    assert feature_ids == {"ssh_count_v1", "ssh_count_v2"}
    # The worker loader now includes both v1 and v2 rules; v2 is executed via the v2 compiler.
    assert worker_ids == {"ssh_count_v1", "ssh_count_v2"}
    schema_versions = {int(rule["schema_version"]) for rule in worker_rules}
    assert schema_versions == {1, 2}


def test_existing_rules_still_load_successfully_with_validation_helper() -> None:
    report = load_and_validate_rules(
        rules_dir=_RULES_DIR,
        apply_env_filters=False,
        strict=False,
        include_non_runtime=True,
    )
    assert report["errors"] == []
    assert len(report["rules"]) >= 80
