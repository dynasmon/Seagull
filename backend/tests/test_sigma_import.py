from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

import yaml

import pytest

from app.features.detections.domain.validation import DetectionRuleValidationError
from app.features.detections.rules.sigma_import import (
    build_sigma_import_pack_document,
    import_sigma_rule_document,
)
from app.features.detections.testing import validate_detection_content


def _compatible_sigma_rule() -> dict:
    return {
        "title": "SSH Password Guessing",
        "description": "Detect repeated failed SSH authentication attempts.",
        "status": "stable",
        "level": "high",
        "tags": ["attack.credential_access", "attack.t1110.001", "network"],
        "references": ["https://example.invalid/sigma/ssh-password-guessing"],
        "falsepositives": ["Approved jump hosts and lab scanners."],
        "logsource": {
            "product": "linux",
            "service": "sshd",
            "category": "authentication",
        },
        "detection": {
            "selection": {
                "event.type": "ssh_auth",
                "DestinationPort": 22,
                "SshAction": "failed_password",
            },
            "condition": "selection",
            "timeframe": "15m",
        },
    }


def _write_yaml(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=False), encoding="utf-8")


def test_compatible_sigma_import() -> None:
    result = import_sigma_rule_document(_compatible_sigma_rule())
    rule = result["rule"]

    assert result["warnings"] == []
    assert rule["schema_version"] == 2
    assert rule["id"] == "ssh_password_guessing_v1"
    assert rule["name"] == "SSH Password Guessing"
    assert rule["enabled"] is False
    assert rule["status"] == "disabled"
    assert rule["maturity"] == "experimental"
    assert rule["severity"] == "high"
    assert rule["aggregation"]["window"] == "15m"
    assert rule["response"]["false_positives"] == ["Approved jump hosts and lab scanners."]
    assert rule["tags"] == ["attack.credential_access", "attack.t1110.001", "network"]
    assert rule["references"] == ["https://example.invalid/sigma/ssh-password-guessing"]
    assert rule["detection"]["selection"] == {
        "event.type": "ssh_auth",
        "destination.port": 22,
        "ssh.action": "failed_password",
    }


def test_unsupported_field_warning() -> None:
    sigma_rule = _compatible_sigma_rule()
    sigma_rule["detection"]["selection"] = {
        "event.type": "proc_exec",
        "CommandLine|contains": "whoami",
    }

    result = import_sigma_rule_document(sigma_rule)
    warnings = result["warnings"]
    rule = result["rule"]

    assert any(warning["code"] == "unsupported_detection_field" for warning in warnings)
    assert rule["detection"]["selection"] == {
        "event.type": "__seagull_sigma_import_blocked__:selection",
    }


def test_unsupported_operator_warning() -> None:
    sigma_rule = _compatible_sigma_rule()
    sigma_rule["detection"]["selection"] = {
        "event.type": "ssh_auth",
        "source.ip|cidr": "10.0.0.0/8",
    }

    result = import_sigma_rule_document(sigma_rule)

    assert any(warning["code"] == "unsupported_detection_operator" for warning in result["warnings"])
    assert result["rule"]["detection"]["selection"] == {
        "event.type": "__seagull_sigma_import_blocked__:selection",
    }


def test_attack_tag_mapping() -> None:
    result = import_sigma_rule_document(_compatible_sigma_rule())
    attack = result["rule"]["attack"]

    assert attack["tactic"] == "credential_access"
    assert attack["technique_id"] == "T1110.001"
    assert attack["technique"] == "Password Guessing"


def test_strict_mode_rejects_unsupported_content() -> None:
    sigma_rule = _compatible_sigma_rule()
    sigma_rule["detection"]["selection"] = {
        "event.type": "ssh_auth",
        "source.ip|cidr": "10.0.0.0/8",
    }

    with pytest.raises(DetectionRuleValidationError):
        import_sigma_rule_document(sigma_rule, strict=True)


def test_generated_seagull_v2_validation(tmp_path: Path) -> None:
    result = import_sigma_rule_document(_compatible_sigma_rule())
    pack_document = build_sigma_import_pack_document(result["rule"], pack="sigma", category="imports")
    output_file = tmp_path / "packs" / "sigma" / "ssh_password_guessing.yml"

    _write_yaml(output_file, pack_document)
    report = validate_detection_content(rules_dir=tmp_path, execute_yaml_tests=False)

    assert report["passed"] is True
    assert report["error_count"] == 0
    assert report["rule_count"] == 1
