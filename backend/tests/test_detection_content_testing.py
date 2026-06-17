from __future__ import annotations

import os
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from app.core.db import get_db
from app.features.auth.session import PortalPrincipal, require_admin
from app.features.detections import api as detections_api
from app.features.detections.rules.loader import load_and_validate_rules, load_rules
from app.features.detections.testing import run_detection_backtest, run_rule_yaml_tests, validate_detection_content
from app.features.events.models import NetEventModel
from app.main import app

_REPO_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def _base_rule_yaml(rule_id: str, extra: str = "") -> str:
    return f"""
    pack: core
    category: auth
    rules:
      - id: {rule_id}
        name: Simple SSH threshold
        description: Detect repeated failed SSH attempts.
        enabled: true
        severity: medium
        type: aggregate_count
        window: 5m
        cooldown: 10m
        match:
          event.type: ssh_auth
          destination.port: 22
          ssh.action: failed_password
        group_by: source.ip
        min_events: 2
        condition:
          operator: ">="
          value: 2
    {extra}
    """


def test_yaml_rule_tests_execute_positive_and_negative(tmp_path: Path) -> None:
    _write(
        tmp_path / "packs" / "core" / "rule.yml",
        _base_rule_yaml(
            "yaml_test_rule_v1",
            extra="""
        tests:
          - name: positive case
            expected: match
            events:
              - agent_id: agent-1
                event_type: ssh_auth
                timestamp: 2026-01-01T00:00:00Z
                src_ip: 198.51.100.10
                dst_ip: 10.0.0.10
                dst_port: 22
                extra:
                  action: failed_password
              - agent_id: agent-1
                event_type: ssh_auth
                timestamp: 2026-01-01T00:01:00Z
                src_ip: 198.51.100.10
                dst_ip: 10.0.0.10
                dst_port: 22
                extra:
                  action: failed_password
          - name: benign case
            expected: no_match
            events:
              - agent_id: agent-1
                event_type: ssh_auth
                timestamp: 2026-01-01T00:00:00Z
                src_ip: 198.51.100.11
                dst_ip: 10.0.0.10
                dst_port: 22
                extra:
                  action: failed_password
        """,
        ),
    )

    rules = load_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=tmp_path,
        apply_env_filters=False,
        include_non_runtime=True,
    )
    assert len(rules) == 1

    results = run_rule_yaml_tests(rules[0])
    assert len(results) == 2
    assert all(result["passed"] for result in results)

    report = validate_detection_content(rules_dir=tmp_path, execute_yaml_tests=True)
    assert report["passed"] is True
    assert report["yaml_test_count"] == 2
    assert report["yaml_failed_count"] == 0


def test_shipped_pack_rules_inline_yaml_tests_all_pass() -> None:
    report = load_and_validate_rules(
        include_disabled=True,
        rules_dir=str(_REPO_RULES_DIR),
        apply_env_filters=False,
        execute_yaml_tests=True,
    )
    assert report["errors"] == []
    assert report["inline_test_failures"] == []


def test_shipped_pack_rules_quality_requires_inline_tests() -> None:
    report = validate_detection_content(
        rules_dir=str(_REPO_RULES_DIR),
        include_disabled=True,
        apply_env_filters=False,
        execute_yaml_tests=True,
    )
    missing = [warning["rule_id"] for warning in report["warnings"] if warning["code"] == "missing_inline_tests"]
    assert missing == []
    assert report["inline_test_failures"] == []


def test_validate_detection_content_catches_bad_field(tmp_path: Path) -> None:
    _write(
        tmp_path / "packs" / "lab" / "invalid_field.yml",
        """
        pack: lab
        rules:
          - schema_version: 2
            id: invalid_field_v2
            name: Invalid field
            description: Invalid field should fail.
            enabled: true
            status: draft
            severity: low
            detection:
              selection:
                unsupported.field: value
            aggregation:
              type: threshold
              group_by:
                - source.ip
        """,
    )

    report = validate_detection_content(rules_dir=tmp_path)
    assert report["passed"] is False
    assert any("Unsupported detection field: unsupported.field" in error["message"] for error in report["errors"])


def test_validate_detection_content_catches_duplicate_rule_ids(tmp_path: Path) -> None:
    _write(tmp_path / "packs" / "core" / "a.yml", _base_rule_yaml("duplicate_rule_v1"))
    _write(tmp_path / "packs" / "network" / "b.yml", _base_rule_yaml("duplicate_rule_v1"))

    report = validate_detection_content(rules_dir=tmp_path)
    assert report["passed"] is False
    assert any("Duplicate rule id detected: duplicate_rule_v1" in error["message"] for error in report["errors"])


def test_validate_detection_content_catches_unsupported_operator(tmp_path: Path) -> None:
    _write(
        tmp_path / "packs" / "lab" / "invalid_operator.yml",
        """
        pack: lab
        rules:
          - schema_version: 2
            id: invalid_operator_v2
            name: Invalid operator
            description: Invalid operator should fail.
            enabled: true
            status: draft
            severity: low
            detection:
              selection:
                source.ip|regex: ^10
            aggregation:
              type: threshold
              group_by:
                - source.ip
        """,
    )

    report = validate_detection_content(rules_dir=tmp_path)
    assert report["passed"] is False
    assert any("Unsupported field operator: regex" in error["message"] for error in report["errors"])


def test_validate_detection_content_emits_quality_warnings(tmp_path: Path) -> None:
    _write(
        tmp_path / "packs" / "core" / "warnings.yml",
        """
        pack: core
        category: auth
        rules:
          - id: overlap_one_v1
            name: Overlap one
            description: Missing guidance by design.
            enabled: true
            severity: high
            type: aggregate_count
            window: 5m
            cooldown: 10m
            match:
              event.type: ssh_auth
              destination.port: 22
              ssh.action: failed_password
            group_by: source.ip
            min_events: 2
            condition:
              operator: ">="
              value: 2
          - id: overlap_two_v1
            name: Overlap two
            description: Missing guidance by design.
            enabled: true
            severity: high
            type: aggregate_count
            window: 5m
            cooldown: 10m
            match:
              event.type: ssh_auth
              destination.port: 22
              ssh.action: failed_password
            group_by: source.ip
            min_events: 5
            condition:
              operator: ">="
              value: 5
        """,
    )

    report = validate_detection_content(rules_dir=tmp_path)
    codes = {warning["code"] for warning in report["warnings"]}
    assert "missing_mitre_metadata" in codes
    assert "missing_response_guidance" in codes
    assert "missing_false_positive_guidance" in codes
    assert "suspicious_rule_overlap" in codes


class _FakeScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeDB:
    def __init__(self, rows=None):
        self._rows = list(rows or [])
        self.add_calls = 0
        self.commit_calls = 0
        self.close_calls = 0

    def execute(self, _stmt):
        return _FakeScalarResult(self._rows)

    def add(self, _obj):
        self.add_calls += 1

    def commit(self):
        self.commit_calls += 1

    def close(self):
        self.close_calls += 1


def test_run_detection_backtest_dry_run_creates_no_alerts(tmp_path: Path) -> None:
    _write(tmp_path / "packs" / "core" / "rule.yml", _base_rule_yaml("backtest_rule_v1"))

    started_at = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    rows = [
        NetEventModel(
            id=1,
            agent_id="agent-1",
            event_type="ssh_auth",
            schema_version=1,
            timestamp=started_at + timedelta(minutes=1),
            src_ip="198.51.100.20",
            dst_ip="10.0.0.10",
            dst_port=22,
            extra={"action": "failed_password"},
        ),
        NetEventModel(
            id=2,
            agent_id="agent-1",
            event_type="ssh_auth",
            schema_version=1,
            timestamp=started_at + timedelta(minutes=2),
            src_ip="198.51.100.20",
            dst_ip="10.0.0.10",
            dst_port=22,
            extra={"action": "failed_password"},
        ),
    ]
    db = _FakeDB(rows)

    result = run_detection_backtest(
        db,
        rule_id="backtest_rule_v1",
        started_at=started_at,
        ended_at=started_at + timedelta(minutes=10),
        limit=100,
        dry_run=True,
        rules_dir=tmp_path,
    )

    assert result["dry_run"] is True
    assert result["match_count"] == 1
    assert result["severity_distribution"] == {"medium": 1}
    assert db.add_calls == 0
    assert db.commit_calls == 0


def test_detections_endpoints_require_admin() -> None:
    def _deny():
        raise HTTPException(status_code=403, detail="Forbidden")

    app.dependency_overrides[require_admin] = _deny
    try:
        with TestClient(app) as client:
            validate_response = client.post("/detections/validate", json={})
            backtest_response = client.post(
                "/detections/backtest",
                json={
                    "rule_id": "x",
                    "started_at": "2026-01-01T00:00:00Z",
                    "ended_at": "2026-01-01T01:00:00Z",
                },
            )
        assert validate_response.status_code == 403
        assert backtest_response.status_code == 403
    finally:
        app.dependency_overrides.pop(require_admin, None)


def test_validate_endpoint_writes_audit_for_admin(monkeypatch) -> None:
    fake_db = _FakeDB()
    audit_calls: list[dict] = []

    app.dependency_overrides[get_db] = lambda: fake_db
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=1, username="root", role="admin")
    monkeypatch.setattr(
        detections_api,
        "validate_detection_content",
        lambda **_: {
            "passed": True,
            "rule_count": 1,
            "error_count": 0,
            "warning_count": 0,
            "yaml_failed_count": 0,
        },
    )
    monkeypatch.setattr(detections_api, "write_audit_event", lambda *_args, **kwargs: audit_calls.append(kwargs))

    try:
        with TestClient(app) as client:
            response = client.post("/detections/validate", json={})
        assert response.status_code == 200
        assert fake_db.commit_calls == 1
        assert audit_calls[0]["action"] == "detection.validate"
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(require_admin, None)
