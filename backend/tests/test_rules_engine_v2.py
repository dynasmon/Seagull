"""Tests for v2 detection rule execution in the rules worker."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

import pytest

from app.features.detections.domain.condition_ast import parse_detection_block
from app.features.detections.domain.rule_types import V2_RULE_SCHEMA_VERSION
from app.features.detections.rules.compatibility import normalize_v1_rule_to_v2
from app.features.detections.rules.compiler import (
    _predicate_to_sqla,
    _v2_mitre_meta,
    _v2_resolve_params,
    _v2_suppressions,
    compile_detection_filters,
    execute_v2_rule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_v2_rule(
    rule_id: str = "test_v2_rule_v1",
    agg_type: str = "threshold",
    condition_value: int = 5,
    window: str = "5m",
    cooldown: str = "10m",
    severity: str = "medium",
    confidence: int = 75,
    group_by: List[str] | str = None,
    distinct_field: Optional[str] = None,
    distinct_conditions: Optional[List[Dict]] = None,
    detection_raw: Optional[Dict] = None,
    attack: Optional[Dict] = None,
    tuning: Optional[Dict] = None,
    suppressions: Optional[List] = None,
) -> Dict[str, Any]:
    if group_by is None:
        group_by = ["src_ip", "dst_ip"]
    if detection_raw is None:
        detection_raw = {
            "selection": {"event.type": "flow"},
            "condition": "selection",
        }
    if attack is None:
        attack = {
            "tactic": "discovery",
            "technique_id": "T1046",
            "technique": "Network Service Scanning",
            "confidence": confidence,
        }

    aggregation: Dict[str, Any] = {
        "type": agg_type,
        "window": window,
        "group_by": group_by,
        "condition": {"operator": ">=", "value": condition_value},
        "min_events": condition_value,
    }
    if distinct_field:
        aggregation["field"] = distinct_field
    if distinct_conditions:
        aggregation["distinct_conditions"] = distinct_conditions

    rule: Dict[str, Any] = {
        "schema_version": V2_RULE_SCHEMA_VERSION,
        "id": rule_id,
        "name": "Test V2 Rule",
        "description": "Test description",
        "enabled": True,
        "status": "active",
        "severity": severity,
        "confidence": confidence,
        "attack": attack,
        "detection": parse_detection_block(detection_raw),
        "aggregation": aggregation,
        "suppression": {"cooldown": cooldown, "rules": list(suppressions or [])},
        "tuning": dict(tuning or {}),
        "logsource": {"event_type": "flow"},
        "pack": "test",
        "category": "test",
        "rule_version": 1,
    }
    return rule


class _FakeRows:
    def __init__(self, rows: List):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeDB:
    def __init__(self, rows_sequence: List[List]):
        self._seq = list(rows_sequence)
        self._idx = 0

    def execute(self, _stmt):
        if self._idx >= len(self._seq):
            return _FakeRows([])
        rows = self._seq[self._idx]
        self._idx += 1
        return _FakeRows(rows)

    def add(self, obj):
        pass


def _row(**kwargs) -> SimpleNamespace:
    defaults = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "proto": "tcp",
        "count": 10,
        "distinct_count": 10,
        "event_count": 50,
        "d0": 10,
        "d1": 3,
    }
    defaults.update(kwargs)

    class _Mapping:
        def __init__(self, d):
            self._d = d

        def get(self, key):
            return self._d.get(key)

    ns = SimpleNamespace(**defaults)
    ns._mapping = _Mapping(defaults)
    return ns


# ---------------------------------------------------------------------------
# Unit tests: compiler helpers
# ---------------------------------------------------------------------------

def test_v2_mitre_meta_reads_attack_field():
    rule = {
        "attack": {
            "tactic": "lateral_movement",
            "technique_id": "T1021",
            "technique": "Remote Services",
            "confidence": 80,
        }
    }
    meta = _v2_mitre_meta(rule)
    assert meta["tactic"] == "lateral_movement"
    assert meta["technique_id"] == "T1021"
    assert meta["confidence"] == 80


def test_v2_mitre_meta_falls_back_to_mitre_key():
    rule = {
        "mitre": {
            "tactic": "impact",
            "technique_id": "T1498",
            "confidence": 85,
        }
    }
    meta = _v2_mitre_meta(rule)
    assert meta["tactic"] == "impact"


def test_v2_mitre_meta_empty_when_no_attack():
    meta = _v2_mitre_meta({"description": "no attack field"})
    assert meta == {}


def test_v2_resolve_params_reads_aggregation():
    rule = _make_v2_rule(window="2m", cooldown="5m", condition_value=10, severity="high")
    window, cooldown, condition, min_events, severity = _v2_resolve_params(rule)
    assert window == timedelta(minutes=2)
    assert cooldown == timedelta(minutes=5)
    assert condition == {"operator": ">=", "value": 10}
    assert min_events == 10
    assert severity == "high"


def test_v2_resolve_params_fallback_to_top_level():
    rule = _make_v2_rule()
    # Simulate DB override setting top-level window/cooldown
    rule["window"] = "1m"
    rule["cooldown"] = "3m"
    # Remove from aggregation/suppression to test fallback
    rule["aggregation"].pop("window", None)
    rule["suppression"].pop("cooldown", None)
    window, cooldown, *_ = _v2_resolve_params(rule)
    assert window == timedelta(minutes=1)
    assert cooldown == timedelta(minutes=3)


def test_v2_suppressions_reads_yaml_rules():
    rule = _make_v2_rule(suppressions=[{"reason": "test", "when": {"agent_id": "agent-1"}}])
    sups = _v2_suppressions(rule)
    assert len(sups) == 1
    assert sups[0]["reason"] == "test"


def test_v2_suppressions_prefers_db_suppressions():
    rule = _make_v2_rule(suppressions=[{"reason": "yaml"}])
    # Simulate apply_tuning_and_suppressions writing top-level suppressions
    rule["suppressions"] = [{"reason": "db", "when": {}}]
    sups = _v2_suppressions(rule)
    assert sups[0]["reason"] == "db"


# ---------------------------------------------------------------------------
# Unit tests: detection filter compilation
# ---------------------------------------------------------------------------

def test_compile_detection_filters_builds_timestamp_bounds():
    detection = parse_detection_block({
        "selection": {"event.type": "flow"},
        "condition": "selection",
    })
    since = datetime(2024, 1, 1, 0, 0, 0)
    until = datetime(2024, 1, 1, 0, 5, 0)
    filters = compile_detection_filters(detection, since, until)
    # Should have timestamp >= since, timestamp < until, and the event_type filter
    assert len(filters) == 3


def test_compile_detection_filters_and_condition():
    detection = parse_detection_block({
        "base": {"event.type": "ssh_auth"},
        "port_filter": {"destination.port": 22},
        "condition": "base and port_filter",
    })
    since = datetime(2024, 1, 1)
    until = datetime(2024, 1, 1, 0, 5)
    filters = compile_detection_filters(detection, since, until)
    # Timestamp bounds + AND(base, port_filter)
    assert len(filters) == 3


def test_compile_detection_filters_not_condition():
    detection = parse_detection_block({
        "selection": {"event.type": "flow"},
        "exclude": {"source.ip|in": ["10.0.0.1"]},
        "condition": "selection and not exclude",
    })
    since = datetime(2024, 1, 1)
    until = datetime(2024, 1, 1, 0, 5)
    filters = compile_detection_filters(detection, since, until)
    assert len(filters) == 3


def test_compile_detection_filters_one_of_pattern():
    detection = parse_detection_block({
        "sel_a": {"event.type": "flow"},
        "sel_b": {"event.type": "ssh_auth"},
        "condition": "1 of sel_*",
    })
    since = datetime(2024, 1, 1)
    until = datetime(2024, 1, 1, 0, 5)
    filters = compile_detection_filters(detection, since, until)
    assert len(filters) == 3


def test_compile_detection_filters_all_of_pattern():
    detection = parse_detection_block({
        "sel_a": {"event.type": "flow"},
        "sel_b": {"destination.port": 443},
        "condition": "all of sel_*",
    })
    since = datetime(2024, 1, 1)
    until = datetime(2024, 1, 1, 0, 5)
    filters = compile_detection_filters(detection, since, until)
    assert len(filters) == 3


# ---------------------------------------------------------------------------
# Unit tests: canonical field matching
# ---------------------------------------------------------------------------

def test_v2_canonical_field_destination_port():
    detection = parse_detection_block({
        "selection": {"destination.port": 22},
        "condition": "selection",
    })
    # Verify the predicate has the correct runtime_field
    sel = detection.selections[0]
    pred = sel.predicates[0]
    assert pred.runtime_field == "dst_port"
    assert pred.value == 22


def test_v2_canonical_field_source_ip():
    detection = parse_detection_block({
        "selection": {"source.ip|in": ["10.0.0.1", "10.0.0.2"]},
        "condition": "selection",
    })
    sel = detection.selections[0]
    pred = sel.predicates[0]
    assert pred.runtime_field == "src_ip"
    assert pred.operator == "in"


def test_v2_canonical_field_exists_operator():
    detection = parse_detection_block({
        "selection": {"user.name|exists": True},
        "condition": "selection",
    })
    sel = detection.selections[0]
    pred = sel.predicates[0]
    assert pred.runtime_field == "ssh_username"
    assert pred.operator == "exists"


# ---------------------------------------------------------------------------
# Integration tests: execute_v2_rule with fake DB
# ---------------------------------------------------------------------------

def _empty_recent_idx():
    return {}


def _empty_agent_ctx():
    return {}


def test_execute_v2_threshold_rule_fires_alert():
    rule = _make_v2_rule(agg_type="threshold", condition_value=5)
    now = datetime.utcnow()

    # DB returns one group row with count=10
    db_row = _row(src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=80, count=10)
    # _enrich_alert_ips does additional queries (for DDoS rules only; this isn't DDoS)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "test_v2_rule_v1"
    assert alert.severity == "medium"
    assert alert.details["schema_version"] == 2
    assert alert.details["type"] == "threshold"
    assert alert.details["count"] == 10


def test_execute_v2_threshold_rule_below_threshold_no_alert():
    rule = _make_v2_rule(agg_type="threshold", condition_value=20)
    now = datetime.utcnow()

    db_row = _row(src_ip="1.2.3.4", dst_ip="5.6.7.8", count=5)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert alerts == []


def test_execute_v2_cardinality_rule_fires_alert():
    rule = _make_v2_rule(
        agg_type="cardinality",
        distinct_field="dst_port",
        group_by=["src_ip"],
        condition_value=10,
    )
    now = datetime.utcnow()

    db_row = _row(src_ip="1.2.3.4", distinct_count=15, event_count=50)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert len(alerts) == 1
    assert alerts[0].details["type"] == "cardinality"
    assert alerts[0].details["distinct_count"] == 15
    assert alerts[0].details["distinct_field"] == "dst_port"


def test_execute_v2_cardinality_rule_below_threshold_no_alert():
    rule = _make_v2_rule(
        agg_type="cardinality",
        distinct_field="dst_port",
        group_by=["src_ip"],
        condition_value=20,
    )
    now = datetime.utcnow()

    db_row = _row(src_ip="1.2.3.4", distinct_count=5, event_count=30)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert alerts == []


def test_execute_v2_multi_cardinality_fires_alert():
    rule = _make_v2_rule(
        agg_type="multi_cardinality",
        group_by=["src_ip"],
        distinct_conditions=[
            {"field": "dst_ip", "operator": ">=", "value": 5},
            {"field": "dst_port", "operator": ">=", "value": 2},
        ],
    )
    now = datetime.utcnow()

    # d0=distinct dst_ip count, d1=distinct dst_port count
    db_row = _row(src_ip="1.2.3.4", event_count=30, d0=8, d1=3)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert len(alerts) == 1
    assert alerts[0].details["type"] == "multi_cardinality"
    assert alerts[0].details["distinct"]["dst_ip"] == 8
    assert alerts[0].details["distinct"]["dst_port"] == 3


def test_execute_v2_multi_cardinality_fails_one_condition_no_alert():
    rule = _make_v2_rule(
        agg_type="multi_cardinality",
        group_by=["src_ip"],
        distinct_conditions=[
            {"field": "dst_ip", "operator": ">=", "value": 5},
            {"field": "dst_port", "operator": ">=", "value": 2},
        ],
    )
    now = datetime.utcnow()

    # d0 passes (8>=5) but d1 fails (1<2)
    db_row = _row(src_ip="1.2.3.4", event_count=30, d0=8, d1=1)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert alerts == []


def test_execute_v2_rule_populates_mitre_fields():
    rule = _make_v2_rule(
        attack={
            "tactic": "lateral_movement",
            "technique_id": "T1021",
            "technique": "Remote Services",
            "confidence": 82,
        }
    )
    now = datetime.utcnow()
    db_row = _row(count=10)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.mitre_tactic == "lateral_movement"
    assert alert.mitre_technique_id == "T1021"
    assert alert.confidence == 82
    assert alert.details["mitre"]["tactic"] == "lateral_movement"


def test_execute_v2_rule_cooldown_prevents_duplicate():
    # group_by=["src_ip", "dst_ip"] so dst_port is None in the dedup key
    rule = _make_v2_rule(condition_value=5, group_by=["src_ip", "dst_ip"])
    now = datetime.utcnow()
    db_row = _row(src_ip="1.2.3.4", dst_ip="5.6.7.8", count=10)
    db = _FakeDB([[db_row]])

    # Prime the recent_idx with an entry that's within cooldown (dst_port=None)
    recent_idx = {
        ("test_v2_rule_v1", "1.2.3.4", "5.6.7.8", None): now - timedelta(seconds=30)
    }

    alerts = execute_v2_rule(db, rule, now, recent_idx, _empty_agent_ctx())
    assert alerts == []


def test_execute_v2_rule_cooldown_expired_allows_alert():
    rule = _make_v2_rule(condition_value=5, group_by=["src_ip", "dst_ip"])
    now = datetime.utcnow()
    db_row = _row(src_ip="1.2.3.4", dst_ip="5.6.7.8", count=10)
    db = _FakeDB([[db_row]])

    # Last alert was > cooldown (10m) ago
    recent_idx = {
        ("test_v2_rule_v1", "1.2.3.4", "5.6.7.8", None): now - timedelta(minutes=15)
    }

    alerts = execute_v2_rule(db, rule, now, recent_idx, _empty_agent_ctx())
    assert len(alerts) == 1


# ---------------------------------------------------------------------------
# Tests: v2 suppression
# ---------------------------------------------------------------------------

def test_execute_v2_suppression_blocks_alert():
    rule = _make_v2_rule(
        condition_value=5,
        suppressions=[
            {
                "reason": "Maintenance window",
                "when": {"src_ip": "1.2.3.4"},
            }
        ],
    )
    now = datetime.utcnow()
    db_row = _row(src_ip="1.2.3.4", dst_ip="5.6.7.8", count=10)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert alerts == []


def test_execute_v2_suppression_allows_non_matching_ip():
    rule = _make_v2_rule(
        condition_value=5,
        suppressions=[
            {
                "reason": "Known scanner",
                "when": {"src_ip": "10.10.10.10"},
            }
        ],
    )
    now = datetime.utcnow()
    db_row = _row(src_ip="1.2.3.4", dst_ip="5.6.7.8", count=10)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert len(alerts) == 1


# ---------------------------------------------------------------------------
# Tests: v2 tuning allowlist
# ---------------------------------------------------------------------------

def test_execute_v2_tuning_allowlist_suppresses():
    rule = _make_v2_rule(
        condition_value=5,
        tuning={
            "allowlist": {
                "src_ips": ["1.2.3.4"],
            }
        },
    )
    now = datetime.utcnow()
    db_row = _row(src_ip="1.2.3.4", count=10)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert alerts == []


def test_execute_v2_tuning_allowlist_allows_other_ips():
    rule = _make_v2_rule(
        condition_value=5,
        tuning={
            "allowlist": {
                "src_ips": ["10.10.10.10"],
            }
        },
    )
    now = datetime.utcnow()
    db_row = _row(src_ip="1.2.3.4", count=10)
    db = _FakeDB([[db_row]])

    alerts = execute_v2_rule(db, rule, now, _empty_recent_idx(), _empty_agent_ctx())
    assert len(alerts) == 1


# ---------------------------------------------------------------------------
# Tests: mixed v1 and v2 loading
# ---------------------------------------------------------------------------

def test_mixed_v1_and_v2_loading(tmp_path: Path) -> None:
    from app.features.detections.rules.loader import load_and_validate_rules

    pack_dir = tmp_path / "packs"
    pack_dir.mkdir(parents=True)

    v1_file = pack_dir / "v1_rules.yml"
    v1_file.write_text(
        "\n".join([
            "schema_version: 1",
            "pack: test",
            "category: v1",
            "rules:",
            "  - id: test_v1_rule_v1",
            "    name: V1 Rule",
            "    description: A v1 rule",
            "    enabled: true",
            "    severity: low",
            "    type: aggregate_count",
            "    window: 5m",
            "    cooldown: 10m",
            "    match:",
            "      event_type: flow",
            "    group_by: [src_ip]",
            "    condition:",
            "      operator: '>='",
            "      value: 10",
        ]),
        encoding="utf-8",
    )

    v2_file = pack_dir / "v2_rules.yml"
    v2_file.write_text(
        "\n".join([
            "schema_version: 2",
            "pack: test",
            "category: v2",
            "rules:",
            "  - schema_version: 2",
            "    id: test_v2_rule_v1",
            "    name: V2 Rule",
            "    description: A v2 rule",
            "    enabled: true",
            "    status: active",
            "    severity: medium",
            "    logsource:",
            "      event_type: flow",
            "    attack:",
            "      tactic: discovery",
            "      technique_id: T1046",
            "      confidence: 70",
            "    detection:",
            "      selection:",
            "        event.type: flow",
            "      condition: selection",
            "    aggregation:",
            "      type: threshold",
            "      window: 5m",
            "      group_by: [source.ip]",
            "      condition:",
            "        operator: '>='",
            "        value: 10",
            "    suppression:",
            "      cooldown: 10m",
            "    tuning: {}",
        ]),
        encoding="utf-8",
    )

    result = load_and_validate_rules(
        rules_dir=tmp_path,
        include_disabled=True,
        apply_env_filters=False,
        include_non_runtime=True,
    )
    rules = result["rules"]
    ids = {r["id"] for r in rules}
    assert "test_v1_rule_v1" in ids, "v1 rule should be loaded"
    assert "test_v2_rule_v1" in ids, "v2 rule should be loaded"
    assert not result["errors"], f"Unexpected errors: {result['errors']}"


def test_worker_loader_includes_v2_rules(tmp_path: Path) -> None:
    from app.workers.intelligence.rules.loader import load_rules

    v2_file = tmp_path / "packs" / "test_v2.yml"
    v2_file.parent.mkdir(parents=True)
    v2_file.write_text(
        "\n".join([
            "schema_version: 2",
            "pack: test",
            "category: v2",
            "rules:",
            "  - schema_version: 2",
            "    id: worker_v2_rule_v1",
            "    name: Worker V2",
            "    description: V2 rule for worker",
            "    enabled: true",
            "    status: active",
            "    severity: medium",
            "    logsource:",
            "      event_type: flow",
            "    attack:",
            "      tactic: discovery",
            "      confidence: 60",
            "    detection:",
            "      selection:",
            "        event.type: flow",
            "      condition: selection",
            "    aggregation:",
            "      type: threshold",
            "      window: 5m",
            "      group_by: [source.ip]",
            "      condition:",
            "        operator: '>='",
            "        value: 5",
            "    suppression:",
            "      cooldown: 10m",
            "    tuning: {}",
        ]),
        encoding="utf-8",
    )

    rules = load_rules(rules_dir=tmp_path, include_disabled=True, apply_env_filters=False)
    ids = {r["id"] for r in rules}
    assert "worker_v2_rule_v1" in ids


# ---------------------------------------------------------------------------
# Tests: v1 rules still pass
# ---------------------------------------------------------------------------

def test_v1_rules_still_load_and_validate(tmp_path: Path) -> None:
    from app.features.detections.rules.loader import load_and_validate_rules

    f = tmp_path / "packs" / "v1_test.yml"
    f.parent.mkdir(parents=True)
    f.write_text(
        "\n".join([
            "schema_version: 1",
            "pack: core",
            "category: auth",
            "rules:",
            "  - id: v1_compat_rule_v1",
            "    name: V1 compat",
            "    description: Still works",
            "    enabled: true",
            "    severity: high",
            "    type: distinct_count",
            "    window: 5m",
            "    cooldown: 15m",
            "    match:",
            "      event_type: ssh_auth",
            "      dst_port: 22",
            "    group_by: [src_ip]",
            "    distinct_field: dst_ip",
            "    condition:",
            "      operator: '>='",
            "      value: 5",
        ]),
        encoding="utf-8",
    )

    result = load_and_validate_rules(
        rules_dir=tmp_path,
        include_disabled=True,
        apply_env_filters=False,
    )
    assert not result["errors"]
    ids = {r["id"] for r in result["rules"]}
    assert "v1_compat_rule_v1" in ids


# ---------------------------------------------------------------------------
# Tests: runner still imports and runs
# ---------------------------------------------------------------------------

def test_runner_module_imports() -> None:
    from app.workers.intelligence.rules import runner  # noqa: F401
    assert hasattr(runner, "main")


def test_run_all_rules_function_importable() -> None:
    from app.features.alerts.rule_runtime import run_all_rules  # noqa: F401
    assert callable(run_all_rules)


# ---------------------------------------------------------------------------
# Tests: v2 lab pack loads correctly
# ---------------------------------------------------------------------------

def test_v2_lab_pack_loads(tmp_path: Path) -> None:
    from app.features.detections.rules.loader import load_and_validate_rules

    rules_dir = Path(__file__).resolve().parents[2] / "rules"
    if not rules_dir.exists():
        pytest.skip("rules directory not found")

    result = load_and_validate_rules(
        rules_dir=rules_dir,
        include_disabled=True,
        apply_env_filters=False,
        include_non_runtime=True,
    )
    ids = {r["id"] for r in result["rules"]}
    assert "v2_lab_ssh_threshold_v1" in ids
    assert "v2_lab_port_scan_cardinality_v1" in ids
    assert "v2_lab_lateral_multi_cardinality_v1" in ids
