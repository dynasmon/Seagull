from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.features.correlations.api import _segment_by_window, _stage_requirements_met
from app.workers.rules_engine import _evaluate_condition, _is_suppressed, _is_tuning_allowlisted, _normalize_dedup_key
from app.workers.rules_loader import load_rules
from app.core.config import settings


@dataclass
class _Alert:
    created_at: datetime
    rule_id: str = "r1"


def test_evaluate_condition_variants() -> None:
    assert _evaluate_condition(10, {"operator": ">=", "value": 5})
    assert _evaluate_condition(10, {"operator": ">", "value": 5})
    assert _evaluate_condition(10, {"operator": "<=", "value": 10})
    assert _evaluate_condition(10, {"operator": "==", "value": 10})
    assert _evaluate_condition(10, {"operator": "!=", "value": 9})


def test_normalize_dedup_key_rule_specific_behavior() -> None:
    assert _normalize_dedup_key("ddos_x", "1.1.1.1", "2.2.2.2", 80) == ("ddos_x", None, "2.2.2.2", 80)
    assert _normalize_dedup_key("ssh_bruteforce_x", "1.1.1.1", "2.2.2.2", 22) == (
        "ssh_bruteforce_x",
        "1.1.1.1",
        None,
        22,
    )


def test_segment_by_window_splits_on_window_limit() -> None:
    t0 = datetime(2026, 1, 1, 0, 0, 0)
    rows = [_Alert(t0), _Alert(t0 + timedelta(seconds=10)), _Alert(t0 + timedelta(seconds=70))]
    segs = _segment_by_window(rows, window_seconds=60)
    assert len(segs) == 2
    assert len(segs[0]) == 2
    assert len(segs[1]) == 1


def test_stage_requirements_met() -> None:
    hits = {"Recon": 2, "Credential": 1}
    stages = [{"name": "Recon", "min_count": 1}, {"name": "Credential", "min_count": 1}]
    assert _stage_requirements_met(hits, stages)


def test_load_rules_supports_packs_and_versioning(tmp_path) -> None:
    f = tmp_path / "packs" / "network" / "discovery.yml"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(
        "\n".join(
            [
                "schema_version: 1",
                "pack: network",
                "category: discovery",
                "pack_version: 2",
                "rules:",
                "  - id: tcp_scan_v3",
                "    name: TCP Scan",
                "    enabled: true",
                "    type: aggregate_count",
                "    group_by: src_ip",
                "    condition: {operator: '>=', value: 1}",
                "  - id: disabled_rule_v1",
                "    enabled: false",
                "    type: aggregate_count",
                "    group_by: src_ip",
                "    condition: {operator: '>=', value: 1}",
            ]
        ),
        encoding="utf-8",
    )

    rules = load_rules(include_disabled=False, with_source=True, rules_dir=tmp_path)
    assert len(rules) == 1
    r = rules[0]
    assert r["id"] == "tcp_scan_v3"
    assert r["pack"] == "network"
    assert r["category"] == "discovery"
    assert int(r["pack_version"]) == 2
    assert int(r["rule_version"]) == 3
    assert str(r["source_file"]).endswith("packs/network/discovery.yml")


def test_load_rules_duplicate_id_raises(tmp_path) -> None:
    a = tmp_path / "a.yml"
    b = tmp_path / "packs" / "x" / "b.yml"
    b.parent.mkdir(parents=True, exist_ok=True)
    a.write_text("rules:\n  - id: same_v1\n    enabled: true\n", encoding="utf-8")
    b.write_text("rules:\n  - id: same_v1\n    enabled: true\n", encoding="utf-8")

    try:
        load_rules(include_disabled=True, rules_dir=tmp_path)
        assert False, "expected duplicate rule id error"
    except RuntimeError as e:
        assert "Duplicate rule id" in str(e)


def test_rule_suppression_matching() -> None:
    rule = {
        "id": "ssh_bruteforce_v1",
        "suppressions": [
            {
                "reason": "trusted jump host",
                "until": "2099-01-01T00:00:00Z",
                "when": {"src_ip": "10.10.10.10", "dst_port": 22},
            }
        ],
    }
    now = datetime.utcnow()

    yes, why = _is_suppressed(rule, {"src_ip": "10.10.10.10", "dst_port": 22}, now)
    assert yes is True
    assert why == "trusted jump host"

    no, _ = _is_suppressed(rule, {"src_ip": "1.1.1.1", "dst_port": 22}, now)
    assert no is False


def test_rule_tuning_allowlist_matching() -> None:
    rule = {
        "id": "x_v1",
        "tuning": {
            "allowlist": {
                "src_cidrs": ["10.10.0.0/16"],
                "dst_ports": [22, 443],
            }
        },
    }
    yes, reason = _is_tuning_allowlisted(rule, {"src_ip": "10.10.1.5", "dst_port": 22})
    assert yes is True
    assert reason == "tuning.allowlist"

    no, _ = _is_tuning_allowlisted(rule, {"src_ip": "10.20.1.5", "dst_port": 22})
    assert no is False


def test_load_rules_pack_and_maturity_filters(tmp_path) -> None:
    f = tmp_path / "packs" / "lab" / "exp.yml"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(
        "\n".join(
            [
                "schema_version: 1",
                "pack: lab",
                "maturity: experimental",
                "environments: [dev, lab]",
                "rules:",
                "  - id: exp_rule_v1",
                "    enabled: true",
                "    type: aggregate_count",
                "    group_by: src_ip",
                "    condition: {operator: '>=', value: 1}",
            ]
        ),
        encoding="utf-8",
    )

    old_env = settings.NETWATCH_RULES_ENV
    old_enabled = list(settings.NETWATCH_RULES_ENABLED_PACKS)
    old_disabled = list(settings.NETWATCH_RULES_DISABLED_PACKS)
    old_experimental = settings.NETWATCH_RULES_INCLUDE_EXPERIMENTAL

    try:
        settings.NETWATCH_RULES_ENV = "dev"
        settings.NETWATCH_RULES_ENABLED_PACKS = ["lab"]
        settings.NETWATCH_RULES_DISABLED_PACKS = []
        settings.NETWATCH_RULES_INCLUDE_EXPERIMENTAL = False
        r0 = load_rules(include_disabled=True, with_source=True, rules_dir=tmp_path)
        assert r0 == []

        settings.NETWATCH_RULES_INCLUDE_EXPERIMENTAL = True
        r1 = load_rules(include_disabled=True, with_source=True, rules_dir=tmp_path)
        assert len(r1) == 1
        assert r1[0]["id"] == "exp_rule_v1"

        settings.NETWATCH_RULES_ENV = "prod"
        r2 = load_rules(include_disabled=True, with_source=True, rules_dir=tmp_path)
        assert r2 == []
    finally:
        settings.NETWATCH_RULES_ENV = old_env
        settings.NETWATCH_RULES_ENABLED_PACKS = old_enabled
        settings.NETWATCH_RULES_DISABLED_PACKS = old_disabled
        settings.NETWATCH_RULES_INCLUDE_EXPERIMENTAL = old_experimental
