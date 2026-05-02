from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from app.core.config import settings
from app.features.alerts import rule_registry_runtime, rule_runtime
from app.features.detections.domain.canonical_fields import (
    UnsupportedCanonicalFieldError,
    canonical_field_names,
    resolve_canonical_field,
)
from app.features.detections.rules.loader import load_rules as load_detection_rules
from app.features.events.models import NetEventModel
from app.workers.intelligence.rules.loader import load_rules as load_worker_rules
from app.workers.manager import GROUPS


_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def test_existing_rules_still_load_from_current_runtime_and_feature_runtime() -> None:
    worker_rules = load_worker_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=_RULES_DIR,
        apply_env_filters=False,
    )
    feature_rules = load_detection_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=_RULES_DIR,
        apply_env_filters=False,
    )

    assert worker_rules
    assert worker_rules == feature_rules
    assert len(worker_rules) >= 80
    assert all(int(rule["schema_version"]) == 1 for rule in worker_rules)


def test_duplicate_rule_ids_still_fail(tmp_path: Path) -> None:
    tmp_root = tmp_path
    (tmp_root / "a.yml").write_text("rules:\n  - id: same_v1\n    enabled: true\n", encoding="utf-8")
    pack_dir = tmp_root / "packs" / "network"
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "b.yml").write_text("rules:\n  - id: same_v1\n    enabled: true\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Duplicate rule id detected: same_v1"):
        load_worker_rules(include_disabled=True, rules_dir=tmp_root)


def test_environment_overrides_still_work(tmp_path: Path) -> None:
    rule_file = tmp_path / "packs" / "network" / "override.yml"
    rule_file.parent.mkdir(parents=True, exist_ok=True)
    rule_file.write_text(
        "\n".join(
            [
                "schema_version: 1",
                "pack: network",
                "rules:",
                "  - id: env_override_rule_v1",
                "    enabled: true",
                "    severity: medium",
                "    type: aggregate_count",
                "    window: 5m",
                "    cooldown: 10m",
                "    match:",
                "      event.type: scan_probe",
                "      network.transport: tcp",
                "    group_by: source.ip",
                "    condition: {operator: '>=', value: 5}",
                "    env_overrides:",
                "      prod:",
                "        condition: {operator: '>=', value: 15}",
                "      dev:",
                "        condition: {operator: '>=', value: 3}",
            ]
        ),
        encoding="utf-8",
    )

    old_env = settings.SEAGULL_RULES_ENV
    old_enabled = list(settings.SEAGULL_RULES_ENABLED_PACKS)
    old_disabled = list(settings.SEAGULL_RULES_DISABLED_PACKS)
    old_experimental = settings.SEAGULL_RULES_INCLUDE_EXPERIMENTAL
    try:
        settings.SEAGULL_RULES_ENABLED_PACKS = ["network"]
        settings.SEAGULL_RULES_DISABLED_PACKS = []
        settings.SEAGULL_RULES_INCLUDE_EXPERIMENTAL = True

        settings.SEAGULL_RULES_ENV = "dev"
        dev_rules = load_worker_rules(include_disabled=True, with_source=True, rules_dir=tmp_path)
        assert len(dev_rules) == 1
        assert int(dev_rules[0]["condition"]["value"]) == 3
        assert dev_rules[0]["match"]["event_type"] == "scan_probe"
        assert dev_rules[0]["match"]["proto"] == "tcp"
        assert dev_rules[0]["group_by"] == "src_ip"

        settings.SEAGULL_RULES_ENV = "prod"
        prod_rules = load_worker_rules(include_disabled=True, with_source=True, rules_dir=tmp_path)
        assert len(prod_rules) == 1
        assert int(prod_rules[0]["condition"]["value"]) == 15
    finally:
        settings.SEAGULL_RULES_ENV = old_env
        settings.SEAGULL_RULES_ENABLED_PACKS = old_enabled
        settings.SEAGULL_RULES_DISABLED_PACKS = old_disabled
        settings.SEAGULL_RULES_INCLUDE_EXPERIMENTAL = old_experimental


def test_disabled_rules_respect_include_disabled(tmp_path: Path) -> None:
    rule_file = tmp_path / "packs" / "core" / "enabled.yml"
    rule_file.parent.mkdir(parents=True, exist_ok=True)
    rule_file.write_text(
        "\n".join(
            [
                "pack: core",
                "rules:",
                "  - id: enabled_rule_v1",
                "    enabled: true",
                "  - id: disabled_rule_v1",
                "    enabled: false",
            ]
        ),
        encoding="utf-8",
    )

    enabled_only = load_worker_rules(include_disabled=False, rules_dir=tmp_path, apply_env_filters=False)
    with_disabled = load_worker_rules(include_disabled=True, rules_dir=tmp_path, apply_env_filters=False)

    assert [rule["id"] for rule in enabled_only] == ["enabled_rule_v1"]
    assert [rule["id"] for rule in with_disabled] == ["disabled_rule_v1", "enabled_rule_v1"]


def test_canonical_field_map_resolves_supported_fields() -> None:
    expected = {
        "agent.id": "agent_id",
        "event.type": "event_type",
        "event.timestamp": "timestamp",
        "source.ip": "src_ip",
        "source.port": "src_port",
        "destination.ip": "dst_ip",
        "destination.port": "dst_port",
        "network.transport": "proto",
        "network.bytes": "bytes",
        "network.protocol": "app_proto",
        "network.protocol.reason": "app_proto_reason",
        "network.protocol.confidence_band": "app_proto_conf_band",
        "dns.question.name": "dns_qname",
        "http.request.host": "http_host",
        "http.request.method": "http_method",
        "tls.server_name": "tls_sni",
        "tls.alpn.first": "tls_alpn_first",
        "tls.ja3": "ja3",
        "tls.ja4": "ja4",
        "tls.ja4.ptype": "ja4_ptype",
        "ssh.action": "ssh_action",
        "user.name": "ssh_username",
        "process.pid": "proc_pid",
        "process.parent.pid": "proc_ppid",
        "process.name": "proc_name",
        "process.executable": "proc_exe",
        "process.parent.name": "proc_parent_name",
        "file.path": "fim_path",
        "file.category": "fim_category",
        "threat.heuristic.name": "heuristic_name",
        "threat.heuristic.confidence": "heuristic_confidence",
    }

    assert set(canonical_field_names()) == set(expected)
    for canonical_name, model_attr in expected.items():
        spec = resolve_canonical_field(canonical_name)
        assert spec.model_attr == model_attr
        assert spec.storage_kind == "column"
        assert hasattr(NetEventModel, model_attr)


def test_unsupported_canonical_field_fails_clearly() -> None:
    with pytest.raises(UnsupportedCanonicalFieldError, match="unsupported.field"):
        resolve_canonical_field("unsupported.field")


def test_alert_rule_runtime_imports_still_work() -> None:
    assert callable(rule_runtime.run_all_rules)
    assert callable(rule_runtime.load_baseline_rules)
    assert callable(rule_registry_runtime.load_baseline_rules)
    assert rule_runtime.run_all_rules.__module__ == "app.workers.intelligence.rules.engine"


def test_rules_runner_import_still_works() -> None:
    module = importlib.import_module("app.workers.intelligence.rules.runner")
    assert callable(module.main)


def test_worker_manager_groups_still_point_to_current_worker_modules() -> None:
    intelligence_modules = [child.module for child in GROUPS["intelligence"]]
    assert intelligence_modules == [
        "app.workers.intelligence.rules.runner",
        "app.workers.intelligence.ip_intel.main",
        "app.workers.intelligence.protocol.main",
        "app.workers.intelligence.attack_chain.main",
        "app.workers.intelligence.exposure.main",
    ]
