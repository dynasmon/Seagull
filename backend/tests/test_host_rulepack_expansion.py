from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.workers.intelligence.rules.tuning import _is_tuning_allowlisted, _resolve_tuning_eval
from tests.detection_rule_harness import evaluate_rule, load_rule_index


_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def _ts(base: datetime, seconds: int) -> datetime:
    return base - timedelta(seconds=seconds)


def _event(*, now: datetime, event_type: str, extra: dict, dst_port: int = 443, proto: str = "tcp") -> dict:
    return {
        "agent_id": "agent-host-a",
        "event_type": event_type,
        "timestamp": now,
        "src_ip": "10.10.10.8",
        "dst_ip": "203.0.113.25",
        "src_port": 54000,
        "dst_port": dst_port,
        "proto": proto,
        "bytes": 4096,
        "extra": extra,
    }


def test_persistence_cron_unprivileged_write_and_root_false_positive_control() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["persistence_cron_unprivileged_write_v1"]
    now = datetime.now(timezone.utc)

    suspicious = _event(
        now=now,
        event_type="persistence_cron",
        extra={
            "action": "modify",
            "path": "/etc/cron.d/db-sync",
            "path_category": "cron",
            "uid": 1001,
            "persistence_related": True,
        },
    )
    assert len(evaluate_rule(rule, [suspicious], now)) == 1

    benign_root = _event(
        now=now,
        event_type="persistence_cron",
        extra={
            "action": "modify",
            "path": "/etc/cron.d/system-maint",
            "path_category": "cron",
            "uid": 0,
            "persistence_related": True,
        },
    )
    assert evaluate_rule(rule, [benign_root], now) == []


def test_privilege_euid_root_pivot_exec_triggers() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["privilege_proc_euid_root_nonroot_uid_chain_v1"]
    now = datetime.now(timezone.utc)

    ev = _event(
        now=now,
        event_type="proc_exec",
        extra={
            "uid": 1000,
            "euid": 0,
            "exe_name": "python3",
            "parent_exe_name": "bash",
            "exec_pattern": "lolbin",
            "exec_patterns": ["lolbin", "interpreter"],
            "cmdline": "python3 -c 'import os;os.system(\"id\")'",
        },
    )
    assert len(evaluate_rule(rule, [ev], now)) == 1


def test_lotl_tmp_chmod_execute_chain_requires_tmp_path() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["lotl_tmp_chmod_execute_chain_v1"]
    now = datetime.now(timezone.utc)

    suspicious = _event(
        now=now,
        event_type="proc_exec",
        extra={
            "exe_name": "bash",
            "exec_pattern": "shell_spawn",
            "exec_patterns": ["shell_spawn"],
            "cmdline": "chmod +x /tmp/.svc && /tmp/.svc",
        },
    )
    assert len(evaluate_rule(rule, [suspicious], now)) == 1

    benign = _event(
        now=now,
        event_type="proc_exec",
        extra={
            "exe_name": "bash",
            "exec_pattern": "shell_spawn",
            "exec_patterns": ["shell_spawn"],
            "cmdline": "chmod +x /usr/local/bin/maint-helper",
        },
    )
    assert evaluate_rule(rule, [benign], now) == []


def test_defense_disable_security_services_command_triggers() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["defense_disable_security_services_cmd_v1"]
    now = datetime.now(timezone.utc)

    ev = _event(
        now=now,
        event_type="sudo_cmd",
        extra={
            "action": "sudo",
            "username": "ops",
            "target_user": "root",
            "command": "systemctl stop auditd",
        },
        dst_port=0,
        proto="sudo",
    )
    assert len(evaluate_rule(rule, [ev], now)) == 1


def test_service_nonroot_systemd_unit_change_triggers() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["service_systemd_unit_nonroot_change_v1"]
    now = datetime.now(timezone.utc)

    ev = _event(
        now=now,
        event_type="persistence_systemd",
        extra={
            "action": "modify",
            "path": "/etc/systemd/system/backup-sync.service",
            "path_category": "systemd_unit",
            "uid": 1002,
            "persistence_related": True,
        },
        proto="file",
    )
    assert len(evaluate_rule(rule, [ev], now)) == 1


def test_outbound_dns_app_on_non_dns_port_and_benign_dns_control() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["outbound_dns_app_on_non_dns_port_v1"]
    now = datetime.now(timezone.utc)

    suspicious = [
        _event(
            now=_ts(now, i * 8),
            event_type="l7_flow",
            extra={"flow_direction": "outbound_from_local", "app_proto": "dns"},
            dst_port=4444,
            proto="tcp",
        )
        for i in range(3)
    ]
    assert len(evaluate_rule(rule, suspicious, now)) == 1

    benign = [
        _event(
            now=_ts(now, i * 8),
            event_type="l7_flow",
            extra={"flow_direction": "outbound_from_local", "app_proto": "dns"},
            dst_port=53,
            proto="udp",
        )
        for i in range(4)
    ]
    assert evaluate_rule(rule, benign, now) == []


def test_outbound_contextual_rare_destination_event_triggers() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["outbound_contextual_rare_destination_v1"]
    now = datetime.now(timezone.utc)

    ev = _event(
        now=now,
        event_type="egress_anomaly",
        extra={
            "heuristic_name": "egress_contextual_anomaly",
            "reason_kind": "rare_destination_after_suspicious_exec",
            "confidence": 83,
            "recent_bytes": 4_194_304,
        },
        dst_port=8443,
    )
    assert len(evaluate_rule(rule, [ev], now)) == 1


def test_tuning_threshold_scopes_and_allowlist_scopes() -> None:
    rule = {
        "id": "x_v1",
        "tuning": {
            "threshold_scopes": [
                {
                    "name": "prod-web",
                    "when": {"environments": ["prod"], "host_roles": ["web"]},
                    "min_events": 4,
                    "condition": {"operator": ">=", "value": 4},
                    "cooldown": "30m",
                    "severity": "high",
                }
            ],
            "allowlist_scopes": [
                {
                    "name": "dev-jump",
                    "reason": "expected jump-host behavior",
                    "when": {"environments": ["dev"], "host_roles": ["jump"]},
                }
            ],
        },
    }

    prod_ctx = {
        "agent_id": "agent-a",
        "environment": "prod",
        "agent_environment": "prod",
        "host_role": "web",
        "agent_host_role": "web",
    }
    cfg = _resolve_tuning_eval(
        rule,
        ctx=prod_ctx,
        base_min_events=1,
        base_condition={"operator": ">=", "value": 1},
        base_cooldown_seconds=120,
        base_severity="medium",
    )
    assert int(cfg["min_events"]) == 4
    assert int(cfg["condition"]["value"]) == 4
    assert int(cfg["cooldown_seconds"]) == 1800
    assert str(cfg["severity"]) == "high"
    assert cfg["applied_scopes"] == ["prod-web"]

    allow_ctx = {
        "agent_id": "agent-b",
        "environment": "dev",
        "agent_environment": "dev",
        "host_role": "jump",
        "agent_host_role": "jump",
    }
    yes, reason = _is_tuning_allowlisted(rule, allow_ctx)
    assert yes is True
    assert reason == "expected jump-host behavior"


def test_false_positive_control_common_benign_admin_activity() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["privilege_sudo_sensitive_file_manipulation_v1"]
    now = datetime.now(timezone.utc)

    benign = _event(
        now=now,
        event_type="sudo_cmd",
        extra={
            "action": "sudo",
            "username": "admin",
            "target_user": "root",
            "command": "apt-get update",
        },
        dst_port=0,
        proto="sudo",
    )
    assert evaluate_rule(rule, [benign], now) == []
