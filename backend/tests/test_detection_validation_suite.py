from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.detection_rule_harness import evaluate_rule, load_rule_index

_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def _ts(base: datetime, seconds: int) -> datetime:
    return base - timedelta(seconds=seconds)


def test_ssh_invalid_user_burst_positive_and_negative() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["ssh_invalid_user_burst_v1"]
    now = datetime.now(timezone.utc)

    positive_events = [
        {
            "agent_id": "agent-proc-1",
            "event_type": "ssh_auth",
            "timestamp": _ts(now, i * 5),
            "src_ip": "203.0.113.77",
            "dst_ip": "10.0.10.10",
            "dst_port": 22,
            "proto": "ssh",
            "bytes": 0,
            "extra": {
                "source": "auth.log",
                "action": "invalid_user",
                "username": "backup",
                "src_port": 51000 + i,
            },
        }
        for i in range(15)
    ]
    hits = evaluate_rule(rule, positive_events, now)
    assert len(hits) == 1

    negative_events = positive_events[:10]
    hits_neg = evaluate_rule(rule, negative_events, now)
    assert hits_neg == []


def test_admin_surface_horizontal_recon_rejects_ack_noise() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["admin_surface_horizontal_recon_v1"]
    now = datetime.now(timezone.utc)

    noisy_ack_events = [
        {
            "agent_id": "agent-scan-1",
            "event_type": "scan_probe",
            "timestamp": _ts(now, i),
            "src_ip": "198.51.100.10",
            "dst_ip": f"10.0.20.{(i % 12) + 1}",
            "src_port": 53000 + i,
            "dst_port": 3389,
            "proto": "tcp",
            "bytes": 80,
            "extra": {
                "scan_type": "tcp_ack",
                "scan_confidence": 90,
            },
        }
        for i in range(80)
    ]
    assert evaluate_rule(rule, noisy_ack_events, now) == []


def test_admin_surface_horizontal_recon_positive() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["admin_surface_horizontal_recon_v1"]
    now = datetime.now(timezone.utc)

    events = []
    for i in range(90):
        events.append(
            {
                "agent_id": "agent-scan-1",
                "event_type": "scan_probe",
                "timestamp": _ts(now, i * 2),
                "src_ip": "198.51.100.50",
                "dst_ip": f"10.10.0.{(i % 14) + 1}",
                "src_port": 55000 + i,
                "dst_port": 445 if i % 2 == 0 else 3389,
                "proto": "tcp",
                "bytes": 96,
                "extra": {
                    "scan_type": "tcp_syn",
                    "scan_confidence": 82,
                },
            }
        )

    hits = evaluate_rule(rule, events, now)
    assert len(hits) == 1
    assert hits[0]["distinct_count"] >= 10


def test_lateral_ssh_fanout_requires_confidence_and_volume() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["lateral_ssh_fanout_v1"]
    now = datetime.now(timezone.utc)

    low_conf_events = [
        {
            "agent_id": "agent-lateral",
            "event_type": "lateral_conn",
            "timestamp": _ts(now, i * 6),
            "src_ip": "10.30.1.8",
            "dst_ip": f"10.30.2.{(i % 8) + 1}",
            "src_port": 51000 + i,
            "dst_port": 22,
            "proto": "tcp",
            "bytes": 60,
            "extra": {
                "lateral_kind": "attempt",
                "lateral_confidence": 68,
            },
        }
        for i in range(30)
    ]
    assert evaluate_rule(rule, low_conf_events, now) == []

    positive_events = [
        {
            "agent_id": "agent-lateral",
            "event_type": "lateral_conn",
            "timestamp": _ts(now, i * 5),
            "src_ip": "10.30.1.8",
            "dst_ip": f"10.30.2.{(i % 9) + 1}",
            "src_port": 52000 + i,
            "dst_port": 22,
            "proto": "tcp",
            "bytes": 64,
            "extra": {
                "lateral_kind": "attempt",
                "lateral_confidence": 79,
            },
        }
        for i in range(30)
    ]
    hits = evaluate_rule(rule, positive_events, now)
    assert len(hits) == 1
    assert hits[0]["distinct_count"] >= 6


def test_ddos_vector_specific_and_generic_rule_separation() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    icmp_rule = rules["ddos_icmp_flood_high_conf_v1"]
    generic_ddos_rule = rules["ddos_attack_high_conf_v1"]
    now = datetime.now(timezone.utc)

    icmp_attack_events = [
        {
            "agent_id": "agent-ddos-1",
            "event_type": "dos_attack",
            "timestamp": _ts(now, 5),
            "dst_ip": "10.50.0.9",
            "dst_port": 0,
            "proto": "icmp",
            "bytes": 180000,
            "extra": {
                "attack": "ddos",
                "vector": "icmp_flood",
                "confidence": 86,
                "unique_src_ips": 36,
            },
        }
    ]

    assert len(evaluate_rule(icmp_rule, icmp_attack_events, now)) == 1
    # Generic rule should stay quiet for vectors covered by specific detectors.
    assert evaluate_rule(generic_ddos_rule, icmp_attack_events, now) == []


def test_ddos_scan_summary_fanout_positive() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["ddos_scan_summary_fanout_v1"]
    now = datetime.now(timezone.utc)

    events = [
        {
            "agent_id": "agent-core-1",
            "event_type": "scan_summary",
            "timestamp": _ts(now, i % 240),
            "src_ip": f"198.51.{i % 120}.{(i % 250) + 1}",
            "dst_ip": "187.127.13.82",
            "dst_port": None,
            "proto": "udp",
            "bytes": 64,
            "extra": {
                "total_probes": 8,
                "window_seconds": 1,
                "scan_class": "low",
            },
        }
        for i in range(1300)
    ]

    hits = evaluate_rule(rule, events, now)
    assert len(hits) == 1
    assert hits[0]["distinct_count"] >= 80


def test_dos_scan_summary_volume_positive() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["dos_scan_summary_volume_v1"]
    now = datetime.now(timezone.utc)

    events = [
        {
            "agent_id": "agent-core-1",
            "event_type": "scan_summary",
            "timestamp": _ts(now, i % 240),
            "src_ip": f"203.0.113.{(i % 20) + 1}",
            "dst_ip": "187.127.13.82",
            "dst_port": None,
            "proto": "udp",
            "bytes": 64,
            "extra": {
                "total_probes": 4,
                "window_seconds": 1,
                "scan_class": "low",
            },
        }
        for i in range(2600)
    ]

    hits = evaluate_rule(rule, events, now)
    assert len(hits) == 1
    assert hits[0]["count"] >= 2500
