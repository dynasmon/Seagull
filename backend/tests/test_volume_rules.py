from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from tests.detection_rule_harness import evaluate_rule, load_rule_index

# Programmatic coverage for catalog rules whose thresholds (min_events 10-2500)
# make a faithful positive impractical to express as inline YAML. Each rule is
# checked at three points: fires at threshold, stays quiet below threshold, and
# stays quiet when a discriminating predicate fails.

_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
_RULES = load_rule_index(str(_RULES_DIR))
_NOW = datetime.now(timezone.utc)
_TS = _NOW - timedelta(seconds=1)

_ADMIN_PORTS = [22, 135, 139, 445, 3389, 5985, 5986]


def _distinct_ip(prefix: str, index: int) -> str:
    return f"{prefix}.{index // 250}.{index % 250 + 1}"


def _scan_probe(
    *,
    src_ip: str = "198.51.100.7",
    dst_ip: str = "10.10.0.10",
    dst_port: int = 4444,
    proto: str = "tcp",
    src_port: int = 40000,
    scan_confidence: int = 85,
    scan_type: str = "connect",
) -> dict:
    return {
        "agent_id": "sensor-1",
        "event_type": "scan_probe",
        "timestamp": _TS,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "extra": {"scan_confidence": scan_confidence, "scan_type": scan_type},
    }


def _lateral_conn(
    *,
    src_ip: str = "10.20.0.5",
    dst_ip: str = "10.20.0.20",
    dst_port: int = 445,
    proto: str = "tcp",
    lateral_kind: str = "attempt",
    lateral_confidence: int = 80,
) -> dict:
    return {
        "agent_id": "sensor-1",
        "event_type": "lateral_conn",
        "timestamp": _TS,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "extra": {"lateral_kind": lateral_kind, "lateral_confidence": lateral_confidence},
    }


def _scan_summary(
    *,
    src_ip: str = "203.0.113.1",
    dst_ip: str = "10.30.0.9",
    proto: str = "tcp",
    total_probes: int = 50,
) -> dict:
    return {
        "agent_id": "sensor-1",
        "event_type": "scan_summary",
        "timestamp": _TS,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "extra": {"total_probes": total_probes},
    }


def _ssh_auth(
    *,
    src_ip: str = "198.51.100.7",
    dst_ip: str = "10.0.0.5",
    dst_port: int = 22,
    username: str = "root",
    action: str = "failed_password",
    source: str = "auth.log",
    src_port: int = 40000,
) -> dict:
    return {
        "agent_id": "sensor-1",
        "event_type": "ssh_auth",
        "timestamp": _TS,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "extra": {"source": source, "action": action, "username": username, "src_port": src_port},
    }


def _sudo_cmd(
    *,
    agent_id: str = "sensor-1",
    src_ip: str = "10.0.0.5",
    username: str = "alice",
    target_user: str = "root",
    action: str = "sudo",
    command: str = "systemctl status app",
) -> dict:
    return {
        "agent_id": agent_id,
        "event_type": "sudo_cmd",
        "timestamp": _TS,
        "src_ip": src_ip,
        "extra": {"action": action, "target_user": target_user, "username": username, "command": command},
    }


def _flow(
    *,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "203.0.113.9",
    dst_port: int = 4444,
    proto: str = "tcp",
    nbytes: int = 100,
) -> dict:
    return {
        "agent_id": "sensor-1",
        "event_type": "flow",
        "timestamp": _TS,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "bytes": nbytes,
    }


# network/scan.yml — vertical / spray scans

def test_tcp_vertical_port_scan_threshold() -> None:
    rule = _RULES["tcp_vertical_port_scan_v3"]
    fires = [_scan_probe(dst_port=1000 + i) for i in range(45)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_probe(dst_port=1000 + i) for i in range(30)]
    assert evaluate_rule(rule, below, _NOW) == []

    low_conf = [_scan_probe(dst_port=1000 + i, scan_confidence=50) for i in range(45)]
    assert evaluate_rule(rule, low_conf, _NOW) == []


def test_udp_vertical_port_scan_threshold() -> None:
    rule = _RULES["udp_vertical_port_scan_v2"]
    fires = [_scan_probe(dst_port=1000 + i, proto="udp", scan_confidence=60) for i in range(30)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_probe(dst_port=1000 + i, proto="udp", scan_confidence=60) for i in range(20)]
    assert evaluate_rule(rule, below, _NOW) == []

    wrong_proto = [_scan_probe(dst_port=1000 + i, proto="tcp", scan_confidence=60) for i in range(30)]
    assert evaluate_rule(rule, wrong_proto, _NOW) == []


def test_tcp_scan_spray_requires_port_diversity() -> None:
    rule = _RULES["tcp_scan_spray_v1"]
    fires = [_scan_probe(dst_port=2000 + i, src_port=40000 + i) for i in range(90)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_probe(dst_port=2000 + i, src_port=40000 + i) for i in range(50)]
    assert evaluate_rule(rule, below, _NOW) == []

    no_src_diversity = [_scan_probe(dst_port=2000 + i, src_port=40000) for i in range(90)]
    assert evaluate_rule(rule, no_src_diversity, _NOW) == []


# network/recon.yml — discovery sweeps

def test_admin_ports_vertical_recon_threshold() -> None:
    rule = _RULES["admin_ports_vertical_recon_v1"]
    fires = [_scan_probe(dst_port=_ADMIN_PORTS[i % len(_ADMIN_PORTS)]) for i in range(40)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_probe(dst_port=_ADMIN_PORTS[i % len(_ADMIN_PORTS)]) for i in range(20)]
    assert evaluate_rule(rule, below, _NOW) == []

    non_admin = [_scan_probe(dst_port=8080) for _ in range(40)]
    assert evaluate_rule(rule, non_admin, _NOW) == []


def test_admin_surface_horizontal_recon_threshold() -> None:
    rule = _RULES["admin_surface_horizontal_recon_v1"]
    fires = [_scan_probe(dst_ip=_distinct_ip("10.40", i), dst_port=445) for i in range(70)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_probe(dst_ip=_distinct_ip("10.40", i), dst_port=445) for i in range(40)]
    assert evaluate_rule(rule, below, _NOW) == []

    non_admin = [_scan_probe(dst_ip=_distinct_ip("10.40", i), dst_port=8080) for i in range(70)]
    assert evaluate_rule(rule, non_admin, _NOW) == []


def test_multi_protocol_scan_pattern_threshold() -> None:
    rule = _RULES["multi_protocol_scan_pattern_v1"]
    fires = [
        _scan_probe(dst_port=1000 + i, proto="tcp" if i % 2 == 0 else "udp", scan_confidence=80)
        for i in range(140)
    ]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_probe(dst_port=1000 + i, proto="tcp" if i % 2 == 0 else "udp") for i in range(100)]
    assert evaluate_rule(rule, below, _NOW) == []

    single_proto = [_scan_probe(dst_port=1000 + i, proto="tcp", scan_confidence=80) for i in range(140)]
    assert evaluate_rule(rule, single_proto, _NOW) == []


def test_high_rate_single_target_probe_threshold() -> None:
    rule = _RULES["high_rate_single_target_probe_v1"]
    fires = [_scan_probe(scan_confidence=80) for _ in range(280)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_probe(scan_confidence=80) for _ in range(200)]
    assert evaluate_rule(rule, below, _NOW) == []

    low_conf = [_scan_probe(scan_confidence=50) for _ in range(280)]
    assert evaluate_rule(rule, low_conf, _NOW) == []


def test_wide_ssh_recon_threshold() -> None:
    rule = _RULES["wide_ssh_recon_v1"]
    fires = [_scan_probe(dst_ip=_distinct_ip("10.41", i), dst_port=22, scan_confidence=80) for i in range(70)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_probe(dst_ip=_distinct_ip("10.41", i), dst_port=22, scan_confidence=80) for i in range(40)]
    assert evaluate_rule(rule, below, _NOW) == []

    non_ssh = [_scan_probe(dst_ip=_distinct_ip("10.41", i), dst_port=23, scan_confidence=80) for i in range(70)]
    assert evaluate_rule(rule, non_ssh, _NOW) == []


def test_icmp_sweep_recon_threshold() -> None:
    rule = _RULES["icmp_sweep_recon_v1"]
    fires = [_scan_probe(dst_ip=_distinct_ip("10.42", i), proto="icmp", scan_confidence=80) for i in range(40)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_probe(dst_ip=_distinct_ip("10.42", i), proto="icmp", scan_confidence=80) for i in range(20)]
    assert evaluate_rule(rule, below, _NOW) == []

    non_icmp = [_scan_probe(dst_ip=_distinct_ip("10.42", i), proto="tcp", scan_confidence=80) for i in range(40)]
    assert evaluate_rule(rule, non_icmp, _NOW) == []


# network/lateral.yml — lateral movement fan-out / pivots

def test_lateral_admin_spray_threshold() -> None:
    rule = _RULES["lateral_admin_spray_v1"]
    fires = [
        _lateral_conn(dst_ip=_distinct_ip("10.50", i), dst_port=_ADMIN_PORTS[i % len(_ADMIN_PORTS)])
        for i in range(26)
    ]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [
        _lateral_conn(dst_ip=_distinct_ip("10.50", i), dst_port=_ADMIN_PORTS[i % len(_ADMIN_PORTS)])
        for i in range(15)
    ]
    assert evaluate_rule(rule, below, _NOW) == []

    non_admin = [_lateral_conn(dst_ip=_distinct_ip("10.50", i), dst_port=8080) for i in range(26)]
    assert evaluate_rule(rule, non_admin, _NOW) == []


def test_lateral_rdp_burst_threshold() -> None:
    rule = _RULES["lateral_rdp_burst_v1"]
    fires = [_lateral_conn(dst_port=3389) for _ in range(14)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_lateral_conn(dst_port=3389) for _ in range(10)]
    assert evaluate_rule(rule, below, _NOW) == []

    non_rdp = [_lateral_conn(dst_port=22) for _ in range(14)]
    assert evaluate_rule(rule, non_rdp, _NOW) == []


def test_lateral_smb_fanout_threshold() -> None:
    rule = _RULES["lateral_smb_fanout_v1"]
    fires = [_lateral_conn(dst_ip=_distinct_ip("10.51", i), dst_port=445) for i in range(28)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_lateral_conn(dst_ip=_distinct_ip("10.51", i), dst_port=445) for i in range(15)]
    assert evaluate_rule(rule, below, _NOW) == []

    non_smb = [_lateral_conn(dst_ip=_distinct_ip("10.51", i), dst_port=22) for i in range(28)]
    assert evaluate_rule(rule, non_smb, _NOW) == []


def test_lateral_winrm_fanout_threshold() -> None:
    rule = _RULES["lateral_winrm_fanout_v1"]
    fires = [_lateral_conn(dst_ip=_distinct_ip("10.52", i), dst_port=5985) for i in range(20)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_lateral_conn(dst_ip=_distinct_ip("10.52", i), dst_port=5985) for i in range(12)]
    assert evaluate_rule(rule, below, _NOW) == []

    non_winrm = [_lateral_conn(dst_ip=_distinct_ip("10.52", i), dst_port=22) for i in range(20)]
    assert evaluate_rule(rule, non_winrm, _NOW) == []


def test_lateral_ssh_fanout_threshold() -> None:
    rule = _RULES["lateral_ssh_fanout_v1"]
    fires = [_lateral_conn(dst_ip=_distinct_ip("10.53", i), dst_port=22) for i in range(22)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_lateral_conn(dst_ip=_distinct_ip("10.53", i), dst_port=22) for i in range(12)]
    assert evaluate_rule(rule, below, _NOW) == []

    low_conf = [_lateral_conn(dst_ip=_distinct_ip("10.53", i), dst_port=22, lateral_confidence=50) for i in range(22)]
    assert evaluate_rule(rule, low_conf, _NOW) == []


def test_lateral_admin_multi_service_pivot_threshold() -> None:
    rule = _RULES["lateral_admin_multi_service_pivot_v1"]
    fires = [
        _lateral_conn(dst_ip=_distinct_ip("10.54", i % 10), dst_port=_ADMIN_PORTS[i % 5])
        for i in range(55)
    ]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [
        _lateral_conn(dst_ip=_distinct_ip("10.54", i % 10), dst_port=_ADMIN_PORTS[i % 5])
        for i in range(30)
    ]
    assert evaluate_rule(rule, below, _NOW) == []

    single_service = [_lateral_conn(dst_ip=_distinct_ip("10.54", i % 10), dst_port=445) for i in range(55)]
    assert evaluate_rule(rule, single_service, _NOW) == []


def test_lateral_rpc_netbios_combo_threshold() -> None:
    rule = _RULES["lateral_rpc_netbios_combo_v1"]
    fires = [
        _lateral_conn(dst_ip=_distinct_ip("10.55", i % 8), dst_port=135 if i % 2 == 0 else 139)
        for i in range(28)
    ]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [
        _lateral_conn(dst_ip=_distinct_ip("10.55", i % 8), dst_port=135 if i % 2 == 0 else 139)
        for i in range(15)
    ]
    assert evaluate_rule(rule, below, _NOW) == []

    single_port = [_lateral_conn(dst_ip=_distinct_ip("10.55", i % 8), dst_port=135) for i in range(28)]
    assert evaluate_rule(rule, single_port, _NOW) == []


# network/ddos.yml — probe-storm summaries

def test_ddos_scan_summary_fanout_threshold() -> None:
    rule = _RULES["ddos_scan_summary_fanout_v1"]
    fires = [_scan_summary(src_ip=_distinct_ip("203.0", i)) for i in range(1200)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_summary(src_ip=_distinct_ip("203.0", i)) for i in range(100)]
    assert evaluate_rule(rule, below, _NOW) == []

    no_probes = [_scan_summary(src_ip=_distinct_ip("203.0", i), total_probes=0) for i in range(5)]
    assert evaluate_rule(rule, no_probes, _NOW) == []


def test_dos_scan_summary_volume_threshold() -> None:
    rule = _RULES["dos_scan_summary_volume_v1"]
    fires = [_scan_summary(src_ip=_distinct_ip("203.1", i % 250)) for i in range(2500)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_summary(src_ip=_distinct_ip("203.1", i % 250)) for i in range(1000)]
    assert evaluate_rule(rule, below, _NOW) == []

    no_probes = [_scan_summary(total_probes=0) for _ in range(5)]
    assert evaluate_rule(rule, no_probes, _NOW) == []


# core/auth.yml + core/baseline.yml — SSH brute-force / spray / sudo bursts

def test_ssh_invalid_user_burst_threshold() -> None:
    rule = _RULES["ssh_invalid_user_burst_v1"]
    fires = [_ssh_auth(action="invalid_user") for _ in range(14)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_ssh_auth(action="invalid_user") for _ in range(10)]
    assert evaluate_rule(rule, below, _NOW) == []

    wrong_action = [_ssh_auth(action="failed_password") for _ in range(14)]
    assert evaluate_rule(rule, wrong_action, _NOW) == []


def test_ssh_distributed_bruteforce_target_threshold() -> None:
    rule = _RULES["ssh_distributed_bruteforce_target_v1"]
    fires = [_ssh_auth(src_ip=_distinct_ip("198.51", i)) for i in range(45)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_ssh_auth(src_ip=_distinct_ip("198.51", i)) for i in range(30)]
    assert evaluate_rule(rule, below, _NOW) == []

    wrong_port = [_ssh_auth(src_ip=_distinct_ip("198.51", i), dst_port=2222) for i in range(45)]
    assert evaluate_rule(rule, wrong_port, _NOW) == []


def test_ssh_failed_password_burst_target_threshold() -> None:
    rule = _RULES["ssh_failed_password_burst_target_v1"]
    fires = [_ssh_auth(action="failed_password") for _ in range(20)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_ssh_auth(action="failed_password") for _ in range(14)]
    assert evaluate_rule(rule, below, _NOW) == []

    accepted = [_ssh_auth(action="accepted") for _ in range(20)]
    assert evaluate_rule(rule, accepted, _NOW) == []


def test_ssh_single_source_multi_target_fail_threshold() -> None:
    rule = _RULES["ssh_single_source_multi_target_fail_v1"]
    fires = [_ssh_auth(dst_ip=_distinct_ip("10.60", i)) for i in range(50)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_ssh_auth(dst_ip=_distinct_ip("10.60", i)) for i in range(30)]
    assert evaluate_rule(rule, below, _NOW) == []

    wrong_source = [_ssh_auth(dst_ip=_distinct_ip("10.60", i), source="syslog") for i in range(50)]
    assert evaluate_rule(rule, wrong_source, _NOW) == []


def test_sudo_root_command_burst_threshold() -> None:
    rule = _RULES["sudo_root_command_burst_v1"]
    fires = [_sudo_cmd() for _ in range(10)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_sudo_cmd() for _ in range(5)]
    assert evaluate_rule(rule, below, _NOW) == []

    root_invoked = [_sudo_cmd(username="root") for _ in range(10)]
    assert evaluate_rule(rule, root_invoked, _NOW) == []


def test_ssh_password_spray_distinct_username_threshold() -> None:
    rule = _RULES["ssh_password_spray_distinct_username_v1"]
    fires = [_ssh_auth(username=f"user{i}") for i in range(12)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_ssh_auth(username=f"user{i}") for i in range(8)]
    assert evaluate_rule(rule, below, _NOW) == []

    accepted = [_ssh_auth(username=f"user{i}", action="accepted") for i in range(12)]
    assert evaluate_rule(rule, accepted, _NOW) == []


def test_ssh_bruteforce_authlog_fast_detector_threshold() -> None:
    rule = _RULES["ssh_bruteforce_authlog_v2"]
    fires = [_ssh_auth(action="failed_password") for _ in range(10)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_ssh_auth(action="failed_password") for _ in range(6)]
    assert evaluate_rule(rule, below, _NOW) == []

    wrong_port = [_ssh_auth(action="failed_password", dst_port=2222) for _ in range(10)]
    assert evaluate_rule(rule, wrong_port, _NOW) == []


# lab/experimental.yml — experimental behavior candidates (volume)

def test_beaconing_fixed_tuple_candidate_threshold() -> None:
    rule = _RULES["beaconing_fixed_tuple_candidate_v1"]
    fires = [_flow(nbytes=100) for _ in range(140)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_flow(nbytes=100) for _ in range(100)]
    assert evaluate_rule(rule, below, _NOW) == []

    large_flows = [_flow(nbytes=5000) for _ in range(140)]
    assert evaluate_rule(rule, large_flows, _NOW) == []


def test_egress_high_volume_candidate_threshold() -> None:
    rule = _RULES["egress_high_volume_candidate_v1"]
    fires = [_flow(nbytes=5_000_000) for _ in range(10)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_flow(nbytes=5_000_000) for _ in range(6)]
    assert evaluate_rule(rule, below, _NOW) == []

    small_flows = [_flow(nbytes=1000) for _ in range(10)]
    assert evaluate_rule(rule, small_flows, _NOW) == []


def test_dns_tunnel_candidate_threshold() -> None:
    rule = _RULES["dns_tunnel_candidate_v1"]
    fires = [_flow(proto="udp", dst_port=53, nbytes=100) for _ in range(260)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_flow(proto="udp", dst_port=53, nbytes=100) for _ in range(100)]
    assert evaluate_rule(rule, below, _NOW) == []

    large_flows = [_flow(proto="udp", dst_port=53, nbytes=5000) for _ in range(260)]
    assert evaluate_rule(rule, large_flows, _NOW) == []


def test_low_and_slow_port_scan_candidate_threshold() -> None:
    rule = _RULES["low_and_slow_port_scan_candidate_v1"]
    fires = [_scan_probe(dst_port=1000 + i, scan_confidence=70) for i in range(30)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_scan_probe(dst_port=1000 + i, scan_confidence=70) for i in range(20)]
    assert evaluate_rule(rule, below, _NOW) == []

    low_conf = [_scan_probe(dst_port=1000 + i, scan_confidence=50) for i in range(30)]
    assert evaluate_rule(rule, low_conf, _NOW) == []


def test_rpc_fanout_candidate_threshold() -> None:
    rule = _RULES["rpc_fanout_candidate_v1"]
    fires = [_lateral_conn(dst_ip=_distinct_ip("10.61", i), dst_port=135, lateral_confidence=70) for i in range(20)]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [_lateral_conn(dst_ip=_distinct_ip("10.61", i), dst_port=135, lateral_confidence=70) for i in range(12)]
    assert evaluate_rule(rule, below, _NOW) == []

    wrong_port = [_lateral_conn(dst_ip=_distinct_ip("10.61", i), dst_port=22, lateral_confidence=70) for i in range(20)]
    assert evaluate_rule(rule, wrong_port, _NOW) == []


def test_smb_ssh_combo_pivot_candidate_threshold() -> None:
    rule = _RULES["smb_ssh_combo_pivot_candidate_v1"]
    fires = [
        _lateral_conn(dst_ip=_distinct_ip("10.62", i % 10), dst_port=22 if i % 2 == 0 else 445, lateral_confidence=70)
        for i in range(25)
    ]
    assert len(evaluate_rule(rule, fires, _NOW)) == 1

    below = [
        _lateral_conn(dst_ip=_distinct_ip("10.62", i % 10), dst_port=22 if i % 2 == 0 else 445, lateral_confidence=70)
        for i in range(15)
    ]
    assert evaluate_rule(rule, below, _NOW) == []

    single_port = [_lateral_conn(dst_ip=_distinct_ip("10.62", i % 10), dst_port=445, lateral_confidence=70) for i in range(25)]
    assert evaluate_rule(rule, single_port, _NOW) == []
