
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)


from app.features.detections.rules.loader import load_and_validate_rules
from app.features.detections.rules.registry import SUPPORTED_RUNTIME_EVENT_FIELDS
from app.workers.intelligence.rules.loader import load_rules
from tests.detection_rule_harness import evaluate_rule, load_rule_index

_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ssh_event(*, now: datetime, action: str, username: str, src_ip: str = "1.2.3.4",
               dst_ip: str = "10.0.0.1", src_port: int = 54321) -> dict:
    return {
        "agent_id": "agent-a",
        "event_type": "ssh_auth",
        "timestamp": now,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": 22,
        "proto": "tcp",
        "bytes": 512,
        "extra": {
            "source": "auth.log",
            "action": action,
            "username": username,
            # src_port in extra mirrors the auth.log "from IP port PORT" extraction
            "src_port": src_port,
        },
    }


def _proc_event(*, now: datetime, exec_patterns: list[str], exe_name: str = "curl",
                parent_name: str = "sshd", agent_id: str = "agent-a") -> dict:
    return {
        "agent_id": agent_id,
        "event_type": "proc_exec",
        "timestamp": now,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "proto": None,
        "bytes": 0,
        "extra": {
            "exe_name": exe_name,
            "parent_exe_name": parent_name,
            "exec_patterns": exec_patterns,
            "exec_pattern": exec_patterns[0] if exec_patterns else None,
        },
    }


def _beacon_event(*, now: datetime, agent_id: str = "agent-a", dst_ip: str = "203.0.113.5",
                  dst_port: int = 443, heuristic_name: str = "beacon_periodic_outbound",
                  confidence: int = 75) -> dict:
    return {
        "agent_id": agent_id,
        "event_type": "beacon_suspect",
        "timestamp": now,
        "src_ip": None,
        "dst_ip": dst_ip,
        "src_port": None,
        "dst_port": dst_port,
        "proto": "tcp",
        "bytes": 256,
        "extra": {
            "heuristic_name": heuristic_name,
            "confidence": confidence,
        },
    }


# ---------------------------------------------------------------------------
# Duplicate-ID regression across all rules
# ---------------------------------------------------------------------------

def test_no_duplicate_rule_ids_in_rules_directory() -> None:
    result = load_and_validate_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=_RULES_DIR,
        apply_env_filters=False,
        strict=False,
    )
    errors = result.get("errors") or []
    duplicate_errors = [e for e in errors if "Duplicate" in str(e.get("message") or "")]
    assert duplicate_errors == [], f"Duplicate rule IDs found: {duplicate_errors}"


# ---------------------------------------------------------------------------
# Field-reference validation
# ---------------------------------------------------------------------------

def test_new_rules_group_by_fields_are_valid() -> None:
    rules = load_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=_RULES_DIR,
        apply_env_filters=False,
    )
    new_ids = {
        "ssh_password_spray_distinct_username_v1",
        "ssh_accepted_login_signal_v1",
        "proc_lolbin_exec_v1",
    }
    found = {r["id"] for r in rules if r.get("id") in new_ids}
    assert found == new_ids, f"Missing rules in load output: {new_ids - found}"

    for rule in rules:
        if rule.get("id") not in new_ids:
            continue
        group_by = rule.get("group_by")
        fields = [group_by] if isinstance(group_by, str) else list(group_by or [])
        for f in fields:
            assert f in SUPPORTED_RUNTIME_EVENT_FIELDS, (
                f"Rule {rule['id']}: group_by field '{f}' not in SUPPORTED_RUNTIME_EVENT_FIELDS"
            )
        distinct_field = rule.get("distinct_field")
        if distinct_field:
            assert distinct_field in SUPPORTED_RUNTIME_EVENT_FIELDS, (
                f"Rule {rule['id']}: distinct_field '{distinct_field}' not in SUPPORTED_RUNTIME_EVENT_FIELDS"
            )


# ---------------------------------------------------------------------------
# ssh_password_spray_distinct_username_v1
# ---------------------------------------------------------------------------

def test_ssh_spray_positive_many_distinct_usernames() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["ssh_password_spray_distinct_username_v1"]
    now = datetime.now(timezone.utc)

    events = [
        _ssh_event(now=now - timedelta(seconds=i * 10), action="failed_password",
                   username=f"user{i:02d}")
        for i in range(12)
    ]
    hits = evaluate_rule(rule, events, now)
    assert len(hits) == 1
    assert hits[0]["distinct_count"] >= 5


def test_ssh_spray_negative_same_username_repeated() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["ssh_password_spray_distinct_username_v1"]
    now = datetime.now(timezone.utc)

    events = [
        _ssh_event(now=now - timedelta(seconds=i * 5), action="failed_password",
                   username="root")
        for i in range(20)
    ]
    hits = evaluate_rule(rule, events, now)
    assert hits == [], "Rule should not fire when only one distinct username is tried"


def test_ssh_spray_negative_accepted_actions_excluded() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["ssh_password_spray_distinct_username_v1"]
    now = datetime.now(timezone.utc)

    events = [
        _ssh_event(now=now - timedelta(seconds=i * 8), action="accepted",
                   username=f"user{i:02d}")
        for i in range(10)
    ]
    hits = evaluate_rule(rule, events, now)
    assert hits == [], "Rule must not count accepted logins as spray events"


def test_ssh_spray_negative_low_port_source_excluded() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["ssh_password_spray_distinct_username_v1"]
    now = datetime.now(timezone.utc)

    events = [
        _ssh_event(now=now - timedelta(seconds=i * 10), action="failed_password",
                   username=f"user{i:02d}", src_port=22)
        for i in range(12)
    ]
    hits = evaluate_rule(rule, events, now)
    assert hits == [], "Rule must exclude low source ports (localhost/internal pivots)"


# ---------------------------------------------------------------------------
# ssh_accepted_login_signal_v1
# ---------------------------------------------------------------------------

def test_ssh_accepted_signal_positive() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["ssh_accepted_login_signal_v1"]
    now = datetime.now(timezone.utc)

    events = [_ssh_event(now=now, action="accepted", username="deploy", src_port=60000)]
    hits = evaluate_rule(rule, events, now)
    assert len(hits) == 1


def test_ssh_accepted_signal_negative_failed_not_accepted() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["ssh_accepted_login_signal_v1"]
    now = datetime.now(timezone.utc)

    events = [
        _ssh_event(now=now - timedelta(seconds=i * 5), action="failed_password",
                   username="root")
        for i in range(5)
    ]
    hits = evaluate_rule(rule, events, now)
    assert hits == [], "Rule must only fire on accepted logins, not failures"


def test_ssh_accepted_signal_is_low_severity() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["ssh_accepted_login_signal_v1"]
    assert rule.get("severity") == "low", (
        "accepted-login signal must be low severity to avoid masking higher-priority alerts"
    )


def test_ssh_spray_is_high_severity() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["ssh_password_spray_distinct_username_v1"]
    assert rule.get("severity") == "high"


# ---------------------------------------------------------------------------
# proc_lolbin_exec_v1
# ---------------------------------------------------------------------------

def test_proc_lolbin_positive() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["proc_lolbin_exec_v1"]
    now = datetime.now(timezone.utc)

    events = [
        _proc_event(now=now - timedelta(seconds=i * 15), exec_patterns=["lolbin"],
                    exe_name="curl", parent_name="sshd")
        for i in range(3)
    ]
    hits = evaluate_rule(rule, events, now)
    assert len(hits) == 1


def test_proc_lolbin_negative_different_pattern() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["proc_lolbin_exec_v1"]
    now = datetime.now(timezone.utc)

    events = [
        _proc_event(now=now - timedelta(seconds=i * 15), exec_patterns=["shell_spawn"],
                    exe_name="bash")
        for i in range(5)
    ]
    hits = evaluate_rule(rule, events, now)
    assert hits == [], "Rule must not fire on non-lolbin exec patterns"


def test_proc_lolbin_negative_threshold_requires_two_events() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["proc_lolbin_exec_v1"]
    now = datetime.now(timezone.utc)

    events = [_proc_event(now=now, exec_patterns=["lolbin"])]
    hits = evaluate_rule(rule, events, now)
    assert hits == [], "Single lolbin event should not exceed threshold of 2"


def test_proc_lolbin_does_not_overlap_with_remote_fetch_rule() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    lolbin_rule = rules["proc_lolbin_exec_v1"]
    remote_rule = rules["proc_remote_fetch_exec_v1"]

    lolbin_match = lolbin_rule.get("match", {})
    remote_match = remote_rule.get("match", {})

    lolbin_patterns = set(lolbin_match.get("extra_exec_pattern_in") or [])
    remote_patterns = set(remote_match.get("extra_exec_pattern_in") or [])

    overlap = lolbin_patterns & remote_patterns
    assert overlap == set(), (
        f"proc_lolbin_exec_v1 and proc_remote_fetch_exec_v1 share exec patterns {overlap}; "
        "they should be complementary, not duplicates"
    )


# ---------------------------------------------------------------------------
# beacon_suspect_heuristic_v1 refinement: heuristic_name filter
# ---------------------------------------------------------------------------

def test_beacon_heuristic_positive_with_correct_name() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["beacon_suspect_heuristic_v1"]
    now = datetime.now(timezone.utc)

    events = [_beacon_event(now=now, heuristic_name="beacon_periodic_outbound", confidence=70)]
    hits = evaluate_rule(rule, events, now)
    assert len(hits) == 1


def test_beacon_heuristic_negative_wrong_name() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["beacon_suspect_heuristic_v1"]
    now = datetime.now(timezone.utc)

    events = [_beacon_event(now=now, heuristic_name="some_other_heuristic", confidence=80)]
    hits = evaluate_rule(rule, events, now)
    assert hits == [], "heuristic_name filter should exclude non-beacon heuristic names"


def test_beacon_heuristic_negative_low_confidence() -> None:
    rules = load_rule_index(str(_RULES_DIR))
    rule = rules["beacon_suspect_heuristic_v1"]
    now = datetime.now(timezone.utc)

    events = [_beacon_event(now=now, heuristic_name="beacon_periodic_outbound", confidence=50)]
    hits = evaluate_rule(rule, events, now)
    assert hits == [], "Confidence below 65 should not fire the beacon rule"


# ---------------------------------------------------------------------------
# tls_ja4_on_http_port_v2: structural validation
# ---------------------------------------------------------------------------

def test_tls_ja4_v2_rule_loads_with_correct_schema_version() -> None:
    rules = load_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=_RULES_DIR,
        apply_env_filters=False,
    )
    rule = next((r for r in rules if r.get("id") == "tls_ja4_on_http_port_v2"), None)
    assert rule is not None, "tls_ja4_on_http_port_v2 must be present in the rule set"
    assert int(rule.get("schema_version") or 0) == 2, "tls_ja4_on_http_port_v2 must have schema_version 2"
    assert rule.get("enabled") is True
    assert rule.get("severity") == "high"


def test_tls_ja4_v2_rule_has_valid_detection_block() -> None:
    from app.features.detections.domain.condition_ast import DetectionBlock
    rules = load_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=_RULES_DIR,
        apply_env_filters=False,
    )
    rule = next((r for r in rules if r.get("id") == "tls_ja4_on_http_port_v2"), None)
    assert rule is not None
    detection = rule.get("detection")
    assert isinstance(detection, DetectionBlock), (
        "tls_ja4_on_http_port_v2 detection block must be parsed into a DetectionBlock object"
    )
    assert len(detection.selections) >= 1
    field_names = {p.runtime_field for s in detection.selections for p in s.predicates}
    assert "event_type" in field_names, "detection must filter on event_type"
    assert "ja4" in field_names, "detection must reference the ja4 fingerprint field"
    assert "dst_port" in field_names, "detection must filter on destination port"


def test_tls_ja4_v2_rule_aggregation_group_by_valid() -> None:
    rules = load_rules(
        include_disabled=True,
        with_source=True,
        rules_dir=_RULES_DIR,
        apply_env_filters=False,
    )
    rule = next((r for r in rules if r.get("id") == "tls_ja4_on_http_port_v2"), None)
    assert rule is not None
    agg = rule.get("aggregation") or {}
    group_by = agg.get("group_by") or []
    if isinstance(group_by, str):
        group_by = [group_by]
    for f in group_by:
        assert f in SUPPORTED_RUNTIME_EVENT_FIELDS, (
            f"tls_ja4_on_http_port_v2 group_by field '{f}' not in SUPPORTED_RUNTIME_EVENT_FIELDS"
        )


# ---------------------------------------------------------------------------
# Story file structural checks
# ---------------------------------------------------------------------------

def _load_story(name: str) -> dict:
    import yaml
    path = _RULES_DIR / "attack_stories" / name
    with open(path) as fh:
        return yaml.safe_load(fh)


def test_suspicious_exec_to_outbound_story_structure() -> None:
    story = _load_story("suspicious_exec_to_outbound_story.yml")
    assert story["id"] == "suspicious_exec_to_outbound_story"
    assert story["enabled"] is True
    stage_ids = {s["id"] for s in story["stages"]}
    assert "suspicious_execution" in stage_ids
    assert "outbound_control" in stage_ids
    outbound_stage = next(s for s in story["stages"] if s["id"] == "outbound_control")
    assert outbound_stage.get("after") == "suspicious_execution"


def test_recon_ddos_story_structure() -> None:
    story = _load_story("recon_ddos_story.yml")
    assert story["id"] == "recon_ddos_story"
    assert story["enabled"] is True
    stage_ids = {s["id"] for s in story["stages"]}
    assert "recon" in stage_ids
    assert "ddos_impact" in stage_ids
    ddos_stage = next(s for s in story["stages"] if s["id"] == "ddos_impact")
    assert ddos_stage.get("after") == "recon"


def test_exposure_exploitation_story_has_valid_rule_ids() -> None:
    story = _load_story("exposure_to_exploitation_story.yml")
    all_rules = load_rule_index(str(_RULES_DIR))
    for stage in story.get("stages") or []:
        for rule_id in stage.get("match", {}).get("rule_ids") or []:
            assert rule_id in all_rules, (
                f"exposure_to_exploitation_story references non-existent rule_id: '{rule_id}'"
            )


def test_suspicious_exec_story_rule_ids_exist() -> None:
    story = _load_story("suspicious_exec_to_outbound_story.yml")
    all_rules = load_rule_index(str(_RULES_DIR))
    for stage in story.get("stages") or []:
        for rule_id in stage.get("match", {}).get("rule_ids") or []:
            assert rule_id in all_rules, (
                f"suspicious_exec_to_outbound_story references non-existent rule_id: '{rule_id}'"
            )


def test_recon_ddos_story_rule_ids_exist() -> None:
    story = _load_story("recon_ddos_story.yml")
    all_rules = load_rule_index(str(_RULES_DIR))
    for stage in story.get("stages") or []:
        for rule_id in stage.get("match", {}).get("rule_ids") or []:
            assert rule_id in all_rules, (
                f"recon_ddos_story references non-existent rule_id: '{rule_id}'"
            )
