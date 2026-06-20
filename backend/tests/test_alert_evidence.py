
from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from types import SimpleNamespace
from typing import Any

from app.features.alerts.evidence import (
    build_aggregate_evidence,
    build_distinct_evidence,
    build_multi_distinct_evidence,
    extract_evidence_specs,
)


def _alert(**kwargs) -> Any:
    defaults = dict(
        id=1,
        rule_id="test_rule_v1",
        src_ip=None,
        dst_ip=None,
        dst_port=None,
        description="Test alert",
        details={},
        detector_type=None,
        rule_version=None,
        rule_hash=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# --- build_aggregate_evidence ---

def test_aggregate_evidence_basic():
    items = build_aggregate_evidence(
        group_fields=["src_ip"],
        group_key={"src_ip": "1.2.3.4"},
        count=42,
        window_seconds=300,
    )
    assert len(items) == 1
    ev = items[0]
    assert ev["evidence_type"] == "aggregate"
    assert ev["evidence_role"] == "trigger"
    assert ev["entity_type"] == "src_ip"
    assert ev["entity_value"] == "1.2.3.4"
    assert ev["matched_field"] == "event_count"
    assert ev["matched_value"] == "42"
    assert "42 events" in ev["summary"]
    assert ev["raw_context"]["window_seconds"] == 300


def test_aggregate_evidence_multi_group():
    items = build_aggregate_evidence(
        group_fields=["src_ip", "dst_port"],
        group_key={"src_ip": "10.0.0.1", "dst_port": 22},
        count=100,
        window_seconds=600,
    )
    assert items[0]["entity_type"] == "src_ip"
    assert items[0]["entity_value"] == "10.0.0.1"
    assert items[0]["raw_context"]["group_by"] == ["src_ip", "dst_port"]


# --- build_distinct_evidence ---

def test_distinct_evidence_basic():
    items = build_distinct_evidence(
        group_fields=["src_ip"],
        group_key={"src_ip": "5.5.5.5"},
        distinct_field="dst_port",
        distinct_count=50,
        window_seconds=300,
    )
    assert len(items) == 1
    ev = items[0]
    assert ev["evidence_type"] == "distinct"
    assert ev["matched_field"] == "dst_port"
    assert ev["matched_value"] == "50"
    assert "distinct" in ev["summary"]
    assert ev["raw_context"]["distinct_field"] == "dst_port"


# --- build_multi_distinct_evidence ---

def test_multi_distinct_evidence():
    items = build_multi_distinct_evidence(
        group_fields=["src_ip"],
        group_key={"src_ip": "192.168.1.1"},
        distinct_results={"dst_port": 30, "dst_ip": 15},
        window_seconds=300,
    )
    assert len(items) == 2
    fields = {ev["matched_field"] for ev in items}
    assert fields == {"dst_port", "dst_ip"}
    for ev in items:
        assert ev["evidence_type"] == "distinct"
        assert ev["evidence_role"] == "trigger"


# --- extract_evidence_specs ---

def test_extract_aggregate_from_alert():
    alert = _alert(
        detector_type="rule",
        details={
            "type": "aggregate_count",
            "group_by": ["src_ip"],
            "group_key": {"src_ip": "1.1.1.1"},
            "count": 77,
            "window_seconds": 300,
        },
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["evidence_type"] == "aggregate"
    assert specs[0]["matched_value"] == "77"


def test_extract_distinct_from_alert():
    alert = _alert(
        detector_type="rule",
        details={
            "type": "distinct_count",
            "group_by": ["src_ip"],
            "group_key": {"src_ip": "2.2.2.2"},
            "distinct_field": "dst_port",
            "distinct_count": 25,
            "window_seconds": 300,
        },
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["evidence_type"] == "distinct"
    assert specs[0]["matched_field"] == "dst_port"
    assert specs[0]["matched_value"] == "25"


def test_extract_multi_distinct_from_alert():
    alert = _alert(
        detector_type="rule",
        details={
            "type": "multi_distinct",
            "group_by": ["src_ip"],
            "group_key": {"src_ip": "3.3.3.3"},
            "distinct": {"dst_port": 10, "dst_ip": 5},
            "window_seconds": 300,
        },
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 2
    assert all(s["evidence_type"] == "distinct" for s in specs)


def test_extract_heuristic():
    alert = _alert(
        src_ip="9.9.9.9",
        detector_type="heuristic",
        rule_id="beacon_heuristic_v1",
        details={"heuristic_name": "beacon", "reason": "Regular interval beaconing"},
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["evidence_type"] == "heuristic"
    assert specs[0]["entity_value"] == "9.9.9.9"
    assert specs[0]["matched_value"] == "beacon"


def test_extract_correlation():
    alert = _alert(
        dst_ip="10.0.0.1",
        detector_type="correlation",
        details={
            "type": "correlation",
            "correlated_rules": {"port_scan_pcap_v1": 3, "ssh_bruteforce_authlog_v2": 1},
        },
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["evidence_type"] == "correlation"
    assert "port_scan_pcap_v1" in (specs[0]["matched_value"] or "")


def test_extract_unknown_returns_empty():
    alert = _alert(detector_type="rule", details={})
    specs = extract_evidence_specs(alert)
    assert specs == []


# --- inline rule evidence ---

def test_inline_ssh_bruteforce():
    alert = _alert(
        rule_id="ssh_bruteforce_v1",
        src_ip="4.4.4.4",
        detector_type="inline",
        details={"event_count": 150, "time_window_minutes": 10, "min_events": 20},
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["entity_value"] == "4.4.4.4"
    assert specs[0]["matched_value"] == "150"
    assert "SSH" in specs[0]["summary"]


def test_inline_port_scan():
    alert = _alert(
        rule_id="port_scan_v1",
        src_ip="6.6.6.6",
        detector_type="inline",
        details={"distinct_ports": 80, "time_window_minutes": 10, "event_count": 200},
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["matched_field"] == "distinct_dst_ports"
    assert specs[0]["matched_value"] == "80"


def test_inline_horizontal_scan():
    alert = _alert(
        rule_id="horizontal_scan_v1",
        src_ip="7.7.7.7",
        dst_port=22,
        detector_type="inline",
        details={"distinct_targets": 30, "time_window_minutes": 10, "event_count": 90},
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["matched_field"] == "distinct_dst_ips"
    assert specs[0]["matched_value"] == "30"
    assert "port 22" in specs[0]["summary"]


def test_inline_new_host_src():
    alert = _alert(
        rule_id="new_host_seen_v1",
        src_ip="8.8.8.8",
        detector_type="inline",
        details={"role": "src", "first_seen": "2026-05-06T10:00:00", "event_count": 5},
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["entity_type"] == "src_ip"
    assert specs[0]["entity_value"] == "8.8.8.8"
    assert specs[0]["matched_field"] == "first_seen"


def test_inline_new_host_dst():
    alert = _alert(
        rule_id="new_host_seen_v1",
        dst_ip="8.8.4.4",
        detector_type="inline",
        details={"role": "dst", "first_seen": "2026-05-06T11:00:00", "event_count": 3},
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["entity_type"] == "dst_ip"
    assert specs[0]["entity_value"] == "8.8.4.4"


# --- v2 rule types map correctly ---

def test_extract_v2_threshold():
    alert = _alert(
        detector_type="rule",
        details={
            "schema_version": 2,
            "type": "threshold",
            "group_by": ["src_ip"],
            "group_key": {"src_ip": "11.11.11.11"},
            "count": 200,
            "window_seconds": 600,
        },
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["evidence_type"] == "aggregate"


def test_extract_v2_cardinality():
    alert = _alert(
        detector_type="rule",
        details={
            "schema_version": 2,
            "type": "cardinality",
            "group_by": ["src_ip"],
            "group_key": {"src_ip": "12.12.12.12"},
            "distinct_field": "dst_ip",
            "distinct_count": 40,
            "window_seconds": 300,
        },
    )
    specs = extract_evidence_specs(alert)
    assert len(specs) == 1
    assert specs[0]["evidence_type"] == "distinct"
    assert specs[0]["matched_field"] == "dst_ip"
