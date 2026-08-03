from __future__ import annotations

import os
from datetime import datetime, timedelta

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

from app.features.alerts.models import AlertModel
from app.features.detections.pipeline.stages import build_alert_details
from app.features.detections.pipeline.types import AlertCandidate, AlertContext


def _context(*, group_key: dict, match_hints: dict) -> AlertContext:
    now = datetime(2026, 8, 3, 12, 0, 0)
    candidate = AlertCandidate(
        rule_id="sudo_root_command_burst_v1",
        rule={"id": "sudo_root_command_burst_v1"},
        group_key=group_key,
        match_hints=match_hints,
        count_value=12,
        min_events_check=10,
        since=now - timedelta(minutes=12),
        until=now,
        extra={"agg_type": "aggregate_count", "group_by": list(group_key), "window_seconds": 720},
    )
    return AlertContext(candidate=candidate)


def test_details_carry_agent_id_from_group_key():
    ctx = _context(group_key={"agent_id": "agent-core-1", "src_ip": "10.0.0.5"}, match_hints={})
    details = build_alert_details(ctx, mitre={})
    assert details["agent_id"] == "agent-core-1"


def test_details_carry_agent_id_from_match_hints():
    ctx = _context(group_key={"src_ip": "10.0.0.5"}, match_hints={"agent_id": "agent-edge-2"})
    details = build_alert_details(ctx, mitre={})
    assert details["agent_id"] == "agent-edge-2"


def test_details_omit_agent_id_when_alert_spans_the_fleet():
    ctx = _context(group_key={"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9"}, match_hints={})
    details = build_alert_details(ctx, mitre={})
    assert "agent_id" not in details


def test_alert_row_exposes_agent_id_from_details():
    assert AlertModel(details={"agent_id": " agent-core-1 "}).agent_id == "agent-core-1"
    assert AlertModel(details={}).agent_id is None
    assert AlertModel(details=None).agent_id is None
