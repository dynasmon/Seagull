from __future__ import annotations

import os

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.features.events import api as events_api


def test_row_to_event_safe_parses_string_timestamp_and_json_extra() -> None:
    row = {
        "id": "42",
        "agent_id": "agent-core-1",
        "event_type": "ssh_auth",
        "schema_version": 1,
        "timestamp": "2026-03-22T18:02:24.594168062Z",
        "src_ip": "203.0.113.10",
        "dst_ip": "192.0.2.10",
        "src_port": 45678,
        "dst_port": 22,
        "proto": "tcp",
        "bytes": 0,
        "extra": '{"action":"failed_password","username":"root"}',
    }

    ev = events_api._row_to_event_safe(row)

    assert ev is not None
    assert ev.id == 42
    assert ev.agent_id == "agent-core-1"
    assert ev.event_type == "ssh_auth"
    assert ev.extra.get("action") == "failed_password"
    assert ev.extra.get("username") == "root"


def test_strip_large_extra_caps_value_size() -> None:
    huge = "x" * 6000
    out = events_api._strip_large_extra({"raw_message": huge})
    assert isinstance(out, dict)
    assert len(out["raw_message"]) == 4096

