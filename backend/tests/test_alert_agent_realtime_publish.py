from __future__ import annotations

import os
from datetime import datetime
from types import SimpleNamespace

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.agents import service as agents_service
from app.features.alerts import realtime as alerts_realtime
from app.features.response import realtime as response_realtime


def test_build_alert_realtime_payload_from_row_contract() -> None:
    row = SimpleNamespace(
        id=101,
        created_at=datetime(2026, 4, 9, 18, 0, 0),
        rule_id="ddos_tcp_flood_v1",
        severity="high",
        src_ip="192.0.2.10",
        dst_ip="198.51.100.5",
        dst_port=443,
        description="X" * 500,
        confidence=87,
    )

    payload = alerts_realtime.build_alert_realtime_payload_from_row(row)

    assert payload["alert_id"] == 101
    assert payload["rule_id"] == "ddos_tcp_flood_v1"
    assert payload["severity"] == "high"
    assert payload["src_ip"] == "192.0.2.10"
    assert payload["dst_ip"] == "198.51.100.5"
    assert payload["dst_port"] == 443
    assert len(payload["description"]) == 240
    assert payload["confidence"] == 87
    assert isinstance(payload["created_at"], str)
    assert "details" not in payload


def test_publish_alert_created_payload_uses_realtime_event(monkeypatch) -> None:
    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(alerts_realtime, "publish_realtime", lambda event_type, payload: emitted.append((event_type, payload)))

    alerts_realtime.publish_alert_created_payload({"alert_id": 7, "rule_id": "x", "severity": "low"})

    assert emitted == [
        (
            "ui.alerts.delta.patch",
            {
                "action": "upsert",
                "alert": {
                    "id": 7,
                    "rule_id": "x",
                    "severity": "low",
                },
                "counters": {"alerts_60m_delta": 1},
            },
        )
    ]


def test_publish_alert_updated_payload_uses_realtime_event(monkeypatch) -> None:
    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(alerts_realtime, "publish_realtime", lambda event_type, payload: emitted.append((event_type, payload)))

    alerts_realtime.publish_alert_updated_payload({"alert_id": 7, "status": "closed"})

    assert emitted == [
        (
            "ui.alerts.delta.patch",
            {
                "action": "patch",
                "alert": {
                    "id": 7,
                    "status": "closed",
                },
            },
        )
    ]


def test_build_agent_heartbeat_payload_contract() -> None:
    row = SimpleNamespace(
        agent_id="agent-core-1",
        last_seen_at=datetime(2026, 4, 9, 18, 30, 0),
        is_revoked=False,
    )

    payload = agents_service._build_agent_heartbeat_payload(row=row, status_text="ok")

    assert payload == {
        "agent_id": "agent-core-1",
        "status": "ok",
        "is_revoked": False,
        "last_seen_at": payload["last_seen_at"],
    }
    assert isinstance(payload["last_seen_at"], str)


def test_publish_agent_heartbeat_realtime_uses_event(monkeypatch) -> None:
    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(agents_service, "publish_realtime", lambda event_type, payload: emitted.append((event_type, payload)))
    row = SimpleNamespace(agent_id="agent-core-1", last_seen_at=datetime(2026, 4, 9, 18, 30, 0), is_revoked=False)

    agents_service._publish_agent_heartbeat_realtime(row=row, status_text="ok")

    assert emitted and emitted[0][0] == "ui.agents.presence.patch"
    assert emitted[0][1]["agent_id"] == "agent-core-1"
    assert emitted[0][1]["status"] == "ok"


def test_publish_response_action_lifecycle_uses_admin_workflow_event(monkeypatch) -> None:
    emitted: list[tuple[str, dict]] = []
    monkeypatch.setattr(response_realtime, "publish_realtime", lambda event_type, payload: emitted.append((event_type, payload)))

    action = SimpleNamespace(
        id=401,
        action_type="collect_triage_bundle",
        agent_id="agent-core-1",
        status="running",
        requested_by="alice",
        requested_at=datetime(2026, 4, 9, 18, 0, 0),
        delivered_at=datetime(2026, 4, 9, 18, 0, 5),
        started_at=datetime(2026, 4, 9, 18, 0, 10),
        finished_at=None,
        cancelled_at=None,
        cancelled_by=None,
        last_error=None,
        created_at=datetime(2026, 4, 9, 18, 0, 0),
        updated_at=datetime(2026, 4, 9, 18, 0, 30),
        expires_at=None,
    )
    result = SimpleNamespace(
        id=902,
        response_action_id=401,
        agent_id="agent-core-1",
        status="running",
        result_payload={"progress": {"percent": 55, "stage": "collecting", "message": "halfway"}},
        error=None,
        started_at=datetime(2026, 4, 9, 18, 0, 10),
        finished_at=None,
        created_at=datetime(2026, 4, 9, 18, 0, 11),
        updated_at=datetime(2026, 4, 9, 18, 0, 30),
    )

    response_realtime.publish_response_action_lifecycle(action=action, lifecycle_event="heartbeat", result=result)

    assert emitted == [
        (
            "ui.response_actions.lifecycle.patch",
            {
                "action_id": 401,
                "agent_id": "agent-core-1",
                "lifecycle_event": "heartbeat",
                "workflow": {
                    "id": 401,
                    "action_type": "collect_triage_bundle",
                    "agent_id": "agent-core-1",
                    "status": "running",
                    "requested_by": "alice",
                    "requested_at": "2026-04-09T18:00:00+00:00",
                    "delivered_at": "2026-04-09T18:00:05+00:00",
                    "started_at": "2026-04-09T18:00:10+00:00",
                    "created_at": "2026-04-09T18:00:00+00:00",
                    "updated_at": "2026-04-09T18:00:30+00:00",
                },
                "result": {
                    "id": 902,
                    "response_action_id": 401,
                    "agent_id": "agent-core-1",
                    "status": "running",
                    "started_at": "2026-04-09T18:00:10+00:00",
                    "created_at": "2026-04-09T18:00:11+00:00",
                    "updated_at": "2026-04-09T18:00:30+00:00",
                    "has_payload": True,
                    "payload_keys": ["progress"],
                    "progress": {"percent": 55, "stage": "collecting", "message": "halfway"},
                },
                "requires_reconcile": False,
            },
        )
    ]
