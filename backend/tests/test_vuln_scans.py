import os
from datetime import datetime, timezone
from types import SimpleNamespace

import sqlalchemy

os.environ.setdefault("SEAGULL_DB_URL", "sqlite+pysqlite:///:memory:")
sqlalchemy.create_engine = lambda *args, **kwargs: SimpleNamespace()

from app.features.vuln.models import VulnScanModel
from app.features.vuln.scans import trigger_manual_scan
from app.features.vuln.schemas import VulnManualScanIn


def _base_scan(**overrides):
    now = datetime(2026, 4, 22, 12, 0, tzinfo=timezone.utc)
    data = {
        "id": 7,
        "scan_uuid": "11111111-1111-1111-1111-111111111111",
        "request_token": "22222222-2222-2222-2222-222222222222",
        "reporter_agent_id": "agent-1",
        "target": "agent:agent-1",
        "tool": "osv-wazuh-like",
        "tool_version": "1",
        "status": "queued",
        "lifecycle_state": "queued",
        "current_phase": "queued",
        "queued_at": now,
        "acknowledged_at": None,
        "started_at": None,
        "finished_at": None,
        "last_progress_at": now,
        "trigger_source": "manual",
        "error_summary": None,
        "scope": {"type": "manual_trigger", "manual_trigger": True, "request_token": "22222222-2222-2222-2222-222222222222"},
        "config": {"manual_trigger": True, "scan_now_token": "22222222-2222-2222-2222-222222222222"},
        "stats": {},
        "phase_timestamps": {"queued": now.isoformat()},
        "updated_at": now,
        "created_at": now,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_trigger_manual_scan_separates_request_token_from_scan_uuid(monkeypatch) -> None:
    agent_row = SimpleNamespace(agent_id="agent-1", is_revoked=False, config={})
    published: list[tuple[str, dict]] = []
    captured_scan: dict[str, VulnScanModel] = {}

    monkeypatch.setattr("app.features.vuln.scans.get_agent_by_agent_id", lambda _db, _agent_id: agent_row)
    monkeypatch.setattr("app.features.vuln.scans.get_latest_live_manual_scan_for_agent", lambda _db, _agent_id: None)
    monkeypatch.setattr("app.features.vuln.scans.add_vuln_scan", lambda _db, scan: captured_scan.setdefault("row", scan))
    monkeypatch.setattr("app.features.vuln.scans.add_agent", lambda _db, _row: None)
    monkeypatch.setattr("app.features.vuln.scans.commit", lambda _db: None)
    monkeypatch.setattr("app.features.vuln.scans.publish_realtime", lambda event_type, payload: published.append((event_type, payload)))

    result = trigger_manual_scan(object(), body=VulnManualScanIn(agent_id="agent-1"))

    assert result.request_token == result.trigger_token
    assert result.request_token != result.scan_uuid
    assert result.scan is not None
    assert result.scan.scan_uuid == result.scan_uuid

    queued_scan = captured_scan["row"]
    assert agent_row.config["revision"] == 1
    assert queued_scan.request_token == result.request_token
    assert queued_scan.scan_uuid == result.scan_uuid
    assert queued_scan.scope["request_token"] == result.request_token

    lifecycle_payload = published[0][1]
    assert lifecycle_payload["scan_uuid"] == result.scan_uuid
    assert "request_token" not in lifecycle_payload["scan"]["scope"]
    assert "scan_now_token" not in lifecycle_payload["scan"]["config"]


def test_trigger_manual_scan_reuses_existing_live_manual_scan(monkeypatch) -> None:
    existing_scan = _base_scan()
    agent_row = SimpleNamespace(
        agent_id="agent-1",
        is_revoked=False,
        config={
            "revision": 7,
            "modules": {
                "vulnscanner": {
                    "enabled": True,
                    "scan_now_token": existing_scan.scan_uuid,
                }
            },
        },
    )

    called = {"add_vuln_scan": 0, "commit": 0}

    monkeypatch.setattr("app.features.vuln.scans.get_agent_by_agent_id", lambda _db, _agent_id: agent_row)
    monkeypatch.setattr("app.features.vuln.scans.get_latest_live_manual_scan_for_agent", lambda _db, _agent_id: existing_scan)
    monkeypatch.setattr("app.features.vuln.scans.add_vuln_scan", lambda _db, _scan: called.__setitem__("add_vuln_scan", called["add_vuln_scan"] + 1))
    monkeypatch.setattr("app.features.vuln.scans.add_agent", lambda _db, _row: None)
    monkeypatch.setattr("app.features.vuln.scans.commit", lambda _db: called.__setitem__("commit", called["commit"] + 1))
    monkeypatch.setattr("app.features.vuln.scans.publish_realtime", lambda *_args, **_kwargs: None)

    result = trigger_manual_scan(object(), body=VulnManualScanIn(agent_id="agent-1"))

    assert result.request_state == "existing"
    assert result.scan_uuid == existing_scan.scan_uuid
    assert result.request_token == existing_scan.request_token
    assert called["add_vuln_scan"] == 0
    assert called["commit"] == 0
    assert result.scan is not None
    assert "request_token" not in result.scan.scope
    assert "scan_now_token" not in result.scan.config
