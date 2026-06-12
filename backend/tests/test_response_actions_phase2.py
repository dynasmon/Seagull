from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.core.db import get_db
from app.features.auth.session import PortalPrincipal, require_admin
from app.features.response import repository, service
from app.features.response.models import ResponseActionModel
from app.features.response.registry import ACTION_REGISTRY, action_catalog
from app.features.response.schemas import BatchDispatchIn
from app.main import app


def test_action_registry_is_complete_and_well_formed() -> None:
    expected = {
        "collect_triage_bundle",
        "trigger_inventory_snapshot",
        "refresh_runtime_config",
        "trigger_topology_discovery",
        "kill_process",
        "block_outbound_ip",
        "unblock_outbound_ip",
        "quarantine_file",
    }
    assert set(ACTION_REGISTRY) == expected
    for definition in ACTION_REGISTRY.values():
        assert definition.category in {"forensics", "diagnostics", "containment"}
        assert definition.risk_level in {"low", "medium", "high", "critical"}
        assert callable(definition.validate_payload)
    assert ACTION_REGISTRY["block_outbound_ip"].undo_action == "unblock_outbound_ip"
    assert ACTION_REGISTRY["kill_process"].requires_confirmation is True
    assert ACTION_REGISTRY["kill_process"].reversible is False

    catalog = action_catalog()
    assert len(catalog) == len(ACTION_REGISTRY)
    assert all("validate_payload" not in entry for entry in catalog)


def test_kill_process_validator_normalizes_signal() -> None:
    out = ACTION_REGISTRY["kill_process"].validate_payload({"target": {"pid": 1234}, "signal": "kill"})
    assert out["target"]["pid"] == 1234
    assert out["signal"] == "SIGKILL"
    assert out["dry_run"] is False


def test_kill_process_validator_rejects_invalid_input() -> None:
    with pytest.raises(HTTPException):
        ACTION_REGISTRY["kill_process"].validate_payload({"target": {"pid": 10, "name": "x"}})
    with pytest.raises(HTTPException):
        ACTION_REGISTRY["kill_process"].validate_payload({"target": {"pid": 1}})
    with pytest.raises(HTTPException):
        ACTION_REGISTRY["kill_process"].validate_payload({"target": {"pid": 10}, "signal": "SIGFOO"})


def test_firewall_validator_defaults_protocol_and_validates_ip() -> None:
    out = ACTION_REGISTRY["block_outbound_ip"].validate_payload({"ip": "185.220.101.45", "port": 4444})
    assert out["ip"] == "185.220.101.45"
    assert out["protocol"] == "tcp"
    assert out["port"] == 4444
    with pytest.raises(HTTPException):
        ACTION_REGISTRY["block_outbound_ip"].validate_payload({"ip": "not-an-ip"})
    with pytest.raises(HTTPException):
        ACTION_REGISTRY["block_outbound_ip"].validate_payload({"ip": "10.0.0.1", "protocol": "icmp"})


def test_quarantine_validator_rejects_protected_paths() -> None:
    out = ACTION_REGISTRY["quarantine_file"].validate_payload({"path": "/tmp/evil.sh"})
    assert out["path"] == "/tmp/evil.sh"
    assert out["compute_hash"] is True
    assert out["dry_run"] is False
    with pytest.raises(HTTPException):
        ACTION_REGISTRY["quarantine_file"].validate_payload({"path": "/etc/shadow"})
    with pytest.raises(HTTPException):
        ACTION_REGISTRY["quarantine_file"].validate_payload({"path": "relative/path"})


def test_build_action_timeline_success_order() -> None:
    now = datetime(2026, 6, 11, 18, 0, 0, tzinfo=timezone.utc)
    row = ResponseActionModel(
        id=1,
        action_type="kill_process",
        agent_id="agent-1",
        status="success",
        requested_by="root",
        requested_at=now,
        delivered_at=now + timedelta(seconds=1),
        started_at=now + timedelta(seconds=2),
        finished_at=now + timedelta(seconds=5),
    )
    events = service.build_action_timeline(row)
    assert [e["event"] for e in events] == ["queued", "delivered", "started", "completed"]
    assert events[0]["actor"] == "root"
    assert events[-1]["actor"] == "agent/agent-1"


def test_build_action_timeline_cancelled_uses_canceller() -> None:
    now = datetime(2026, 6, 11, 18, 0, 0, tzinfo=timezone.utc)
    row = ResponseActionModel(
        id=2,
        action_type="block_outbound_ip",
        agent_id="agent-1",
        status="cancelled",
        requested_by="root",
        requested_at=now,
        cancelled_at=now + timedelta(seconds=3),
        cancelled_by="alice",
        finished_at=now + timedelta(seconds=3),
    )
    events = service.build_action_timeline(row)
    names = [e["event"] for e in events]
    assert names == ["queued", "cancelled"]
    cancelled = next(e for e in events if e["event"] == "cancelled")
    assert cancelled["actor"] == "alice"


def test_create_response_action_batch(monkeypatch) -> None:
    agents = {
        "agent-1": SimpleNamespace(agent_id="agent-1", is_revoked=False),
        "agent-2": SimpleNamespace(agent_id="agent-2", is_revoked=True),
    }
    created: list = []
    counter = {"n": 100}

    def fake_get_agent(db, *, agent_id):
        return agents.get(agent_id)

    def fake_create_action(
        db,
        *,
        action_type,
        agent_id,
        status,
        payload,
        requested_by,
        requested_at,
        expires_at,
        batch_id=None,
    ):
        counter["n"] += 1
        row = SimpleNamespace(
            id=counter["n"],
            action_type=action_type,
            agent_id=agent_id,
            status=status,
            payload=payload,
            requested_by=requested_by,
            requested_at=requested_at,
            expires_at=expires_at,
            batch_id=batch_id,
        )
        created.append(row)
        return row

    monkeypatch.setattr(repository, "get_agent", fake_get_agent)
    monkeypatch.setattr(repository, "create_action", fake_create_action)
    monkeypatch.setattr(repository, "flush", lambda db: None)
    monkeypatch.setattr(repository, "commit", lambda db: None)
    monkeypatch.setattr(repository, "refresh", lambda db, row: None)
    monkeypatch.setattr(service, "publish_response_action_lifecycle", lambda **kwargs: None)

    audits: list = []
    payload = BatchDispatchIn(
        action_type="block_outbound_ip",
        agent_ids=["agent-1", "agent-2", "agent-3", "agent-1"],
        payload={"ip": "185.220.101.45", "protocol": "tcp"},
        justification="bulk containment for incident 42",
    )
    admin = SimpleNamespace(id=1, username="root")

    out = service.create_response_action_batch(
        None,
        payload=payload,
        request=None,
        admin=admin,
        audit_writer=lambda *a, **k: audits.append(k),
    )

    assert out["total"] == 3
    assert len(out["queued"]) == 1
    assert out["queued"][0] == {"agent_id": "agent-1", "action_id": 101}
    reasons = {s["agent_id"]: s["reason"] for s in out["skipped"]}
    assert reasons == {"agent-2": "revoked", "agent-3": "not_found"}
    assert out["batch_id"].startswith("batch_")
    assert created[0].batch_id == out["batch_id"]
    assert len(audits) == 1
    assert audits[0]["action"] == "response.actions.batch_create"
    assert audits[0]["context"]["justification"] == "bulk containment for incident 42"


def test_action_types_endpoint() -> None:
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=1, username="root", role="admin")
    try:
        with TestClient(app) as client:
            r = client.get("/response/action-types")
            assert r.status_code == 200
            rows = r.json()
            keys = {x["key"] for x in rows}
            assert {"kill_process", "block_outbound_ip", "collect_triage_bundle"}.issubset(keys)
            kill = next(x for x in rows if x["key"] == "kill_process")
            assert kill["category"] == "containment"
            assert kill["requires_confirmation"] is True
            assert kill["reversible"] is False
            block = next(x for x in rows if x["key"] == "block_outbound_ip")
            assert block["undo_action"] == "unblock_outbound_ip"
    finally:
        app.dependency_overrides.pop(require_admin, None)


class _TimelineFakeQuery:
    def __init__(self, row):
        self._row = row

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def with_for_update(self, *args, **kwargs):
        return self

    def first(self):
        return self._row

    def all(self):
        return [self._row] if self._row else []


class _TimelineFakeDB:
    def __init__(self, row):
        self._row = row

    def query(self, model):
        return _TimelineFakeQuery(self._row)

    def add(self, obj):
        return None

    def flush(self):
        return None

    def commit(self):
        return None

    def refresh(self, obj):
        return None

    def close(self):
        return None


def test_timeline_endpoint() -> None:
    now = datetime.utcnow()
    row = ResponseActionModel(
        id=501,
        action_type="quarantine_file",
        agent_id="agent-9",
        status="success",
        requested_by="root",
        requested_at=now - timedelta(seconds=10),
        delivered_at=now - timedelta(seconds=8),
        started_at=now - timedelta(seconds=7),
        finished_at=now - timedelta(seconds=2),
        created_at=now - timedelta(seconds=10),
        updated_at=now - timedelta(seconds=2),
    )
    fake_db = _TimelineFakeDB(row)
    app.dependency_overrides[get_db] = lambda: fake_db
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=1, username="root", role="admin")
    try:
        with TestClient(app) as client:
            r = client.get("/response/actions/501/timeline")
            assert r.status_code == 200
            events = r.json()
            assert [e["event"] for e in events] == ["queued", "delivered", "started", "completed"]
            assert events[0]["actor"] == "root"
            assert events[-1]["actor"] == "agent/agent-9"
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(require_admin, None)
