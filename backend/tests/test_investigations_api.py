from __future__ import annotations

import os
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient
import pytest

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core.portal_auth import PortalPrincipal, get_current_user
from app.features.attack_chain.models import AttackChainCaseModel, AttackChainStepModel
from app.features.events.models import NetEventModel
from app.features.inventory.models import AgentInventorySnapshotModel
from app.features.investigations import api as investigations_api
from app.features.investigations import service
from app.features.investigations.models import (
    InvestigationEvidenceBookmarkModel,
    InvestigationNoteModel,
    InvestigationWorkspaceModel,
)
from app.features.response.models import ResponseActionModel, ResponseActionResultModel
from app.main import app


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class _FakeInvestigationsRepo:
    def __init__(self) -> None:
        self.workspaces: dict[int, InvestigationWorkspaceModel] = {}
        self.notes: dict[int, InvestigationNoteModel] = {}
        self.bookmarks: dict[int, InvestigationEvidenceBookmarkModel] = {}

        self.events: dict[int, NetEventModel] = {}
        self.inventory_snapshots: dict[int, AgentInventorySnapshotModel] = {}
        self.response_results: dict[int, ResponseActionResultModel] = {}
        self.response_actions: dict[int, ResponseActionModel] = {}
        self.attack_cases: dict[int, AttackChainCaseModel] = {}
        self.attack_steps: dict[int, AttackChainStepModel] = {}
        self.audit_events: list[Any] = []

        self._workspace_seq = 1
        self._note_seq = 1
        self._bookmark_seq = 1

    def list_workspaces_page(self, db, **kwargs):
        rows = list(self.workspaces.values())
        rows.sort(key=lambda x: (x.updated_at, x.id), reverse=True)
        page_size = int(kwargs.get("page_size") or 50)
        return rows[: page_size + 1]

    def get_workspace(self, db, workspace_id: int, *, for_update: bool = False):
        return self.workspaces.get(int(workspace_id))

    def create_workspace(self, db, **kwargs):
        now = _utc_now()
        row = InvestigationWorkspaceModel(**kwargs)
        row.id = self._workspace_seq
        self._workspace_seq += 1
        row.created_at = now
        row.updated_at = now
        self.workspaces[int(row.id)] = row
        return row

    def save_workspace(self, db, row):
        row.updated_at = _utc_now()
        self.workspaces[int(row.id)] = row
        return row

    def get_workspace_by_key(self, db, workspace_key: str):
        for row in self.workspaces.values():
            if row.workspace_key == workspace_key:
                return row
        return None

    def get_attack_chain_case(self, db, case_id: int):
        return self.attack_cases.get(int(case_id))

    def get_attack_chain_step(self, db, step_id: int):
        return self.attack_steps.get(int(step_id))

    def list_notes_by_workspace(self, db, *, workspace_id: int, limit: int = 500):
        rows = [n for n in self.notes.values() if int(n.workspace_id) == int(workspace_id)]
        rows.sort(key=lambda x: (x.created_at, x.id), reverse=True)
        return rows[: int(limit)]

    def get_note(self, db, note_id: int, *, for_update: bool = False):
        return self.notes.get(int(note_id))

    def create_note(self, db, *, workspace_id: int, author: str, body: str):
        now = _utc_now()
        row = InvestigationNoteModel(workspace_id=int(workspace_id), author=author, body=body)
        row.id = self._note_seq
        self._note_seq += 1
        row.created_at = now
        row.updated_at = now
        self.notes[int(row.id)] = row
        return row

    def save_note(self, db, row):
        row.updated_at = _utc_now()
        self.notes[int(row.id)] = row
        return row

    def delete_note(self, db, row):
        self.notes.pop(int(row.id), None)

    def count_notes_by_workspace(self, db, workspace_id: int):
        return len([n for n in self.notes.values() if int(n.workspace_id) == int(workspace_id)])

    def list_bookmarks_page(self, db, *, workspace_id: int, evidence_type: str | None, page_size: int, cursor_parsed=None):
        rows = [b for b in self.bookmarks.values() if int(b.workspace_id) == int(workspace_id)]
        if evidence_type:
            rows = [b for b in rows if b.evidence_type == evidence_type]
        rows.sort(key=lambda x: (x.created_at, x.id), reverse=True)
        return rows[: int(page_size) + 1]

    def list_workspace_activity_audit_page(self, db, *, workspace_id: int, page_size: int, cursor_parsed=None):
        ws_id = int(workspace_id)
        rows = []
        for ev in self.audit_events:
            resource_type = str(getattr(ev, "resource_type", "") or "")
            resource_id = str(getattr(ev, "resource_id", "") or "")
            if resource_type == "investigation_workspace" and resource_id == str(ws_id):
                rows.append(ev)
                continue
            if resource_type == "investigation_note":
                try:
                    note_id = int(resource_id)
                except ValueError:
                    note_id = 0
                note = self.notes.get(note_id)
                if note and int(note.workspace_id) == ws_id:
                    rows.append(ev)
                    continue
                before_ws = str(getattr(ev, "before", {}).get("workspace_id", "") or "")
                after_ws = str(getattr(ev, "after", {}).get("workspace_id", "") or "")
                if before_ws == str(ws_id) or after_ws == str(ws_id):
                    rows.append(ev)
                continue
            if resource_type == "investigation_bookmark":
                try:
                    bookmark_id = int(resource_id)
                except ValueError:
                    bookmark_id = 0
                bookmark = self.bookmarks.get(bookmark_id)
                if bookmark and int(bookmark.workspace_id) == ws_id:
                    rows.append(ev)
                    continue
                before_ws = str(getattr(ev, "before", {}).get("workspace_id", "") or "")
                after_ws = str(getattr(ev, "after", {}).get("workspace_id", "") or "")
                if before_ws == str(ws_id) or after_ws == str(ws_id):
                    rows.append(ev)
                continue

        rows.sort(key=lambda x: (x.created_at, x.id), reverse=True)

        if cursor_parsed:
            c_ts, c_id = cursor_parsed
            rows = [r for r in rows if r.created_at < c_ts or (r.created_at == c_ts and str(r.id) < str(c_id))]

        return rows[: int(page_size) + 1]

    def get_bookmark(self, db, bookmark_id: int, *, for_update: bool = False):
        return self.bookmarks.get(int(bookmark_id))

    def find_bookmark_by_dedupe(self, db, *, workspace_id: int, dedupe_key: str):
        for row in self.bookmarks.values():
            if int(row.workspace_id) == int(workspace_id) and row.dedupe_key == dedupe_key:
                return row
        return None

    def create_bookmark(self, db, **kwargs):
        now = _utc_now()
        row = InvestigationEvidenceBookmarkModel(**kwargs)
        row.id = self._bookmark_seq
        self._bookmark_seq += 1
        row.created_at = now
        self.bookmarks[int(row.id)] = row
        return row

    def delete_bookmark(self, db, row):
        self.bookmarks.pop(int(row.id), None)

    def count_bookmarks_by_workspace(self, db, workspace_id: int):
        return len([b for b in self.bookmarks.values() if int(b.workspace_id) == int(workspace_id)])

    def count_bookmarks_grouped_by_type(self, db, workspace_id: int):
        out: dict[str, int] = {}
        for row in self.bookmarks.values():
            if int(row.workspace_id) != int(workspace_id):
                continue
            out[row.evidence_type] = out.get(row.evidence_type, 0) + 1
        return out

    def get_event(self, db, event_id: int):
        return self.events.get(int(event_id))

    def get_inventory_snapshot(self, db, snapshot_id: int):
        return self.inventory_snapshots.get(int(snapshot_id))

    def get_response_action_result(self, db, result_id: int):
        return self.response_results.get(int(result_id))

    def get_response_action(self, db, action_id: int):
        return self.response_actions.get(int(action_id))

    def flush(self, db):
        return None

    def refresh(self, db, row):
        return None

    def commit(self, db):
        return None


class _FakeDB:
    def close(self):
        return None


@pytest.fixture()
def fake_investigations_api(monkeypatch: pytest.MonkeyPatch) -> _FakeInvestigationsRepo:
    repo = _FakeInvestigationsRepo()

    def _audit(_db, **kwargs):
        before = kwargs.get("before") if isinstance(kwargs.get("before"), dict) else {}
        after = kwargs.get("after") if isinstance(kwargs.get("after"), dict) else {}
        changed_fields = sorted(set(before.keys()) | set(after.keys()))
        changed_fields = [k for k in changed_fields if before.get(k) != after.get(k)]
        seq = len(repo.audit_events) + 1
        repo.audit_events.append(
            SimpleNamespace(
                id=f"audit-{seq:06d}",
                created_at=_utc_now(),
                action=kwargs.get("action"),
                outcome=kwargs.get("outcome") or "success",
                actor_username=getattr(kwargs.get("actor"), "username", None),
                resource_type=kwargs.get("resource_type"),
                resource_id=kwargs.get("resource_id"),
                before=before,
                after=after,
                changed_fields=changed_fields,
                context=kwargs.get("context") or {},
            )
        )

    monkeypatch.setattr(service, "repository", repo)
    monkeypatch.setattr(investigations_api, "SessionLocal", lambda: _FakeDB())
    monkeypatch.setattr(investigations_api, "write_audit_event", _audit)
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=5, username="analyst", role="admin")

    yield repo

    app.dependency_overrides.pop(get_current_user, None)


def test_workspace_note_bookmark_lifecycle_activity_and_summary_regression(fake_investigations_api: _FakeInvestigationsRepo) -> None:
    now = _utc_now()
    fake_investigations_api.events[501] = NetEventModel(
        id=501,
        agent_id="agent-api",
        event_type="dns",
        timestamp=now,
        src_ip="10.0.0.2",
        dst_ip="8.8.8.8",
        src_port=51000,
        dst_port=53,
        proto="udp",
        bytes=120,
        extra={"dns_qname": "example.org"},
        app_proto="dns",
        dns_qname="example.org",
    )
    fake_investigations_api.events[502] = NetEventModel(
        id=502,
        agent_id="agent-api",
        event_type="dns",
        timestamp=now,
        src_ip="10.0.0.3",
        dst_ip="1.1.1.1",
        src_port=51001,
        dst_port=53,
        proto="udp",
        bytes=130,
        extra={"dns_qname": "example.net"},
        app_proto="dns",
        dns_qname="example.net",
    )

    with TestClient(app) as client:
        r_create = client.post(
            "/investigations/workspaces",
            json={
                "title": "API Workspace",
                "description": "Created through API tests",
                "severity": "high",
                "priority": "p2",
                "assignee": "analyst-a",
                "primary_agent_id": "agent-api",
            },
        )
        assert r_create.status_code == 201
        ws = r_create.json()
        ws_id = ws["id"]

        r_get = client.get(f"/investigations/workspaces/{ws_id}")
        assert r_get.status_code == 200
        assert r_get.json()["title"] == "API Workspace"

        r_update = client.put(
            f"/investigations/workspaces/{ws_id}",
            json={
                "title": "API Workspace Updated",
                "description": "Updated description",
                "status": "open",
                "severity": "critical",
                "priority": "p1",
                "assignee": "analyst-b",
                "triage_state": "assigned",
                "primary_agent_id": "agent-api",
            },
        )
        assert r_update.status_code == 200
        assert r_update.json()["title"] == "API Workspace Updated"
        assert r_update.json()["severity"] == "critical"

        r_close = client.post(f"/investigations/workspaces/{ws_id}/close")
        assert r_close.status_code == 200
        assert r_close.json()["status"] == "closed"

        r_reopen = client.post(f"/investigations/workspaces/{ws_id}/reopen")
        assert r_reopen.status_code == 200
        assert r_reopen.json()["status"] == "open"

        r_note = client.post(f"/investigations/workspaces/{ws_id}/notes", json={"body": "first note"})
        assert r_note.status_code == 201
        note_id = r_note.json()["id"]

        r_note_upd = client.put(f"/investigations/notes/{note_id}", json={"body": "first note updated"})
        assert r_note_upd.status_code == 200
        assert r_note_upd.json()["edited"] is True

        r_bm_create = client.post(
            f"/investigations/workspaces/{ws_id}/bookmarks",
            json={
                "evidence_type": "net_event",
                "source_event_id": 501,
            },
        )
        assert r_bm_create.status_code == 200
        first_bookmark = r_bm_create.json()["bookmark"]
        assert "event_id=501" in str(first_bookmark["payload_snapshot"].get("deep_link") or "")

        r_bm_dup = client.post(
            f"/investigations/workspaces/{ws_id}/bookmarks",
            json={
                "evidence_type": "net_event",
                "source_event_id": 501,
            },
        )
        assert r_bm_dup.status_code == 200
        assert r_bm_dup.json()["created"] is False

        r_pin_with_note = client.post(
            f"/investigations/workspaces/{ws_id}/pin-event/502",
            json={"note": "why this matters"},
        )
        assert r_pin_with_note.status_code == 200
        assert r_pin_with_note.json()["created"] is True

        r_pin_dup = client.post(
            f"/investigations/workspaces/{ws_id}/pin-event/502",
            json={"note": "duplicate"},
        )
        assert r_pin_dup.status_code == 200
        assert r_pin_dup.json()["created"] is False

        r_ws_after_pin = client.get(f"/investigations/workspaces/{ws_id}")
        assert r_ws_after_pin.status_code == 200
        ws_after_pin = r_ws_after_pin.json()
        assert ws_after_pin["bookmarks_count"] == 2
        assert ws_after_pin["notes_count"] == 2
        assert ws_after_pin["evidence_type_counts"].get("net_event") == 2

        r_activity = client.get(f"/investigations/workspaces/{ws_id}/activity?page_size=100")
        assert r_activity.status_code == 200
        activity = r_activity.json()
        assert isinstance(activity["items"], list)
        assert activity["items"]
        action_types = {item["activity_type"] for item in activity["items"]}
        assert "workspace_created" in action_types
        assert "workspace_updated" in action_types
        assert "workspace_closed" in action_types
        assert "workspace_reopened" in action_types
        assert "note_created" in action_types
        assert "note_updated" in action_types
        assert "bookmark_created" in action_types

        r_activity_page = client.get(f"/investigations/workspaces/{ws_id}/activity?page_size=2")
        assert r_activity_page.status_code == 200
        page_one = r_activity_page.json()
        assert len(page_one["items"]) == 2
        assert page_one["has_more"] is True
        assert page_one["next_cursor"]

        r_delete = client.delete(f"/investigations/bookmarks/{first_bookmark['id']}")
        assert r_delete.status_code == 200

        r_activity_after_delete = client.get(f"/investigations/workspaces/{ws_id}/activity?page_size=100")
        assert r_activity_after_delete.status_code == 200
        action_types_after_delete = {item["activity_type"] for item in r_activity_after_delete.json()["items"]}
        assert "bookmark_deleted" in action_types_after_delete

        r_ws_final = client.get(f"/investigations/workspaces/{ws_id}")
        assert r_ws_final.status_code == 200
        ws_final = r_ws_final.json()
        assert ws_final["bookmarks_count"] == 1
        assert ws_final["notes_count"] == 2


def test_precise_deep_links_for_protocol_inventory_response_and_attack_chain(fake_investigations_api: _FakeInvestigationsRepo) -> None:
    now = _utc_now()

    fake_investigations_api.events[601] = NetEventModel(
        id=601,
        agent_id="agent-z",
        event_type="http",
        timestamp=now,
        src_ip="10.0.1.3",
        dst_ip="198.51.100.4",
        src_port=44000,
        dst_port=443,
        proto="tcp",
        bytes=900,
        extra={"app_proto_reason": "http_host"},
        app_proto="http",
        http_host="api.example.local",
    )

    fake_investigations_api.inventory_snapshots[12] = AgentInventorySnapshotModel(
        id=12,
        agent_id="agent-z",
        collected_at=now,
        schema_version=1,
        os={"pretty_name": "Ubuntu 22.04"},
        packages=[],
        packages_hash="a" * 64,
        packages_count=243,
        manager="apt",
        extra={"warnings": ["drift"]},
    )

    fake_investigations_api.response_actions[55] = ResponseActionModel(
        id=55,
        action_type="collect_triage_bundle",
        agent_id="agent-z",
        status="success",
        payload={},
        requested_by="analyst",
        requested_at=now,
    )
    fake_investigations_api.response_results[56] = ResponseActionResultModel(
        id=56,
        response_action_id=55,
        agent_id="agent-z",
        status="success",
        result_payload={"bundle_id": "abc"},
        error=None,
        started_at=now,
        finished_at=now,
        created_at=now,
        updated_at=now,
    )

    fake_investigations_api.attack_cases[77] = AttackChainCaseModel(
        id=77,
        agent_id="agent-z",
        suspect_ip="203.0.113.10",
        status="open",
        score=88,
        max_stage="lateral_movement",
        first_seen_at=now,
        last_seen_at=now,
        step_count=4,
        context={"confidence": 90},
    )
    fake_investigations_api.attack_steps[78] = AttackChainStepModel(
        id=78,
        case_id=77,
        stage="discovery",
        label="Port scan burst",
        score_delta=12,
        event_id=44,
        event_type="scan",
        timestamp=now,
        src_ip="10.0.0.8",
        dst_ip="203.0.113.10",
        src_port=40001,
        dst_port=22,
        proto="tcp",
        fingerprint="step-fp-78",
        details={"confidence": 86, "kind": "port_scan"},
    )

    with TestClient(app) as client:
        r_ws = client.post("/investigations/workspaces", json={"title": "Deep Link Workspace"})
        assert r_ws.status_code == 201
        ws_id = r_ws.json()["id"]

        r_protocol = client.post(
            f"/investigations/workspaces/{ws_id}/pin-protocol-intel-event/601",
            json={
                "metadata": {
                    "protocol_indicator_kind": "http_host",
                    "protocol_indicator_value": "api.example.local",
                }
            },
        )
        assert r_protocol.status_code == 200
        protocol_link = str(r_protocol.json()["bookmark"]["payload_snapshot"].get("deep_link") or "")
        assert "/events/network?" in protocol_link
        assert "focus_event_id=601" in protocol_link
        assert "indicator_kind=http_host" in protocol_link

        r_inventory = client.post(f"/investigations/workspaces/{ws_id}/pin-inventory-snapshot/12", json={})
        assert r_inventory.status_code == 200
        inventory_link = str(r_inventory.json()["bookmark"]["payload_snapshot"].get("deep_link") or "")
        assert "agent_id=agent-z" in inventory_link
        assert "snapshot_id=12" in inventory_link

        r_response = client.post(f"/investigations/workspaces/{ws_id}/pin-response-result/56", json={})
        assert r_response.status_code == 200
        response_link = str(r_response.json()["bookmark"]["payload_snapshot"].get("deep_link") or "")
        assert "response_action_id=55" in response_link
        assert "response_result_id=56" in response_link
        assert "response_tab=result" in response_link

        r_case = client.post(f"/investigations/workspaces/{ws_id}/pin-attack-chain-case/77", json={})
        assert r_case.status_code == 200
        case_link = str(r_case.json()["bookmark"]["payload_snapshot"].get("deep_link") or "")
        assert "case_id=77" in case_link

        r_step = client.post(f"/investigations/workspaces/{ws_id}/pin-attack-chain-step/78", json={})
        assert r_step.status_code == 200
        step_link = str(r_step.json()["bookmark"]["payload_snapshot"].get("deep_link") or "")
        assert "case_id=77" in step_link
        assert "step_id=78" in step_link

        r_ws_after = client.get(f"/investigations/workspaces/{ws_id}")
        assert r_ws_after.status_code == 200
        ws_after = r_ws_after.json()
        assert ws_after["bookmarks_count"] == 5
        assert ws_after["notes_count"] == 0


def test_pin_event_endpoint_falls_back_to_recent_feed_for_synthetic_event_id(
    fake_investigations_api: _FakeInvestigationsRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    synthetic_event_id = 1176742294
    now = _utc_now()

    def _fake_fetch_event_by_id(*, event_id: int, agent_id: str | None = None):
        if int(event_id) != synthetic_event_id:
            return None
        return {
            "id": synthetic_event_id,
            "timestamp": now.isoformat(),
            "agent_id": "agent-flow",
            "event_type": "flow",
            "src_ip": "10.10.0.2",
            "dst_ip": "203.0.113.9",
            "src_port": 53211,
            "dst_port": 443,
            "proto": "tcp",
            "bytes": 1580,
            "extra": {"app_proto": "tls", "tls_sni": "login.example.net"},
        }

    monkeypatch.setattr(service, "fetch_recent_feed_event_by_id", _fake_fetch_event_by_id)

    with TestClient(app) as client:
        r_ws = client.post("/investigations/workspaces", json={"title": "Synthetic Event Pin"})
        assert r_ws.status_code == 201
        ws_id = r_ws.json()["id"]

        r_pin = client.post(
            f"/investigations/workspaces/{ws_id}/pin-event/{synthetic_event_id}",
            json={"note": "pin from feed fallback"},
        )
        assert r_pin.status_code == 200
        body = r_pin.json()
        assert body["created"] is True
        assert int(body["bookmark"]["payload_snapshot"].get("event_id") or 0) == synthetic_event_id
        assert "event_id=1176742294" in str(body["bookmark"]["payload_snapshot"].get("deep_link") or "")

        r_pin_dup = client.post(
            f"/investigations/workspaces/{ws_id}/pin-event/{synthetic_event_id}",
            json={"note": "duplicate"},
        )
        assert r_pin_dup.status_code == 200
        assert r_pin_dup.json()["created"] is False

        r_ws_after = client.get(f"/investigations/workspaces/{ws_id}")
        assert r_ws_after.status_code == 200
        ws_after = r_ws_after.json()
        assert ws_after["bookmarks_count"] == 1
        assert ws_after["notes_count"] == 1
