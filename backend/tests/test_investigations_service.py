from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi import HTTPException

from app.core.portal_auth import PortalPrincipal
from app.features.attack_chain.models import AttackChainCaseModel, AttackChainStepModel
from app.features.events.models import NetEventModel
from app.features.inventory.models import AgentInventorySnapshotModel
from app.features.investigations import service
from app.features.investigations.models import (
    InvestigationEvidenceBookmarkModel,
    InvestigationNoteModel,
    InvestigationWorkspaceModel,
)
from app.features.investigations.schemas import (
    InvestigationBookmarkCreateIn,
    InvestigationNoteCreateIn,
    InvestigationNoteUpdateIn,
    InvestigationPinOptionsIn,
    InvestigationWorkspaceCreateIn,
    InvestigationWorkspaceUpdateIn,
)
from app.features.response.models import ResponseActionModel, ResponseActionResultModel


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


@pytest.fixture()
def fake_repo(monkeypatch: pytest.MonkeyPatch) -> _FakeInvestigationsRepo:
    repo = _FakeInvestigationsRepo()
    monkeypatch.setattr(service, "repository", repo)
    return repo


@pytest.fixture()
def actor() -> PortalPrincipal:
    return PortalPrincipal(id=7, username="analyst", role="admin")


def test_create_update_close_reopen_workspace_and_audit(fake_repo: _FakeInvestigationsRepo, actor: PortalPrincipal) -> None:
    audits: list[dict[str, Any]] = []

    def _audit(_db, **kwargs):
        audits.append(kwargs)

    out = service.create_workspace(
        db=object(),
        payload=InvestigationWorkspaceCreateIn(title="DNS Incident", triage_state="triage"),
        request=None,
        user=actor,
        audit_writer=_audit,
    )
    assert out.id == 1
    assert out.title == "DNS Incident"
    assert out.status == "open"
    assert out.triage_state == "triage"

    upd = service.update_workspace(
        db=object(),
        workspace_id=out.id,
        payload=InvestigationWorkspaceUpdateIn(priority="p1", assignee="alice", triage_state="contained"),
        request=None,
        user=actor,
        audit_writer=_audit,
    )
    assert upd.priority == "p1"
    assert upd.assignee == "alice"
    assert upd.status == "contained"

    closed = service.close_workspace(
        db=object(),
        workspace_id=out.id,
        request=None,
        user=actor,
        audit_writer=_audit,
    )
    assert closed.status == "closed"
    assert closed.closed_at is not None

    reopened = service.reopen_workspace(
        db=object(),
        workspace_id=out.id,
        request=None,
        user=actor,
        audit_writer=_audit,
    )
    assert reopened.status == "open"
    assert reopened.closed_at is None

    actions = [a["action"] for a in audits]
    assert "workspace.create" in actions
    assert "workspace.update" in actions
    assert "workspace.close" in actions
    assert "workspace.reopen" in actions


def test_notes_create_and_update(fake_repo: _FakeInvestigationsRepo, actor: PortalPrincipal) -> None:
    audits: list[dict[str, Any]] = []

    def _audit(_db, **kwargs):
        audits.append(kwargs)

    ws = service.create_workspace(
        db=object(),
        payload=InvestigationWorkspaceCreateIn(title="Notes Workspace"),
        request=None,
        user=actor,
        audit_writer=_audit,
    )

    note = service.create_note(
        db=object(),
        workspace_id=ws.id,
        payload=InvestigationNoteCreateIn(body="Initial finding."),
        request=None,
        user=actor,
        audit_writer=_audit,
    )
    assert note.workspace_id == ws.id
    assert note.author == "analyst"
    assert note.edited is False

    note2 = service.update_note(
        db=object(),
        note_id=note.id,
        payload=InvestigationNoteUpdateIn(body="Initial finding (updated)."),
        request=None,
        user=actor,
        audit_writer=_audit,
    )
    assert note2.id == note.id
    assert "updated" in note2.body
    assert note2.edited is True

    ws_after = service.get_workspace(db=object(), workspace_id=ws.id)
    assert ws_after.notes_count == 1

    actions = [a["action"] for a in audits]
    assert "workspace.note.create" in actions
    assert "workspace.note.update" in actions


def test_pin_event_and_dedupe(fake_repo: _FakeInvestigationsRepo, actor: PortalPrincipal) -> None:
    now = _utc_now()
    fake_repo.events[44] = NetEventModel(
        id=44,
        agent_id="agent-a",
        event_type="dns",
        timestamp=now,
        src_ip="10.0.0.2",
        dst_ip="8.8.8.8",
        src_port=53321,
        dst_port=53,
        proto="udp",
        bytes=120,
        extra={"dns_qname": "example.org"},
        app_proto="dns",
        dns_qname="example.org",
    )

    audits: list[dict[str, Any]] = []

    def _audit(_db, **kwargs):
        audits.append(kwargs)

    ws = service.create_workspace(
        db=object(),
        payload=InvestigationWorkspaceCreateIn(title="Pin Event Workspace"),
        request=None,
        user=actor,
        audit_writer=_audit,
    )

    first = service.pin_event(
        db=object(),
        workspace_id=ws.id,
        event_id=44,
        payload=InvestigationPinOptionsIn(note="Suspicious DNS."),
        request=None,
        user=actor,
        audit_writer=_audit,
    )
    assert first.created is True
    assert first.bookmark.evidence_type == "net_event"

    second = service.pin_event(
        db=object(),
        workspace_id=ws.id,
        event_id=44,
        payload=InvestigationPinOptionsIn(),
        request=None,
        user=actor,
        audit_writer=_audit,
    )
    assert second.created is False
    assert second.duplicate_of_id == first.bookmark.id

    ws_after = service.get_workspace(db=object(), workspace_id=ws.id)
    assert ws_after.bookmarks_count == 1
    assert ws_after.evidence_type_counts.get("net_event") == 1

    delete_out = service.delete_bookmark(
        db=object(),
        bookmark_id=first.bookmark.id,
        request=None,
        user=actor,
        audit_writer=_audit,
    )
    assert delete_out["status"] == "ok"

    ws_final = service.get_workspace(db=object(), workspace_id=ws.id)
    assert ws_final.bookmarks_count == 0

    bookmark_create_audits = [a for a in audits if a.get("action") == "workspace.bookmark.create"]
    assert len(bookmark_create_audits) == 1
    assert any(a.get("action") == "workspace.bookmark.delete" for a in audits)


def test_pin_inventory_response_result_and_attack_case(fake_repo: _FakeInvestigationsRepo, actor: PortalPrincipal) -> None:
    now = _utc_now()

    fake_repo.inventory_snapshots[12] = AgentInventorySnapshotModel(
        id=12,
        agent_id="agent-z",
        collected_at=now,
        schema_version=1,
        os={"pretty_name": "Ubuntu 22.04"},
        packages=[],
        packages_hash="a" * 64,
        packages_count=243,
        manager="apt",
        extra={"warnings": ["package drift"]},
    )

    fake_repo.response_actions[55] = ResponseActionModel(
        id=55,
        action_type="collect_triage_bundle",
        agent_id="agent-z",
        status="success",
        payload={},
        requested_by="analyst",
        requested_at=now,
    )
    fake_repo.response_results[56] = ResponseActionResultModel(
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

    fake_repo.attack_cases[77] = AttackChainCaseModel(
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
    fake_repo.attack_steps[78] = AttackChainStepModel(
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

    ws = service.create_workspace(
        db=object(),
        payload=InvestigationWorkspaceCreateIn(title="Cross-source pinning"),
        request=None,
        user=actor,
        audit_writer=lambda *_args, **_kwargs: None,
    )

    inv = service.pin_inventory_snapshot(
        db=object(),
        workspace_id=ws.id,
        snapshot_id=12,
        payload=InvestigationPinOptionsIn(),
        request=None,
        user=actor,
        audit_writer=lambda *_args, **_kwargs: None,
    )
    assert inv.created is True
    assert inv.bookmark.evidence_type == "inventory_snapshot"

    rr = service.pin_response_result(
        db=object(),
        workspace_id=ws.id,
        result_id=56,
        payload=InvestigationPinOptionsIn(),
        request=None,
        user=actor,
        audit_writer=lambda *_args, **_kwargs: None,
    )
    assert rr.created is True
    assert rr.bookmark.evidence_type == "response_action_result"

    ac = service.pin_attack_chain_case(
        db=object(),
        workspace_id=ws.id,
        case_id=77,
        payload=InvestigationPinOptionsIn(),
        request=None,
        user=actor,
        audit_writer=lambda *_args, **_kwargs: None,
    )
    assert ac.created is True
    assert ac.bookmark.evidence_type == "attack_chain_case"

    st = service.pin_attack_chain_step(
        db=object(),
        workspace_id=ws.id,
        step_id=78,
        payload=InvestigationPinOptionsIn(),
        request=None,
        user=actor,
        audit_writer=lambda *_args, **_kwargs: None,
    )
    assert st.created is True
    assert st.bookmark.evidence_type == "attack_chain_step"

    ws_after = service.get_workspace(db=object(), workspace_id=ws.id)
    assert ws_after.bookmarks_count == 4
    assert ws_after.evidence_type_counts.get("inventory_snapshot") == 1
    assert ws_after.evidence_type_counts.get("response_action_result") == 1
    assert ws_after.evidence_type_counts.get("attack_chain_case") == 1
    assert ws_after.evidence_type_counts.get("attack_chain_step") == 1


def test_not_found_and_audit_actions(fake_repo: _FakeInvestigationsRepo, actor: PortalPrincipal) -> None:
    audits: list[dict[str, Any]] = []

    def _audit(_db, **kwargs):
        audits.append(kwargs)

    ws = service.create_workspace(
        db=object(),
        payload=InvestigationWorkspaceCreateIn(title="Audit Workspace"),
        request=None,
        user=actor,
        audit_writer=_audit,
    )

    fake_repo.events[99] = NetEventModel(
        id=99,
        agent_id="agent-1",
        event_type="http",
        timestamp=_utc_now(),
        src_ip="10.1.1.1",
        dst_ip="198.51.100.8",
        src_port=49400,
        dst_port=443,
        proto="tcp",
        bytes=812,
        extra={"http_host": "malicious.example"},
        app_proto="http",
        http_host="malicious.example",
    )

    pin = service.create_bookmark(
        db=object(),
        workspace_id=ws.id,
        payload=InvestigationBookmarkCreateIn(evidence_type="net_event", source_event_id=99),
        request=None,
        user=actor,
        audit_writer=_audit,
    )
    assert pin.created is True

    with pytest.raises(HTTPException) as exc_info:
        service.pin_event(
            db=object(),
            workspace_id=ws.id,
            event_id=123456,
            payload=InvestigationPinOptionsIn(),
            request=None,
            user=actor,
            audit_writer=_audit,
        )
    assert exc_info.value.status_code == 404

    service.delete_bookmark(
        db=object(),
        bookmark_id=pin.bookmark.id,
        request=None,
        user=actor,
        audit_writer=_audit,
    )

    action_set = {a.get("action") for a in audits}
    assert "workspace.create" in action_set
    assert "workspace.bookmark.create" in action_set
    assert "workspace.bookmark.delete" in action_set
