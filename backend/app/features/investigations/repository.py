from __future__ import annotations

from datetime import datetime

from sqlalchemy import String, and_, cast, exists, func, or_, select
from sqlalchemy.orm import Session

from app.features.admin.models import AdminAuditEventModel
from app.features.attack_chain.models import AttackChainCaseModel, AttackChainStepModel
from app.features.events.models import NetEventModel
from app.features.inventory.models import AgentInventorySnapshotModel
from app.features.investigations.models import (
    InvestigationEvidenceBookmarkModel,
    InvestigationNoteModel,
    InvestigationWorkspaceModel,
)
from app.features.response.models import ResponseActionModel, ResponseActionResultModel


def list_workspaces_page(
    db: Session,
    *,
    page_size: int,
    status: str | None,
    severity: str | None,
    priority: str | None,
    assignee: str | None,
    linked_attack_chain_case_id: int | None,
    agent_id: str | None,
    search: str | None,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[InvestigationWorkspaceModel]:
    stmt = select(InvestigationWorkspaceModel).order_by(
        InvestigationWorkspaceModel.updated_at.desc(),
        InvestigationWorkspaceModel.id.desc(),
    )

    if status:
        stmt = stmt.where(InvestigationWorkspaceModel.status == status)
    if severity:
        stmt = stmt.where(InvestigationWorkspaceModel.severity == severity)
    if priority:
        stmt = stmt.where(InvestigationWorkspaceModel.priority == priority)
    if assignee:
        stmt = stmt.where(InvestigationWorkspaceModel.assignee == assignee)
    if linked_attack_chain_case_id is not None:
        stmt = stmt.where(InvestigationWorkspaceModel.linked_attack_chain_case_id == int(linked_attack_chain_case_id))

    if agent_id:
        has_agent_bookmark = exists().where(
            InvestigationEvidenceBookmarkModel.workspace_id == InvestigationWorkspaceModel.id,
            InvestigationEvidenceBookmarkModel.agent_id == agent_id,
        )
        stmt = stmt.where(
            or_(
                InvestigationWorkspaceModel.primary_agent_id == agent_id,
                has_agent_bookmark,
            )
        )

    if search:
        token = f"%{search}%"
        stmt = stmt.where(
            or_(
                InvestigationWorkspaceModel.workspace_key.ilike(token),
                InvestigationWorkspaceModel.title.ilike(token),
                InvestigationWorkspaceModel.description.ilike(token),
                InvestigationWorkspaceModel.assignee.ilike(token),
            )
        )

    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                InvestigationWorkspaceModel.updated_at < c_ts,
                and_(InvestigationWorkspaceModel.updated_at == c_ts, InvestigationWorkspaceModel.id < c_id),
            )
        )

    return db.execute(stmt.limit(int(page_size) + 1)).scalars().all()


def get_workspace(db: Session, workspace_id: int, *, for_update: bool = False) -> InvestigationWorkspaceModel | None:
    stmt = select(InvestigationWorkspaceModel).where(InvestigationWorkspaceModel.id == int(workspace_id))
    if for_update:
        stmt = stmt.with_for_update()
    return db.execute(stmt).scalars().first()


def create_workspace(
    db: Session,
    *,
    workspace_key: str,
    title: str,
    description: str | None,
    status: str,
    severity: str,
    priority: str,
    assignee: str | None,
    created_by: str,
    updated_by: str,
    closed_at,
    linked_attack_chain_case_id: int | None,
    primary_agent_id: str | None,
    summary: dict,
) -> InvestigationWorkspaceModel:
    row = InvestigationWorkspaceModel(
        workspace_key=workspace_key,
        title=title,
        description=description,
        status=status,
        severity=severity,
        priority=priority,
        assignee=assignee,
        created_by=created_by,
        updated_by=updated_by,
        closed_at=closed_at,
        linked_attack_chain_case_id=linked_attack_chain_case_id,
        primary_agent_id=primary_agent_id,
        summary=summary,
    )
    db.add(row)
    return row


def save_workspace(db: Session, row: InvestigationWorkspaceModel) -> InvestigationWorkspaceModel:
    db.add(row)
    return row


def get_workspace_by_key(db: Session, workspace_key: str) -> InvestigationWorkspaceModel | None:
    stmt = select(InvestigationWorkspaceModel).where(InvestigationWorkspaceModel.workspace_key == workspace_key)
    return db.execute(stmt).scalars().first()


def get_attack_chain_case(db: Session, case_id: int) -> AttackChainCaseModel | None:
    return db.get(AttackChainCaseModel, int(case_id))


def get_attack_chain_step(db: Session, step_id: int) -> AttackChainStepModel | None:
    return db.get(AttackChainStepModel, int(step_id))


def list_notes_by_workspace(db: Session, *, workspace_id: int, limit: int = 500) -> list[InvestigationNoteModel]:
    stmt = (
        select(InvestigationNoteModel)
        .where(InvestigationNoteModel.workspace_id == int(workspace_id))
        .order_by(InvestigationNoteModel.created_at.desc(), InvestigationNoteModel.id.desc())
        .limit(int(limit))
    )
    return db.execute(stmt).scalars().all()


def get_note(db: Session, note_id: int, *, for_update: bool = False) -> InvestigationNoteModel | None:
    stmt = select(InvestigationNoteModel).where(InvestigationNoteModel.id == int(note_id))
    if for_update:
        stmt = stmt.with_for_update()
    return db.execute(stmt).scalars().first()


def create_note(db: Session, *, workspace_id: int, author: str, body: str) -> InvestigationNoteModel:
    row = InvestigationNoteModel(workspace_id=int(workspace_id), author=author, body=body)
    db.add(row)
    return row


def save_note(db: Session, row: InvestigationNoteModel) -> InvestigationNoteModel:
    db.add(row)
    return row


def delete_note(db: Session, row: InvestigationNoteModel) -> None:
    db.delete(row)


def count_notes_by_workspace(db: Session, workspace_id: int) -> int:
    stmt = select(func.count(InvestigationNoteModel.id)).where(InvestigationNoteModel.workspace_id == int(workspace_id))
    return int(db.execute(stmt).scalar() or 0)


def list_bookmarks_page(
    db: Session,
    *,
    workspace_id: int,
    evidence_type: str | None,
    page_size: int,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[InvestigationEvidenceBookmarkModel]:
    stmt = (
        select(InvestigationEvidenceBookmarkModel)
        .where(InvestigationEvidenceBookmarkModel.workspace_id == int(workspace_id))
        .order_by(InvestigationEvidenceBookmarkModel.created_at.desc(), InvestigationEvidenceBookmarkModel.id.desc())
    )
    if evidence_type:
        stmt = stmt.where(InvestigationEvidenceBookmarkModel.evidence_type == evidence_type)

    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                InvestigationEvidenceBookmarkModel.created_at < c_ts,
                and_(InvestigationEvidenceBookmarkModel.created_at == c_ts, InvestigationEvidenceBookmarkModel.id < c_id),
            )
        )

    return db.execute(stmt.limit(int(page_size) + 1)).scalars().all()


def list_workspace_activity_audit_page(
    db: Session,
    *,
    workspace_id: int,
    page_size: int,
    cursor_parsed: tuple[datetime, str] | None,
) -> list[AdminAuditEventModel]:
    ws_id = int(workspace_id)
    ws_id_text = str(ws_id)

    note_exists = exists(
        select(InvestigationNoteModel.id).where(
            InvestigationNoteModel.workspace_id == ws_id,
            cast(InvestigationNoteModel.id, String) == AdminAuditEventModel.resource_id,
        )
    )
    note_workspace_match = or_(
        AdminAuditEventModel.before["workspace_id"].astext == ws_id_text,
        AdminAuditEventModel.after["workspace_id"].astext == ws_id_text,
    )
    bookmark_exists = exists(
        select(InvestigationEvidenceBookmarkModel.id).where(
            InvestigationEvidenceBookmarkModel.workspace_id == ws_id,
            cast(InvestigationEvidenceBookmarkModel.id, String) == AdminAuditEventModel.resource_id,
        )
    )
    bookmark_workspace_match = or_(
        AdminAuditEventModel.before["workspace_id"].astext == ws_id_text,
        AdminAuditEventModel.after["workspace_id"].astext == ws_id_text,
    )

    stmt = (
        select(AdminAuditEventModel)
        .where(
            or_(
                and_(
                    AdminAuditEventModel.resource_type == "investigation_workspace",
                    AdminAuditEventModel.resource_id == ws_id_text,
                ),
                and_(
                    AdminAuditEventModel.resource_type == "investigation_note",
                    or_(note_exists, note_workspace_match),
                ),
                and_(
                    AdminAuditEventModel.resource_type == "investigation_bookmark",
                    or_(bookmark_exists, bookmark_workspace_match),
                ),
            )
        )
        .order_by(AdminAuditEventModel.created_at.desc(), AdminAuditEventModel.id.desc())
    )

    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                AdminAuditEventModel.created_at < c_ts,
                and_(AdminAuditEventModel.created_at == c_ts, AdminAuditEventModel.id < c_id),
            )
        )

    return db.execute(stmt.limit(int(page_size) + 1)).scalars().all()


def get_bookmark(db: Session, bookmark_id: int, *, for_update: bool = False) -> InvestigationEvidenceBookmarkModel | None:
    stmt = select(InvestigationEvidenceBookmarkModel).where(InvestigationEvidenceBookmarkModel.id == int(bookmark_id))
    if for_update:
        stmt = stmt.with_for_update()
    return db.execute(stmt).scalars().first()


def find_bookmark_by_dedupe(db: Session, *, workspace_id: int, dedupe_key: str) -> InvestigationEvidenceBookmarkModel | None:
    stmt = select(InvestigationEvidenceBookmarkModel).where(
        InvestigationEvidenceBookmarkModel.workspace_id == int(workspace_id),
        InvestigationEvidenceBookmarkModel.dedupe_key == dedupe_key,
    )
    return db.execute(stmt).scalars().first()


def create_bookmark(
    db: Session,
    *,
    workspace_id: int,
    evidence_type: str,
    evidence_subtype: str | None,
    source_module: str,
    title: str,
    summary: str | None,
    agent_id: str | None,
    observed_at,
    created_by: str,
    ref_id: str | None,
    ref_table: str | None,
    fingerprint: str | None,
    dedupe_key: str,
    tags: list[str],
    payload_snapshot: dict,
    metadata: dict,
) -> InvestigationEvidenceBookmarkModel:
    row = InvestigationEvidenceBookmarkModel(
        workspace_id=int(workspace_id),
        evidence_type=evidence_type,
        evidence_subtype=evidence_subtype,
        source_module=source_module,
        title=title,
        summary=summary,
        agent_id=agent_id,
        observed_at=observed_at,
        created_by=created_by,
        ref_id=ref_id,
        ref_table=ref_table,
        fingerprint=fingerprint,
        dedupe_key=dedupe_key,
        tags=tags,
        payload_snapshot=payload_snapshot,
        metadata_json=metadata,
    )
    db.add(row)
    return row


def delete_bookmark(db: Session, row: InvestigationEvidenceBookmarkModel) -> None:
    db.delete(row)


def count_bookmarks_by_workspace(db: Session, workspace_id: int) -> int:
    stmt = select(func.count(InvestigationEvidenceBookmarkModel.id)).where(
        InvestigationEvidenceBookmarkModel.workspace_id == int(workspace_id)
    )
    return int(db.execute(stmt).scalar() or 0)


def count_bookmarks_grouped_by_type(db: Session, workspace_id: int) -> dict[str, int]:
    stmt = (
        select(
            InvestigationEvidenceBookmarkModel.evidence_type,
            func.count(InvestigationEvidenceBookmarkModel.id).label("c"),
        )
        .where(
            InvestigationEvidenceBookmarkModel.workspace_id == int(workspace_id)
        )
        .group_by(InvestigationEvidenceBookmarkModel.evidence_type)
    )
    out: dict[str, int] = {}
    for evidence_type, count in db.execute(stmt).all():
        k = str(evidence_type or "").strip()
        if not k:
            continue
        out[k] = int(count or 0)
    return out


def get_event(db: Session, event_id: int) -> NetEventModel | None:
    return db.get(NetEventModel, int(event_id))


def get_inventory_snapshot(db: Session, snapshot_id: int) -> AgentInventorySnapshotModel | None:
    return db.get(AgentInventorySnapshotModel, int(snapshot_id))


def get_response_action_result(db: Session, result_id: int) -> ResponseActionResultModel | None:
    return db.get(ResponseActionResultModel, int(result_id))


def get_response_action(db: Session, action_id: int) -> ResponseActionModel | None:
    return db.get(ResponseActionModel, int(action_id))


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()
