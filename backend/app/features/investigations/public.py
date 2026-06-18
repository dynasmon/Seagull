from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlalchemy import exists, or_, select
from sqlalchemy.orm import Session

from app.features.investigations import repository, service
from app.features.investigations.models import InvestigationEvidenceBookmarkModel, InvestigationWorkspaceModel
from app.features.investigations.schemas import (
    InvestigationBookmarkCreateResult,
    InvestigationPinOptionsIn,
    InvestigationWorkspaceCreateIn,
    InvestigationWorkspaceOut,
)

__all__ = [
    "InvestigationBookmarkCreateResult",
    "InvestigationBookmarkDTO",
    "InvestigationEvidenceRefDTO",
    "InvestigationPinOptionsIn",
    "InvestigationWorkspaceContextDTO",
    "InvestigationWorkspaceCreateIn",
    "InvestigationWorkspaceDTO",
    "InvestigationWorkspaceOut",
    "create_bookmark",
    "create_workspace",
    "find_bookmark_by_dedupe",
    "list_evidence_bookmarks_for_agent",
    "list_open_workspaces_for_agent",
    "list_open_workspaces_for_context",
    "list_workspaces_for_asset",
    "merge_workspace_summary",
    "pin_attack_chain_case",
    "refresh_workspace_summary",
]

_OPEN_WORKSPACE_STATUSES = ("open", "contained")


class InvestigationWorkspaceDTO(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    workspace_key: str
    title: str
    status: str
    severity: str
    priority: str
    assignee: str | None
    updated_at: datetime
    linked_attack_chain_case_id: int | None
    summary: dict[str, Any]


class InvestigationWorkspaceContextDTO(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    workspace_key: str
    title: str
    status: str
    severity: str
    linked_attack_chain_case_id: int | None
    updated_at: datetime


class InvestigationEvidenceRefDTO(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    workspace_id: int
    evidence_type: str
    title: str
    summary: str | None
    observed_at: datetime | None
    ref_id: str | None


class InvestigationBookmarkDTO(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int


def _to_workspace_dto(row: InvestigationWorkspaceModel) -> InvestigationWorkspaceDTO:
    return InvestigationWorkspaceDTO(
        id=row.id,
        workspace_key=row.workspace_key,
        title=row.title,
        status=row.status,
        severity=row.severity,
        priority=row.priority,
        assignee=row.assignee,
        updated_at=row.updated_at,
        linked_attack_chain_case_id=row.linked_attack_chain_case_id,
        summary=row.summary or {},
    )


def list_workspaces_for_asset(
    db: Session,
    *,
    asset_key: str,
    agent_id: str | None,
    limit: int,
) -> list[InvestigationWorkspaceDTO]:
    bookmark_exists = exists(
        select(InvestigationEvidenceBookmarkModel.id).where(
            InvestigationEvidenceBookmarkModel.workspace_id == InvestigationWorkspaceModel.id,
            InvestigationEvidenceBookmarkModel.metadata_json["asset_key"].astext == asset_key,
        )
    )
    conditions = [bookmark_exists, InvestigationWorkspaceModel.summary["exposure_asset_key"].astext == asset_key]
    if agent_id:
        conditions.append(InvestigationWorkspaceModel.primary_agent_id == agent_id)
        conditions.append(
            exists(
                select(InvestigationEvidenceBookmarkModel.id).where(
                    InvestigationEvidenceBookmarkModel.workspace_id == InvestigationWorkspaceModel.id,
                    InvestigationEvidenceBookmarkModel.agent_id == agent_id,
                )
            )
        )
    stmt = (
        select(InvestigationWorkspaceModel)
        .where(or_(*conditions))
        .order_by(InvestigationWorkspaceModel.updated_at.desc(), InvestigationWorkspaceModel.id.desc())
        .limit(max(1, int(limit)))
    )
    return [_to_workspace_dto(row) for row in db.execute(stmt).scalars().all()]


def list_open_workspaces_for_context(
    db: Session,
    *,
    asset_key: str,
    agent_id: str | None,
    linked_attack_chain_case_id: int | None,
    limit: int,
) -> list[InvestigationWorkspaceDTO]:
    conditions = [InvestigationWorkspaceModel.summary["exposure_asset_key"].astext == asset_key]
    if agent_id:
        conditions.append(InvestigationWorkspaceModel.primary_agent_id == agent_id)
    if linked_attack_chain_case_id is not None:
        conditions.append(InvestigationWorkspaceModel.linked_attack_chain_case_id == int(linked_attack_chain_case_id))
    stmt = (
        select(InvestigationWorkspaceModel)
        .where(
            InvestigationWorkspaceModel.status.in_(_OPEN_WORKSPACE_STATUSES),
            or_(*conditions),
        )
        .order_by(InvestigationWorkspaceModel.updated_at.desc(), InvestigationWorkspaceModel.id.desc())
        .limit(max(1, int(limit)))
    )
    return [_to_workspace_dto(row) for row in db.execute(stmt).scalars().all()]


def list_open_workspaces_for_agent(
    db: Session,
    *,
    agent_id: str,
    limit: int,
) -> list[InvestigationWorkspaceContextDTO]:
    stmt = (
        select(
            InvestigationWorkspaceModel.id,
            InvestigationWorkspaceModel.workspace_key,
            InvestigationWorkspaceModel.title,
            InvestigationWorkspaceModel.status,
            InvestigationWorkspaceModel.severity,
            InvestigationWorkspaceModel.linked_attack_chain_case_id,
            InvestigationWorkspaceModel.updated_at,
        )
        .where(
            InvestigationWorkspaceModel.primary_agent_id == agent_id,
            InvestigationWorkspaceModel.status.in_(["open", "active", "in_progress"]),
        )
        .order_by(InvestigationWorkspaceModel.updated_at.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).mappings().all()
    return [
        InvestigationWorkspaceContextDTO(
            id=r["id"],
            workspace_key=r["workspace_key"],
            title=r["title"],
            status=r["status"],
            severity=r["severity"],
            linked_attack_chain_case_id=r["linked_attack_chain_case_id"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]


def list_evidence_bookmarks_for_agent(
    db: Session,
    *,
    agent_id: str,
    limit: int,
) -> list[InvestigationEvidenceRefDTO]:
    stmt = (
        select(
            InvestigationEvidenceBookmarkModel.id,
            InvestigationEvidenceBookmarkModel.workspace_id,
            InvestigationEvidenceBookmarkModel.evidence_type,
            InvestigationEvidenceBookmarkModel.title,
            InvestigationEvidenceBookmarkModel.summary,
            InvestigationEvidenceBookmarkModel.observed_at,
            InvestigationEvidenceBookmarkModel.ref_id,
        )
        .where(InvestigationEvidenceBookmarkModel.agent_id == agent_id)
        .order_by(
            InvestigationEvidenceBookmarkModel.observed_at.desc().nullslast(),
            InvestigationEvidenceBookmarkModel.id.desc(),
        )
        .limit(limit)
    )
    rows = db.execute(stmt).mappings().all()
    return [
        InvestigationEvidenceRefDTO(
            id=r["id"],
            workspace_id=r["workspace_id"],
            evidence_type=r["evidence_type"],
            title=r["title"],
            summary=r["summary"],
            observed_at=r["observed_at"],
            ref_id=r["ref_id"],
        )
        for r in rows
    ]


def create_workspace(
    db: Session,
    *,
    payload: InvestigationWorkspaceCreateIn,
    request,
    user,
    audit_writer,
) -> InvestigationWorkspaceOut:
    return service.create_workspace(db, payload=payload, request=request, user=user, audit_writer=audit_writer)


def pin_attack_chain_case(
    db: Session,
    *,
    workspace_id: int,
    case_id: int,
    payload: InvestigationPinOptionsIn,
    request,
    user,
    audit_writer,
) -> InvestigationBookmarkCreateResult:
    return service.pin_attack_chain_case(
        db,
        workspace_id=workspace_id,
        case_id=case_id,
        payload=payload,
        request=request,
        user=user,
        audit_writer=audit_writer,
    )


def merge_workspace_summary(
    db: Session,
    *,
    workspace_id: int,
    summary_updates: dict[str, Any],
    updated_by: str,
) -> bool:
    row = repository.get_workspace(db, int(workspace_id), for_update=True)
    if row is None:
        return False
    summary = dict(row.summary or {}) if isinstance(row.summary, dict) else {}
    summary.update(summary_updates)
    row.summary = summary
    row.updated_by = updated_by
    repository.save_workspace(db, row)
    return True


def refresh_workspace_summary(db: Session, *, workspace_id: int, updated_by: str) -> bool:
    row = repository.get_workspace(db, int(workspace_id), for_update=True)
    if row is None:
        return False
    summary = dict(row.summary or {}) if isinstance(row.summary, dict) else {}
    summary["notes_count"] = repository.count_notes_by_workspace(db, int(row.id))
    summary["bookmarks_count"] = repository.count_bookmarks_by_workspace(db, int(row.id))
    summary["evidence_type_counts"] = repository.count_bookmarks_grouped_by_type(db, int(row.id))
    if not summary.get("triage_state"):
        summary["triage_state"] = "triage"
    row.summary = summary
    row.updated_by = updated_by
    repository.save_workspace(db, row)
    return True


def find_bookmark_by_dedupe(db: Session, *, workspace_id: int, dedupe_key: str) -> InvestigationBookmarkDTO | None:
    row = repository.find_bookmark_by_dedupe(db, workspace_id=workspace_id, dedupe_key=dedupe_key)
    if row is None:
        return None
    return InvestigationBookmarkDTO(id=row.id)


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
) -> InvestigationBookmarkDTO:
    row = repository.create_bookmark(
        db,
        workspace_id=workspace_id,
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
        metadata=metadata,
    )
    db.flush()
    return InvestigationBookmarkDTO(id=row.id)
