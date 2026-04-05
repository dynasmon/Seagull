from __future__ import annotations

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class InvestigationWorkspaceModel(Base):
    __tablename__ = "investigation_workspaces"
    __table_args__ = (
        Index("ix_investigation_workspaces_updated_id", "updated_at", "id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    workspace_key = Column(String(48), nullable=False, unique=True, index=True)

    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)

    status = Column(String(16), nullable=False, default="open", index=True)
    severity = Column(String(16), nullable=False, default="medium", index=True)
    priority = Column(String(8), nullable=False, default="p3", index=True)

    assignee = Column(String(128), nullable=True, index=True)

    created_by = Column(String(64), nullable=False)
    updated_by = Column(String(64), nullable=False)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now(), index=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    linked_attack_chain_case_id = Column(
        Integer,
        ForeignKey("attack_chain_cases.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    primary_agent_id = Column(String(64), nullable=True, index=True)

    # Lightweight counters + workflow metadata (e.g., triage state).
    summary = Column(JSONB, nullable=True, default=dict)


class InvestigationNoteModel(Base):
    __tablename__ = "investigation_notes"
    __table_args__ = (
        Index("ix_investigation_notes_workspace_created", "workspace_id", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("investigation_workspaces.id", ondelete="CASCADE"), nullable=False, index=True)

    author = Column(String(64), nullable=False)
    body = Column(Text, nullable=False)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class InvestigationEvidenceBookmarkModel(Base):
    __tablename__ = "investigation_evidence_bookmarks"
    __table_args__ = (
        UniqueConstraint("workspace_id", "dedupe_key", name="uq_investigation_bookmarks_workspace_dedupe"),
        Index("ix_investigation_bookmarks_workspace_created", "workspace_id", "created_at"),
        Index("ix_investigation_bookmarks_workspace_type", "workspace_id", "evidence_type"),
    )

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("investigation_workspaces.id", ondelete="CASCADE"), nullable=False, index=True)

    evidence_type = Column(String(32), nullable=False, index=True)
    evidence_subtype = Column(String(64), nullable=True)
    source_module = Column(String(64), nullable=False)

    title = Column(String(200), nullable=False)
    summary = Column(Text, nullable=True)

    agent_id = Column(String(64), nullable=True, index=True)
    observed_at = Column(DateTime(timezone=True), nullable=True, index=True)

    created_by = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)

    ref_id = Column(String(128), nullable=True)
    ref_table = Column(String(64), nullable=True)
    fingerprint = Column(String(128), nullable=True)
    dedupe_key = Column(String(128), nullable=False)

    tags = Column(JSONB, nullable=True, default=list)
    payload_snapshot = Column(JSONB, nullable=False, default=dict)
    metadata_json = Column("metadata", JSONB, nullable=True, default=dict)
