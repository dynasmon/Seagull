
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260405_0012"
down_revision = "20260404_0011"
branch_labels = None
depends_on = None


def _inspector():
    return inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    return table_name in set(_inspector().get_table_names(schema="public"))


def _has_index(table_name: str, index_name: str) -> bool:
    if not _has_table(table_name):
        return False
    idx = _inspector().get_indexes(table_name, schema="public")
    return any(str(i.get("name")) == index_name for i in idx)


def _has_unique(table_name: str, constraint_name: str) -> bool:
    if not _has_table(table_name):
        return False
    rows = _inspector().get_unique_constraints(table_name, schema="public")
    return any(str(r.get("name")) == constraint_name for r in rows)


def upgrade() -> None:
    if not _has_table("investigation_workspaces"):
        op.create_table(
            "investigation_workspaces",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("workspace_key", sa.String(length=48), nullable=False),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("status", sa.String(length=16), nullable=False, server_default=sa.text("'open'")),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default=sa.text("'medium'")),
            sa.Column("priority", sa.String(length=8), nullable=False, server_default=sa.text("'p3'")),
            sa.Column("assignee", sa.String(length=128), nullable=True),
            sa.Column("created_by", sa.String(length=64), nullable=False),
            sa.Column("updated_by", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("linked_attack_chain_case_id", sa.Integer(), nullable=True),
            sa.Column("primary_agent_id", sa.String(length=64), nullable=True),
            sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'{}'::jsonb")),
            sa.ForeignKeyConstraint(["linked_attack_chain_case_id"], ["attack_chain_cases.id"], ondelete="SET NULL"),
            sa.UniqueConstraint("workspace_key", name="uq_investigation_workspaces_workspace_key"),
        )

    if not _has_index("investigation_workspaces", "ix_investigation_workspaces_workspace_key"):
        op.create_index("ix_investigation_workspaces_workspace_key", "investigation_workspaces", ["workspace_key"], unique=False)
    if not _has_index("investigation_workspaces", "ix_investigation_workspaces_status"):
        op.create_index("ix_investigation_workspaces_status", "investigation_workspaces", ["status"], unique=False)
    if not _has_index("investigation_workspaces", "ix_investigation_workspaces_severity"):
        op.create_index("ix_investigation_workspaces_severity", "investigation_workspaces", ["severity"], unique=False)
    if not _has_index("investigation_workspaces", "ix_investigation_workspaces_priority"):
        op.create_index("ix_investigation_workspaces_priority", "investigation_workspaces", ["priority"], unique=False)
    if not _has_index("investigation_workspaces", "ix_investigation_workspaces_assignee"):
        op.create_index("ix_investigation_workspaces_assignee", "investigation_workspaces", ["assignee"], unique=False)
    if not _has_index("investigation_workspaces", "ix_investigation_workspaces_updated_at"):
        op.create_index("ix_investigation_workspaces_updated_at", "investigation_workspaces", ["updated_at"], unique=False)
    if not _has_index("investigation_workspaces", "ix_investigation_workspaces_linked_attack_chain_case_id"):
        op.create_index(
            "ix_investigation_workspaces_linked_attack_chain_case_id",
            "investigation_workspaces",
            ["linked_attack_chain_case_id"],
            unique=False,
        )
    if not _has_index("investigation_workspaces", "ix_investigation_workspaces_primary_agent_id"):
        op.create_index("ix_investigation_workspaces_primary_agent_id", "investigation_workspaces", ["primary_agent_id"], unique=False)
    if not _has_index("investigation_workspaces", "ix_investigation_workspaces_updated_id"):
        op.create_index("ix_investigation_workspaces_updated_id", "investigation_workspaces", ["updated_at", "id"], unique=False)

    if not _has_table("investigation_notes"):
        op.create_table(
            "investigation_notes",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("workspace_id", sa.Integer(), nullable=False),
            sa.Column("author", sa.String(length=64), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.ForeignKeyConstraint(["workspace_id"], ["investigation_workspaces.id"], ondelete="CASCADE"),
        )

    if not _has_index("investigation_notes", "ix_investigation_notes_workspace_id"):
        op.create_index("ix_investigation_notes_workspace_id", "investigation_notes", ["workspace_id"], unique=False)
    if not _has_index("investigation_notes", "ix_investigation_notes_workspace_created"):
        op.create_index("ix_investigation_notes_workspace_created", "investigation_notes", ["workspace_id", "created_at"], unique=False)

    if not _has_table("investigation_evidence_bookmarks"):
        op.create_table(
            "investigation_evidence_bookmarks",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("workspace_id", sa.Integer(), nullable=False),
            sa.Column("evidence_type", sa.String(length=32), nullable=False),
            sa.Column("evidence_subtype", sa.String(length=64), nullable=True),
            sa.Column("source_module", sa.String(length=64), nullable=False),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("agent_id", sa.String(length=64), nullable=True),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("ref_id", sa.String(length=128), nullable=True),
            sa.Column("ref_table", sa.String(length=64), nullable=True),
            sa.Column("fingerprint", sa.String(length=128), nullable=True),
            sa.Column("dedupe_key", sa.String(length=128), nullable=False),
            sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'[]'::jsonb")),
            sa.Column("payload_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'{}'::jsonb")),
            sa.ForeignKeyConstraint(["workspace_id"], ["investigation_workspaces.id"], ondelete="CASCADE"),
        )

    if not _has_unique("investigation_evidence_bookmarks", "uq_investigation_bookmarks_workspace_dedupe"):
        op.create_unique_constraint(
            "uq_investigation_bookmarks_workspace_dedupe",
            "investigation_evidence_bookmarks",
            ["workspace_id", "dedupe_key"],
        )

    if not _has_index("investigation_evidence_bookmarks", "ix_investigation_evidence_bookmarks_workspace_id"):
        op.create_index(
            "ix_investigation_evidence_bookmarks_workspace_id",
            "investigation_evidence_bookmarks",
            ["workspace_id"],
            unique=False,
        )
    if not _has_index("investigation_evidence_bookmarks", "ix_investigation_evidence_bookmarks_evidence_type"):
        op.create_index(
            "ix_investigation_evidence_bookmarks_evidence_type",
            "investigation_evidence_bookmarks",
            ["evidence_type"],
            unique=False,
        )
    if not _has_index("investigation_evidence_bookmarks", "ix_investigation_evidence_bookmarks_agent_id"):
        op.create_index(
            "ix_investigation_evidence_bookmarks_agent_id",
            "investigation_evidence_bookmarks",
            ["agent_id"],
            unique=False,
        )
    if not _has_index("investigation_evidence_bookmarks", "ix_investigation_evidence_bookmarks_observed_at"):
        op.create_index(
            "ix_investigation_evidence_bookmarks_observed_at",
            "investigation_evidence_bookmarks",
            ["observed_at"],
            unique=False,
        )
    if not _has_index("investigation_evidence_bookmarks", "ix_investigation_bookmarks_workspace_created"):
        op.create_index(
            "ix_investigation_bookmarks_workspace_created",
            "investigation_evidence_bookmarks",
            ["workspace_id", "created_at"],
            unique=False,
        )
    if not _has_index("investigation_evidence_bookmarks", "ix_investigation_bookmarks_workspace_type"):
        op.create_index(
            "ix_investigation_bookmarks_workspace_type",
            "investigation_evidence_bookmarks",
            ["workspace_id", "evidence_type"],
            unique=False,
        )


def downgrade() -> None:
    if _has_table("investigation_evidence_bookmarks"):
        op.drop_table("investigation_evidence_bookmarks")

    if _has_table("investigation_notes"):
        op.drop_table("investigation_notes")

    if _has_table("investigation_workspaces"):
        op.drop_table("investigation_workspaces")
