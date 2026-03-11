"""Add administrative audit trail and platform settings tables."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "20260311_0003"
down_revision = "20260309_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)

    tables = set(insp.get_table_names(schema="public"))
    index_names = {
        idx["name"]
        for table_name in tables
        for idx in insp.get_indexes(table_name, schema="public")
    }

    if "admin_audit_events" not in tables:
        op.create_table(
            "admin_audit_events",
            sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
            sa.Column("operation_id", sa.String(length=36), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("event_type", sa.String(length=32), nullable=False, server_default="admin_action"),
            sa.Column("action", sa.String(length=96), nullable=False),
            sa.Column("outcome", sa.String(length=16), nullable=False, server_default="success"),
            sa.Column("actor_user_id", sa.Integer(), nullable=True),
            sa.Column("actor_username", sa.String(length=64), nullable=True),
            sa.Column("resource_type", sa.String(length=48), nullable=False),
            sa.Column("resource_id", sa.String(length=128), nullable=True),
            sa.Column("request_id", sa.String(length=64), nullable=True),
            sa.Column("trace_id", sa.String(length=128), nullable=True),
            sa.Column("ip", sa.String(length=64), nullable=True),
            sa.Column("user_agent", sa.String(length=256), nullable=True),
            sa.Column("method", sa.String(length=16), nullable=True),
            sa.Column("path", sa.String(length=255), nullable=True),
            sa.Column("reason", sa.String(length=255), nullable=True),
            sa.Column("error", sa.String(length=255), nullable=True),
            sa.Column("before", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("after", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("changed_fields", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("context", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("prev_event_hash", sa.String(length=64), nullable=True),
            sa.Column("event_hash", sa.String(length=64), nullable=True),
            sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        )

    tables = set(insp.get_table_names(schema="public"))
    if "idx_admin_audit_created_at" not in index_names and "admin_audit_events" in tables:
        op.create_index("idx_admin_audit_created_at", "admin_audit_events", ["created_at"], unique=False)
    if "idx_admin_audit_timeline" not in index_names and "admin_audit_events" in tables:
        op.create_index(
            "idx_admin_audit_timeline",
            "admin_audit_events",
            ["created_at", "event_type", "action", "resource_type"],
            unique=False,
        )
    if "idx_admin_audit_actor_created" not in index_names and "admin_audit_events" in tables:
        op.create_index(
            "idx_admin_audit_actor_created",
            "admin_audit_events",
            ["actor_user_id", "created_at"],
            unique=False,
        )
    if "ix_admin_audit_events_operation_id" not in index_names and "admin_audit_events" in tables:
        op.create_index("ix_admin_audit_events_operation_id", "admin_audit_events", ["operation_id"], unique=False)
    if "ix_admin_audit_events_action" not in index_names and "admin_audit_events" in tables:
        op.create_index("ix_admin_audit_events_action", "admin_audit_events", ["action"], unique=False)
    if "ix_admin_audit_events_resource_type" not in index_names and "admin_audit_events" in tables:
        op.create_index("ix_admin_audit_events_resource_type", "admin_audit_events", ["resource_type"], unique=False)
    if "ix_admin_audit_events_resource_id" not in index_names and "admin_audit_events" in tables:
        op.create_index("ix_admin_audit_events_resource_id", "admin_audit_events", ["resource_id"], unique=False)
    if "ix_admin_audit_events_actor_user_id" not in index_names and "admin_audit_events" in tables:
        op.create_index("ix_admin_audit_events_actor_user_id", "admin_audit_events", ["actor_user_id"], unique=False)
    if "ix_admin_audit_events_actor_username" not in index_names and "admin_audit_events" in tables:
        op.create_index("ix_admin_audit_events_actor_username", "admin_audit_events", ["actor_username"], unique=False)
    if "ix_admin_audit_events_request_id" not in index_names and "admin_audit_events" in tables:
        op.create_index("ix_admin_audit_events_request_id", "admin_audit_events", ["request_id"], unique=False)
    if "ix_admin_audit_events_trace_id" not in index_names and "admin_audit_events" in tables:
        op.create_index("ix_admin_audit_events_trace_id", "admin_audit_events", ["trace_id"], unique=False)
    if "ix_admin_audit_events_event_hash" not in index_names and "admin_audit_events" in tables:
        op.create_index("ix_admin_audit_events_event_hash", "admin_audit_events", ["event_hash"], unique=False)

    if "platform_settings" not in tables:
        op.create_table(
            "platform_settings",
            sa.Column("key", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("description", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
            sa.Column("updated_by_username", sa.String(length=64), nullable=True),
        )

    tables = set(insp.get_table_names(schema="public"))
    if "idx_platform_settings_updated_at" not in index_names and "platform_settings" in tables:
        op.create_index("idx_platform_settings_updated_at", "platform_settings", ["updated_at"], unique=False)


def downgrade() -> None:
    op.drop_index("idx_platform_settings_updated_at", table_name="platform_settings")
    op.drop_table("platform_settings")

    op.drop_index("ix_admin_audit_events_event_hash", table_name="admin_audit_events")
    op.drop_index("ix_admin_audit_events_trace_id", table_name="admin_audit_events")
    op.drop_index("ix_admin_audit_events_request_id", table_name="admin_audit_events")
    op.drop_index("ix_admin_audit_events_actor_username", table_name="admin_audit_events")
    op.drop_index("ix_admin_audit_events_actor_user_id", table_name="admin_audit_events")
    op.drop_index("ix_admin_audit_events_resource_id", table_name="admin_audit_events")
    op.drop_index("ix_admin_audit_events_resource_type", table_name="admin_audit_events")
    op.drop_index("ix_admin_audit_events_action", table_name="admin_audit_events")
    op.drop_index("ix_admin_audit_events_operation_id", table_name="admin_audit_events")
    op.drop_index("idx_admin_audit_actor_created", table_name="admin_audit_events")
    op.drop_index("idx_admin_audit_timeline", table_name="admin_audit_events")
    op.drop_index("idx_admin_audit_created_at", table_name="admin_audit_events")
    op.drop_table("admin_audit_events")
