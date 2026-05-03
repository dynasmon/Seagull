"""Correlation incident, evidence, rule run, and entity state tables.

Revision ID: 20260503_0017
Revises: 20260426_0016
Create Date: 2026-05-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects.postgresql import JSONB


revision = "20260503_0017"
down_revision = "20260426_0016"
branch_labels = None
depends_on = None


def _inspector():
    return inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    return table_name in set(_inspector().get_table_names(schema="public"))


def _has_index(table_name: str, index_name: str) -> bool:
    if not _has_table(table_name):
        return False
    return index_name in {idx["name"] for idx in _inspector().get_indexes(table_name, schema="public")}


def upgrade() -> None:
    if not _has_table("correlation_incidents"):
        op.create_table(
            "correlation_incidents",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("correlation_rule_id", sa.Integer(), nullable=True),
            sa.Column("correlation_rule_name", sa.String(length=96), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default="high"),
            sa.Column("risk_score", sa.Integer(), nullable=True),
            sa.Column("confidence", sa.Integer(), nullable=True),
            sa.Column("entity_type", sa.String(length=32), nullable=True),
            sa.Column("entity_value", sa.String(length=256), nullable=True),
            sa.Column("group_by", sa.String(length=32), nullable=False, server_default="src_ip"),
            sa.Column("group_value", sa.String(length=256), nullable=False, server_default=""),
            sa.Column("dedup_key", sa.String(length=512), nullable=False),
            sa.Column("started_at", sa.DateTime(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(), nullable=False),
            sa.Column("closed_at", sa.DateTime(), nullable=True),
            sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("unique_rules", JSONB(), nullable=False, server_default="[]"),
            sa.Column("stage_hits", JSONB(), nullable=False, server_default="{}"),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("context", JSONB(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_correlation_incidents_id", "correlation_incidents", ["id"])
        op.create_index("ix_correlation_incidents_dedup_key", "correlation_incidents", ["dedup_key"])
        op.create_index("ix_correlation_incidents_status_last_seen_at", "correlation_incidents", ["status", "last_seen_at"])
        op.create_index("ix_correlation_incidents_rule_status_last_seen", "correlation_incidents", ["correlation_rule_id", "status", "last_seen_at"])
        op.create_index("ix_correlation_incidents_entity_last_seen", "correlation_incidents", ["entity_type", "entity_value", "last_seen_at"])

    if not _has_table("correlation_incident_evidence"):
        op.create_table(
            "correlation_incident_evidence",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("incident_id", sa.Integer(), sa.ForeignKey("correlation_incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("alert_id", sa.Integer(), nullable=True),
            sa.Column("net_event_id", sa.Integer(), nullable=True),
            sa.Column("evidence_type", sa.String(length=32), nullable=False, server_default="alert"),
            sa.Column("rule_id", sa.String(length=128), nullable=True),
            sa.Column("stage", sa.String(length=64), nullable=True),
            sa.Column("timestamp", sa.DateTime(), nullable=False),
            sa.Column("src_ip", sa.String(length=64), nullable=True),
            sa.Column("dst_ip", sa.String(length=64), nullable=True),
            sa.Column("dst_port", sa.Integer(), nullable=True),
            sa.Column("details", JSONB(), nullable=False, server_default="{}"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_correlation_incident_evidence_id", "correlation_incident_evidence", ["id"])
        op.create_index("ix_correlation_incident_evidence_incident_ts", "correlation_incident_evidence", ["incident_id", "timestamp"])
        op.create_index("ix_correlation_incident_evidence_alert_id", "correlation_incident_evidence", ["alert_id"])
        op.create_index("ix_correlation_incident_evidence_net_event_id", "correlation_incident_evidence", ["net_event_id"])

    if not _has_table("correlation_rule_runs"):
        op.create_table(
            "correlation_rule_runs",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("correlation_rule_id", sa.Integer(), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=False),
            sa.Column("finished_at", sa.DateTime(), nullable=True),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="running"),
            sa.Column("scanned_alerts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("incidents_created", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("incidents_updated", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("context", JSONB(), nullable=False, server_default="{}"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_correlation_rule_runs_id", "correlation_rule_runs", ["id"])
        op.create_index("ix_correlation_rule_runs_started_at", "correlation_rule_runs", ["started_at"])

    if not _has_table("correlation_entity_states"):
        op.create_table(
            "correlation_entity_states",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("entity_type", sa.String(length=32), nullable=False),
            sa.Column("entity_value", sa.String(length=256), nullable=False),
            sa.Column("first_seen_at", sa.DateTime(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(), nullable=False),
            sa.Column("seen_count", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("last_context", JSONB(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("entity_type", "entity_value", name="uq_correlation_entity_states_type_value"),
        )
        op.create_index("ix_correlation_entity_states_id", "correlation_entity_states", ["id"])
        op.create_index("ix_correlation_entity_states_type_value", "correlation_entity_states", ["entity_type", "entity_value"])
        op.create_index("ix_correlation_entity_states_last_seen_at", "correlation_entity_states", ["last_seen_at"])


def downgrade() -> None:
    for table in (
        "correlation_entity_states",
        "correlation_rule_runs",
        "correlation_incident_evidence",
        "correlation_incidents",
    ):
        if _has_table(table):
            op.drop_table(table)
