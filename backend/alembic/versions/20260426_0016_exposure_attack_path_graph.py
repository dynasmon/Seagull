
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "20260426_0016"
down_revision = "20260422_0015"
branch_labels = None
depends_on = None


def _inspector():
    return inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    return table_name in set(_inspector().get_table_names(schema="public"))


def _has_column(table_name: str, column_name: str) -> bool:
    if not _has_table(table_name):
        return False
    return column_name in {col["name"] for col in _inspector().get_columns(table_name, schema="public")}


def _has_index(table_name: str, index_name: str) -> bool:
    if not _has_table(table_name):
        return False
    return index_name in {idx["name"] for idx in _inspector().get_indexes(table_name, schema="public")}


def upgrade() -> None:
    # exposure_asset_posture
    if not _has_table("exposure_asset_posture"):
        op.create_table(
            "exposure_asset_posture",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("asset_key", sa.String(length=256), nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=True),
            sa.Column("asset_type", sa.String(length=32), nullable=False, server_default="agent"),
            sa.Column("display_name", sa.String(length=256), nullable=False, server_default=""),
            sa.Column("hostname", sa.String(length=256), nullable=True),
            sa.Column("environment", sa.String(length=64), nullable=True),
            sa.Column("criticality", sa.String(length=16), nullable=False, server_default="unknown"),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default="unknown"),
            sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
            sa.Column("exposure_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("vulnerability_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("active_threat_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("persistence_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("attack_chain_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("asset_criticality_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("reliability_penalty", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="unknown"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("score_breakdown", JSONB(), nullable=False, server_default="{}"),
            sa.Column("reason_codes", JSONB(), nullable=False, server_default="[]"),
            sa.Column("top_recommendations", JSONB(), nullable=False, server_default="[]"),
            sa.Column("evidence_counts", JSONB(), nullable=False, server_default="{}"),
            sa.Column("extra_data", JSONB(), nullable=False, server_default="{}"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("asset_key", name="uq_exposure_asset_posture_asset_key"),
        )
        op.create_index("ix_exposure_asset_posture_id", "exposure_asset_posture", ["id"])
        op.create_index("ix_exposure_asset_posture_asset_key", "exposure_asset_posture", ["asset_key"])
        op.create_index("ix_exposure_asset_posture_agent_id", "exposure_asset_posture", ["agent_id"])
        op.create_index("ix_exposure_asset_posture_last_seen_at", "exposure_asset_posture", ["last_seen_at"])

    # exposure_nodes
    if not _has_table("exposure_nodes"):
        op.create_table(
            "exposure_nodes",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("node_key", sa.String(length=128), nullable=False),
            sa.Column("node_type", sa.String(length=32), nullable=False),
            sa.Column("asset_key", sa.String(length=256), nullable=True),
            sa.Column("agent_id", sa.String(length=64), nullable=True),
            sa.Column("label", sa.String(length=256), nullable=False, server_default=""),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default="unknown"),
            sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("properties", JSONB(), nullable=False, server_default="{}"),
            sa.Column("source_refs", JSONB(), nullable=False, server_default="[]"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("node_key", name="uq_exposure_nodes_node_key"),
        )
        op.create_index("ix_exposure_nodes_id", "exposure_nodes", ["id"])
        op.create_index("ix_exposure_nodes_node_key", "exposure_nodes", ["node_key"])
        op.create_index("ix_exposure_nodes_node_type", "exposure_nodes", ["node_type"])
        op.create_index("ix_exposure_nodes_asset_key", "exposure_nodes", ["asset_key"])
        op.create_index("ix_exposure_nodes_agent_id", "exposure_nodes", ["agent_id"])
        op.create_index("ix_exposure_nodes_last_seen_at", "exposure_nodes", ["last_seen_at"])

    # exposure_edges
    if not _has_table("exposure_edges"):
        op.create_table(
            "exposure_edges",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("edge_key", sa.String(length=128), nullable=False),
            sa.Column("source_node_key", sa.String(length=128), nullable=False),
            sa.Column("target_node_key", sa.String(length=128), nullable=False),
            sa.Column("edge_type", sa.String(length=64), nullable=False),
            sa.Column("asset_key", sa.String(length=256), nullable=True),
            sa.Column("agent_id", sa.String(length=64), nullable=True),
            sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("properties", JSONB(), nullable=False, server_default="{}"),
            sa.Column("evidence_refs", JSONB(), nullable=False, server_default="[]"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("edge_key", name="uq_exposure_edges_edge_key"),
        )
        op.create_index("ix_exposure_edges_id", "exposure_edges", ["id"])
        op.create_index("ix_exposure_edges_edge_key", "exposure_edges", ["edge_key"])
        op.create_index("ix_exposure_edges_source_node_key", "exposure_edges", ["source_node_key"])
        op.create_index("ix_exposure_edges_target_node_key", "exposure_edges", ["target_node_key"])
        op.create_index("ix_exposure_edges_edge_type", "exposure_edges", ["edge_type"])
        op.create_index("ix_exposure_edges_asset_key", "exposure_edges", ["asset_key"])
        op.create_index("ix_exposure_edges_agent_id", "exposure_edges", ["agent_id"])
        op.create_index("ix_exposure_edges_last_seen_at", "exposure_edges", ["last_seen_at"])

    # exposure_findings
    if not _has_table("exposure_findings"):
        op.create_table(
            "exposure_findings",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("finding_key", sa.String(length=128), nullable=False),
            sa.Column("asset_key", sa.String(length=256), nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=True),
            sa.Column("finding_type", sa.String(length=32), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default="unknown"),
            sa.Column("score_delta", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
            sa.Column("title", sa.Text(), nullable=False, server_default=""),
            sa.Column("summary", sa.Text(), nullable=False, server_default=""),
            sa.Column("status", sa.String(length=24), nullable=False, server_default="open"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("related_node_keys", JSONB(), nullable=False, server_default="[]"),
            sa.Column("evidence_refs", JSONB(), nullable=False, server_default="[]"),
            sa.Column("reason_codes", JSONB(), nullable=False, server_default="[]"),
            sa.Column("recommendations", JSONB(), nullable=False, server_default="[]"),
            sa.Column("extra_data", JSONB(), nullable=False, server_default="{}"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("finding_key", name="uq_exposure_findings_finding_key"),
        )
        op.create_index("ix_exposure_findings_id", "exposure_findings", ["id"])
        op.create_index("ix_exposure_findings_finding_key", "exposure_findings", ["finding_key"])
        op.create_index("ix_exposure_findings_asset_key", "exposure_findings", ["asset_key"])
        op.create_index("ix_exposure_findings_agent_id", "exposure_findings", ["agent_id"])
        op.create_index("ix_exposure_findings_finding_type", "exposure_findings", ["finding_type"])
        op.create_index("ix_exposure_findings_severity", "exposure_findings", ["severity"])
        op.create_index("ix_exposure_findings_status", "exposure_findings", ["status"])
        op.create_index("ix_exposure_findings_last_seen_at", "exposure_findings", ["last_seen_at"])

    # exposure_score_history
    if not _has_table("exposure_score_history"):
        op.create_table(
            "exposure_score_history",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("asset_key", sa.String(length=256), nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=True),
            sa.Column("bucket_ts", sa.DateTime(timezone=True), nullable=False),
            sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default="unknown"),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
            sa.Column("score_breakdown", JSONB(), nullable=False, server_default="{}"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_exposure_score_history_id", "exposure_score_history", ["id"])
        op.create_index("ix_exposure_score_history_asset_key", "exposure_score_history", ["asset_key"])
        op.create_index("ix_exposure_score_history_agent_id", "exposure_score_history", ["agent_id"])
        op.create_index("ix_exposure_score_history_bucket_ts", "exposure_score_history", ["bucket_ts"])


def downgrade() -> None:
    for table in (
        "exposure_score_history",
        "exposure_findings",
        "exposure_edges",
        "exposure_nodes",
        "exposure_asset_posture",
    ):
        if _has_table(table):
            op.drop_table(table)
