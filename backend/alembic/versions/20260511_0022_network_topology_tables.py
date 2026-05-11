"""network topology tables

Revision ID: 20260511_0022
Revises: 20260506_0021
Create Date: 2026-05-11
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "20260511_0022"
down_revision = "20260506_0021"
branch_labels = None
depends_on = None


def _has_table(table: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    )
    return result.fetchone() is not None


def _has_index(table: str, index: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            "SELECT 1 FROM pg_indexes WHERE tablename = :t AND indexname = :i"
        ),
        {"t": table, "i": index},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    if not _has_table("network_topology_nodes"):
        op.create_table(
            "network_topology_nodes",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("node_key", sa.String(256), nullable=False),
            sa.Column("node_type", sa.String(32), nullable=False),
            sa.Column("agent_id", sa.String(64), nullable=True),
            sa.Column("label", sa.String(256), nullable=False, server_default=""),
            sa.Column("ip", sa.String(64), nullable=True),
            sa.Column("cidr", sa.String(64), nullable=True),
            sa.Column("port", sa.Integer(), nullable=True),
            sa.Column("protocol", sa.String(16), nullable=True),
            sa.Column("severity", sa.String(16), nullable=False, server_default="unknown"),
            sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
            sa.Column("is_stale", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("extra_data", JSONB(), nullable=False, server_default="{}"),
        )

    for idx_name, cols in [
        ("ix_topo_nodes_id", ["id"]),
        ("ix_topo_nodes_node_key", ["node_key"]),
        ("ix_topo_nodes_node_type", ["node_type"]),
        ("ix_topo_nodes_agent_id", ["agent_id"]),
        ("ix_topo_nodes_ip", ["ip"]),
        ("ix_topo_nodes_cidr", ["cidr"]),
        ("ix_topo_nodes_severity", ["severity"]),
        ("ix_topo_nodes_last_seen", ["last_seen_at"]),
    ]:
        if not _has_index("network_topology_nodes", idx_name):
            unique = idx_name == "ix_topo_nodes_node_key"
            op.create_index(idx_name, "network_topology_nodes", cols, unique=unique)

    if not _has_table("network_topology_edges"):
        op.create_table(
            "network_topology_edges",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("edge_key", sa.String(256), nullable=False),
            sa.Column("source_node_key", sa.String(256), nullable=False),
            sa.Column("target_node_key", sa.String(256), nullable=False),
            sa.Column("edge_type", sa.String(64), nullable=False),
            sa.Column("agent_id", sa.String(64), nullable=True),
            sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
            sa.Column("severity", sa.String(16), nullable=False, server_default="unknown"),
            sa.Column("port", sa.Integer(), nullable=True),
            sa.Column("protocol", sa.String(16), nullable=True),
            sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("extra_data", JSONB(), nullable=False, server_default="{}"),
        )

    for idx_name, cols in [
        ("ix_topo_edges_id", ["id"]),
        ("ix_topo_edges_edge_key", ["edge_key"]),
        ("ix_topo_edges_src", ["source_node_key"]),
        ("ix_topo_edges_dst", ["target_node_key"]),
        ("ix_topo_edges_type", ["edge_type"]),
        ("ix_topo_edges_agent", ["agent_id"]),
        ("ix_topo_edges_severity", ["severity"]),
        ("ix_topo_edges_last_seen", ["last_seen_at"]),
    ]:
        if not _has_index("network_topology_edges", idx_name):
            unique = idx_name == "ix_topo_edges_edge_key"
            op.create_index(idx_name, "network_topology_edges", cols, unique=unique)

    if not _has_table("network_topology_observations"):
        op.create_table(
            "network_topology_observations",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("node_key", sa.String(256), nullable=False),
            sa.Column("edge_key", sa.String(256), nullable=True),
            sa.Column("agent_id", sa.String(64), nullable=True),
            sa.Column("source_type", sa.String(32), nullable=False),
            sa.Column("source_id", sa.String(128), nullable=True),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("summary", sa.String(512), nullable=False, server_default=""),
            sa.Column("raw_context", JSONB(), nullable=False, server_default="{}"),
        )

    for idx_name, cols in [
        ("ix_topo_obs_id", ["id"]),
        ("ix_topo_obs_node_key", ["node_key"]),
        ("ix_topo_obs_edge_key", ["edge_key"]),
        ("ix_topo_obs_agent", ["agent_id"]),
        ("ix_topo_obs_source_type", ["source_type"]),
        ("ix_topo_obs_observed_at", ["observed_at"]),
    ]:
        if not _has_index("network_topology_observations", idx_name):
            op.create_index(idx_name, "network_topology_observations", cols)

    if not _has_table("network_topology_snapshots"):
        op.create_table(
            "network_topology_snapshots",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("snapshot_key", sa.String(128), nullable=False),
            sa.Column("node_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("edge_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("agent_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("subnet_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("external_ip_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("coverage", JSONB(), nullable=False, server_default="{}"),
            sa.Column("metrics", JSONB(), nullable=False, server_default="{}"),
        )

    for idx_name, cols in [
        ("ix_topo_snapshots_id", ["id"]),
        ("ix_topo_snapshots_key", ["snapshot_key"]),
    ]:
        if not _has_index("network_topology_snapshots", idx_name):
            unique = idx_name == "ix_topo_snapshots_key"
            op.create_index(idx_name, "network_topology_snapshots", cols, unique=unique)


def downgrade() -> None:
    for idx in [
        "ix_topo_snapshots_key",
        "ix_topo_snapshots_id",
    ]:
        if _has_index("network_topology_snapshots", idx):
            op.drop_index(idx, table_name="network_topology_snapshots")
    if _has_table("network_topology_snapshots"):
        op.drop_table("network_topology_snapshots")

    for idx in [
        "ix_topo_obs_observed_at",
        "ix_topo_obs_source_type",
        "ix_topo_obs_agent",
        "ix_topo_obs_edge_key",
        "ix_topo_obs_node_key",
        "ix_topo_obs_id",
    ]:
        if _has_index("network_topology_observations", idx):
            op.drop_index(idx, table_name="network_topology_observations")
    if _has_table("network_topology_observations"):
        op.drop_table("network_topology_observations")

    for idx in [
        "ix_topo_edges_last_seen",
        "ix_topo_edges_severity",
        "ix_topo_edges_agent",
        "ix_topo_edges_type",
        "ix_topo_edges_dst",
        "ix_topo_edges_src",
        "ix_topo_edges_edge_key",
        "ix_topo_edges_id",
    ]:
        if _has_index("network_topology_edges", idx):
            op.drop_index(idx, table_name="network_topology_edges")
    if _has_table("network_topology_edges"):
        op.drop_table("network_topology_edges")

    for idx in [
        "ix_topo_nodes_last_seen",
        "ix_topo_nodes_severity",
        "ix_topo_nodes_cidr",
        "ix_topo_nodes_ip",
        "ix_topo_nodes_agent_id",
        "ix_topo_nodes_node_type",
        "ix_topo_nodes_node_key",
        "ix_topo_nodes_id",
    ]:
        if _has_index("network_topology_nodes", idx):
            op.drop_index(idx, table_name="network_topology_nodes")
    if _has_table("network_topology_nodes"):
        op.drop_table("network_topology_nodes")
