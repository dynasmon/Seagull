"""Performance hot paths: denormalized event fields and latest inventory state."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260317_0005"
down_revision = "20260313_0004"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    return bool(sa.inspect(op.get_bind()).has_table(table_name))


def _has_column(table_name: str, column_name: str) -> bool:
    cols = sa.inspect(op.get_bind()).get_columns(table_name)
    return any(str(c.get("name")) == column_name for c in cols)


def _has_index(table_name: str, index_name: str) -> bool:
    indexes = sa.inspect(op.get_bind()).get_indexes(table_name)
    return any(str(i.get("name")) == index_name for i in indexes)


def upgrade() -> None:
    net_event_cols = [
        ("app_proto", sa.String(length=32)),
        ("app_proto_reason", sa.String(length=64)),
        ("app_proto_conf_band", sa.String(length=16)),
        ("dns_qname", sa.String(length=512)),
        ("http_host", sa.String(length=512)),
        ("http_method", sa.String(length=16)),
        ("tls_sni", sa.String(length=512)),
        ("tls_alpn_first", sa.String(length=64)),
        ("ja3", sa.String(length=128)),
        ("ja4", sa.String(length=128)),
        ("ja4_ptype", sa.String(length=8)),
        ("ssh_action", sa.String(length=64)),
        ("ssh_username", sa.String(length=128)),
    ]
    for col_name, col_type in net_event_cols:
        if not _has_column("net_events", col_name):
            op.add_column("net_events", sa.Column(col_name, col_type, nullable=True))

    if not _has_index("net_events", "idx_net_events_recent_brin"):
        op.create_index("idx_net_events_recent_brin", "net_events", ["timestamp"], unique=False, postgresql_using="brin")
    if not _has_index("net_events", "idx_net_events_app_proto_ts"):
        op.create_index("idx_net_events_app_proto_ts", "net_events", ["app_proto", sa.text('"timestamp" DESC')], unique=False)
    if not _has_index("net_events", "idx_net_events_dns_qname_ts"):
        op.create_index("idx_net_events_dns_qname_ts", "net_events", ["dns_qname", sa.text('"timestamp" DESC')], unique=False)
    if not _has_index("net_events", "idx_net_events_http_host_ts"):
        op.create_index("idx_net_events_http_host_ts", "net_events", ["http_host", sa.text('"timestamp" DESC')], unique=False)
    if not _has_index("net_events", "idx_net_events_tls_sni_ts"):
        op.create_index("idx_net_events_tls_sni_ts", "net_events", ["tls_sni", sa.text('"timestamp" DESC')], unique=False)
    if not _has_index("net_events", "idx_net_events_ja4_ts"):
        op.create_index("idx_net_events_ja4_ts", "net_events", ["ja4", sa.text('"timestamp" DESC')], unique=False)
    if not _has_index("net_events", "idx_net_events_ssh_action_col_ts"):
        op.create_index(
            "idx_net_events_ssh_action_col_ts",
            "net_events",
            ["ssh_action", sa.text('"timestamp" DESC')],
            unique=False,
            postgresql_where=sa.text("event_type = 'ssh_auth'"),
        )
    if not _has_index("net_events", "idx_net_events_ssh_user_col_ts"):
        op.create_index(
            "idx_net_events_ssh_user_col_ts",
            "net_events",
            ["ssh_username", sa.text('"timestamp" DESC')],
            unique=False,
            postgresql_where=sa.text("event_type = 'ssh_auth'"),
        )

    if not _has_table("agent_inventory_latest"):
        op.create_table(
            "agent_inventory_latest",
            sa.Column("agent_id", sa.String(length=64), nullable=False),
            sa.Column("snapshot_id", sa.Integer(), nullable=False),
            sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("os", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("packages_count", sa.Integer(), nullable=False),
            sa.Column("packages_hash", sa.String(length=64), nullable=False),
            sa.Column("manager", sa.String(length=32), nullable=True),
            sa.Column("extra", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.PrimaryKeyConstraint("agent_id"),
        )
    if not _has_index("agent_inventory_latest", "idx_inv_latest_collected"):
        op.create_index("idx_inv_latest_collected", "agent_inventory_latest", [sa.text("collected_at DESC")], unique=False)
    if not _has_index("agent_inventory_latest", "idx_inv_latest_packages_count"):
        op.create_index(
            "idx_inv_latest_packages_count",
            "agent_inventory_latest",
            [sa.text("packages_count DESC"), sa.text("agent_id ASC")],
            unique=False,
        )

    # Bounded backfill for recent events to keep migration cost predictable.
    op.execute(
        """
        UPDATE net_events
        SET
          app_proto = NULLIF(extra->>'app_proto', ''),
          app_proto_reason = NULLIF(extra->>'app_proto_reason', ''),
          app_proto_conf_band = NULLIF(extra->>'app_proto_conf_band', ''),
          dns_qname = lower(NULLIF(extra->>'dns_qname', '')),
          http_host = lower(NULLIF(extra->>'http_host', '')),
          http_method = upper(NULLIF(extra->>'http_method', '')),
          tls_sni = lower(NULLIF(extra->>'tls_sni', '')),
          tls_alpn_first = lower(NULLIF(extra->>'tls_alpn_first', '')),
          ja3 = NULLIF(extra->>'ja3', ''),
          ja4 = NULLIF(extra->>'ja4', ''),
          ja4_ptype = COALESCE(NULLIF(extra->>'ja4_ptype', ''), 't'),
          ssh_action = NULLIF(extra->>'action', ''),
          ssh_username = NULLIF(extra->>'username', '')
        WHERE timestamp >= now() - interval '14 days'
        """
    )

    # Materialize latest state per agent for inventory overview.
    op.execute(
        """
        INSERT INTO agent_inventory_latest (
          agent_id, snapshot_id, collected_at, os, packages_count, packages_hash, manager, extra
        )
        SELECT DISTINCT ON (s.agent_id)
          s.agent_id,
          s.id,
          s.collected_at,
          COALESCE(s.os, '{}'::jsonb),
          COALESCE(s.packages_count, 0),
          COALESCE(s.packages_hash, ''),
          s.manager,
          COALESCE(s.extra, '{}'::jsonb)
        FROM agent_inventory_snapshots s
        ORDER BY s.agent_id, s.collected_at DESC, s.id DESC
        ON CONFLICT (agent_id) DO UPDATE SET
          snapshot_id = EXCLUDED.snapshot_id,
          collected_at = EXCLUDED.collected_at,
          os = EXCLUDED.os,
          packages_count = EXCLUDED.packages_count,
          packages_hash = EXCLUDED.packages_hash,
          manager = EXCLUDED.manager,
          extra = EXCLUDED.extra,
          updated_at = now()
        """
    )


def downgrade() -> None:
    op.drop_index("idx_inv_latest_packages_count", table_name="agent_inventory_latest")
    op.drop_index("idx_inv_latest_collected", table_name="agent_inventory_latest")
    op.drop_table("agent_inventory_latest")

    op.drop_index("idx_net_events_ssh_user_col_ts", table_name="net_events")
    op.drop_index("idx_net_events_ssh_action_col_ts", table_name="net_events")
    op.drop_index("idx_net_events_ja4_ts", table_name="net_events")
    op.drop_index("idx_net_events_tls_sni_ts", table_name="net_events")
    op.drop_index("idx_net_events_http_host_ts", table_name="net_events")
    op.drop_index("idx_net_events_dns_qname_ts", table_name="net_events")
    op.drop_index("idx_net_events_app_proto_ts", table_name="net_events")
    op.drop_index("idx_net_events_recent_brin", table_name="net_events")

    op.drop_column("net_events", "ssh_username")
    op.drop_column("net_events", "ssh_action")
    op.drop_column("net_events", "ja4_ptype")
    op.drop_column("net_events", "ja4")
    op.drop_column("net_events", "ja3")
    op.drop_column("net_events", "tls_alpn_first")
    op.drop_column("net_events", "tls_sni")
    op.drop_column("net_events", "http_method")
    op.drop_column("net_events", "http_host")
    op.drop_column("net_events", "dns_qname")
    op.drop_column("net_events", "app_proto_conf_band")
    op.drop_column("net_events", "app_proto_reason")
    op.drop_column("net_events", "app_proto")
