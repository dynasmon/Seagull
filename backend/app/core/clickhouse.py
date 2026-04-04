"""ClickHouse client helpers.

ClickHouse is used as an analytics store for high-volume event queries.
Postgres remains the transactional source of truth.
"""

from __future__ import annotations

import re
import time
from typing import Any, Optional

from app.core.config import settings


_ch_client: Optional[Any] = None
_last_ping_at: float = 0.0
_last_ping_ok: bool = False
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _safe_ident(v: str, *, fallback: str) -> str:
    s = (v or "").strip()
    if _IDENT_RE.match(s):
        return s
    return fallback


def _build_clickhouse_client() -> Any:
    import clickhouse_connect

    kwargs = {
        "host": (settings.NETWATCH_CLICKHOUSE_HOST or "clickhouse"),
        "port": int(settings.NETWATCH_CLICKHOUSE_PORT or 8123),
        "username": (settings.NETWATCH_CLICKHOUSE_USERNAME or "default"),
        "password": (settings.NETWATCH_CLICKHOUSE_PASSWORD or ""),
        "secure": bool(settings.NETWATCH_CLICKHOUSE_SECURE),
        "verify": bool(settings.NETWATCH_CLICKHOUSE_VERIFY),
        "connect_timeout": float(settings.NETWATCH_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS or 2.0),
        "send_receive_timeout": float(settings.NETWATCH_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS or 5.0),
    }

    preferred_db = (settings.NETWATCH_CLICKHOUSE_DATABASE or "default").strip() or "default"
    db_candidates = [preferred_db]
    if preferred_db != "default":
        db_candidates.append("default")

    last_error: Exception | None = None
    for db in db_candidates:
        try:
            client = clickhouse_connect.get_client(database=db, **kwargs)
            # Force a handshake so we can fallback to "default" when the DB is missing.
            client.query("SELECT 1")
            return client
        except Exception as exc:
            last_error = exc
            continue

    if last_error is not None:
        raise last_error
    raise RuntimeError("Unable to initialize ClickHouse client")


def get_clickhouse_client() -> Any:
    global _ch_client
    if _ch_client is None:
        _ch_client = _build_clickhouse_client()
    return _ch_client


def reset_clickhouse_client() -> None:
    global _ch_client, _last_ping_at, _last_ping_ok
    _ch_client = None
    _last_ping_at = 0.0
    _last_ping_ok = False


def clickhouse_is_enabled() -> bool:
    return bool(getattr(settings, "NETWATCH_CLICKHOUSE_ENABLED", False))


def clickhouse_is_available() -> bool:
    global _last_ping_at, _last_ping_ok

    if not clickhouse_is_enabled():
        return False
    ttl = int(getattr(settings, "NETWATCH_CLICKHOUSE_PING_TTL_SECONDS", 2) or 2)
    now = time.time()
    if (now - _last_ping_at) < max(1, ttl):
        return _last_ping_ok

    _last_ping_at = now
    try:
        row = get_clickhouse_client().query("SELECT 1").first_row
        _last_ping_ok = bool(row and int(row[0]) == 1)
    except Exception:
        _last_ping_ok = False
    return _last_ping_ok


def clickhouse_events_table_ref() -> str:
    db = _safe_ident(getattr(settings, "NETWATCH_CLICKHOUSE_DATABASE", "netwatch"), fallback="netwatch")
    table = _safe_ident(getattr(settings, "NETWATCH_CLICKHOUSE_EVENTS_TABLE", "net_events_raw"), fallback="net_events_raw")
    return f"{db}.{table}"


def clickhouse_events_1m_table_ref() -> str:
    db = _safe_ident(getattr(settings, "NETWATCH_CLICKHOUSE_DATABASE", "netwatch"), fallback="netwatch")
    return f"{db}.net_events_1m"


def ensure_clickhouse_events_schema() -> bool:
    """Idempotent schema bootstrap for analytics events table."""

    if not clickhouse_is_enabled():
        return False

    client = get_clickhouse_client()
    db = _safe_ident(getattr(settings, "NETWATCH_CLICKHOUSE_DATABASE", "netwatch"), fallback="netwatch")
    table = _safe_ident(getattr(settings, "NETWATCH_CLICKHOUSE_EVENTS_TABLE", "net_events_raw"), fallback="net_events_raw")
    agg_table = "net_events_1m"
    agg_mv = "mv_net_events_1m"
    retention_days = max(1, int(getattr(settings, "NETWATCH_CLICKHOUSE_EVENTS_RETENTION_DAYS", 30) or 30))

    client.command(f"CREATE DATABASE IF NOT EXISTS {db}")
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {db}.{table}
        (
            timestamp DateTime64(3, 'UTC'),
            pg_event_id UInt64,
            agent_id LowCardinality(String),
            event_type LowCardinality(String),
            schema_version UInt16,
            severity Nullable(String),
            src_ip Nullable(String),
            dst_ip Nullable(String),
            src_port Nullable(UInt16),
            dst_port Nullable(UInt16),
            proto Nullable(String),
            bytes Nullable(Int64),
            app_proto Nullable(String),
            app_proto_reason Nullable(String),
            app_proto_conf_band Nullable(String),
            dns_qname Nullable(String),
            http_host Nullable(String),
            http_method Nullable(String),
            tls_sni Nullable(String),
            tls_alpn_first Nullable(String),
            ja3 Nullable(String),
            ja4 Nullable(String),
            ja4_ptype Nullable(String),
            ssh_action Nullable(String),
            ssh_username Nullable(String),
            sudo_username Nullable(String),
            sudo_target_user Nullable(String),
            sudo_command Nullable(String),
            sudo_tty Nullable(String),
            proc_pid Nullable(Int32),
            proc_ppid Nullable(Int32),
            proc_name Nullable(String),
            proc_exe Nullable(String),
            proc_parent_name Nullable(String),
            fim_path Nullable(String),
            fim_category Nullable(String),
            heuristic_name Nullable(String),
            heuristic_confidence Nullable(Int16),
            extra_json String,
            ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
        )
        ENGINE = ReplacingMergeTree(ingested_at)
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (timestamp, agent_id, event_type, pg_event_id)
        TTL toDateTime(timestamp) + toIntervalDay({retention_days}) DELETE
        SETTINGS index_granularity = 8192
        """
    )
    client.command(
        f"ALTER TABLE {db}.{table} "
        f"MODIFY TTL toDateTime(timestamp) + toIntervalDay({retention_days}) DELETE"
    )
    client.command(
        f"ALTER TABLE {db}.{table} "
        "ADD COLUMN IF NOT EXISTS pg_event_id UInt64 DEFAULT 0 AFTER timestamp"
    )
    client.command(
        f"ALTER TABLE {db}.{table} "
        "ADD COLUMN IF NOT EXISTS ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)"
    )
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS app_proto Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS app_proto_reason Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS app_proto_conf_band Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS dns_qname Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS http_host Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS http_method Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS tls_sni Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS tls_alpn_first Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS ja3 Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS ja4 Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS ja4_ptype Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS ssh_action Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS ssh_username Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS sudo_username Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS sudo_target_user Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS sudo_command Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS sudo_tty Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS proc_pid Nullable(Int32)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS proc_ppid Nullable(Int32)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS proc_name Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS proc_exe Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS proc_parent_name Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS fim_path Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS fim_category Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS heuristic_name Nullable(String)")
    client.command(f"ALTER TABLE {db}.{table} ADD COLUMN IF NOT EXISTS heuristic_confidence Nullable(Int16)")
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {db}.{agg_table}
        (
            bucket_ts DateTime('UTC'),
            agent_id LowCardinality(String),
            event_type LowCardinality(String),
            dst_port Nullable(UInt16),
            proto Nullable(String),
            total_count UInt64,
            total_bytes Int64,
            ssh_failures UInt64,
            dos_events UInt64
        )
        ENGINE = SummingMergeTree
        PARTITION BY toYYYYMM(bucket_ts)
        ORDER BY (bucket_ts, agent_id, event_type, ifNull(dst_port, 0), ifNull(proto, ''))
        TTL bucket_ts + toIntervalDay({retention_days}) DELETE
        SETTINGS index_granularity = 8192
        """
    )
    client.command(
        f"""
        CREATE MATERIALIZED VIEW IF NOT EXISTS {db}.{agg_mv}
        TO {db}.{agg_table}
        AS
        SELECT
            toStartOfMinute(timestamp) AS bucket_ts,
            agent_id,
            event_type,
            dst_port,
            proto,
            count() AS total_count,
            sum(ifNull(bytes, 0)) AS total_bytes,
            countIf(event_type = 'ssh_auth' AND ifNull(ssh_action, '') != 'accepted') AS ssh_failures,
            countIf(event_type = 'dos_attack') AS dos_events
        FROM {db}.{table}
        GROUP BY bucket_ts, agent_id, event_type, dst_port, proto
        """
    )

    # Sanity check: table exists and is queryable.
    exists = client.query(f"EXISTS TABLE {db}.{table}").first_row
    if not (exists and int(exists[0]) == 1):
        return False
    client.query(f"SELECT pg_event_id FROM {db}.{table} LIMIT 0")
    client.query(f"SELECT app_proto FROM {db}.{table} LIMIT 0")
    client.query(f"SELECT total_count FROM {db}.{agg_table} LIMIT 0")
    return True
