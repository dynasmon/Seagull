
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

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
        "host": (settings.SEAGULL_CLICKHOUSE_HOST or "clickhouse"),
        "port": int(settings.SEAGULL_CLICKHOUSE_PORT or 8123),
        "username": (settings.SEAGULL_CLICKHOUSE_USERNAME or "default"),
        "password": (settings.SEAGULL_CLICKHOUSE_PASSWORD or ""),
        "secure": bool(settings.SEAGULL_CLICKHOUSE_SECURE),
        "verify": bool(settings.SEAGULL_CLICKHOUSE_VERIFY),
        "connect_timeout": float(settings.SEAGULL_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS or 2.0),
        "send_receive_timeout": float(settings.SEAGULL_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS or 5.0),
    }

    preferred_db = (settings.SEAGULL_CLICKHOUSE_DATABASE or "default").strip() or "default"
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


def get_clickhouse_client_new() -> Any:
    # Dedicated client for concurrent workers: the shared client is not thread-safe.
    return _build_clickhouse_client()


def reset_clickhouse_client() -> None:
    global _ch_client, _last_ping_at, _last_ping_ok
    _ch_client = None
    _last_ping_at = 0.0
    _last_ping_ok = False


def clickhouse_is_enabled() -> bool:
    return bool(getattr(settings, "SEAGULL_CLICKHOUSE_ENABLED", False))


def clickhouse_is_available() -> bool:
    global _last_ping_at, _last_ping_ok

    if not clickhouse_is_enabled():
        return False
    ttl = int(getattr(settings, "SEAGULL_CLICKHOUSE_PING_TTL_SECONDS", 2) or 2)
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
    db = _safe_ident(getattr(settings, "SEAGULL_CLICKHOUSE_DATABASE", "seagull"), fallback="seagull")
    table = _safe_ident(getattr(settings, "SEAGULL_CLICKHOUSE_EVENTS_TABLE", "net_events_raw"), fallback="net_events_raw")
    return f"{db}.{table}"


def clickhouse_events_1m_table_ref() -> str:
    db = _safe_ident(getattr(settings, "SEAGULL_CLICKHOUSE_DATABASE", "seagull"), fallback="seagull")
    return f"{db}.net_events_1m"


def clickhouse_proto_intel_table_ref() -> str:
    db = _safe_ident(getattr(settings, "SEAGULL_CLICKHOUSE_DATABASE", "seagull"), fallback="seagull")
    return f"{db}.net_events_proto_intel_1m"


def clickhouse_proto_intel_overview_table_ref() -> str:
    db = _safe_ident(getattr(settings, "SEAGULL_CLICKHOUSE_DATABASE", "seagull"), fallback="seagull")
    return f"{db}.net_events_proto_intel_overview_1m"


def _mv_table_ref(table: str) -> str:
    db = _safe_ident(getattr(settings, "SEAGULL_CLICKHOUSE_DATABASE", "seagull"), fallback="seagull")
    return f"{db}.{table}"


def clickhouse_ddos_volume_1m_table_ref() -> str:
    return _mv_table_ref("net_events_ddos_volume_1m")


def clickhouse_src_ips_1m_table_ref() -> str:
    return _mv_table_ref("net_events_src_ips_1m")


def clickhouse_ssh_ip_1h_table_ref() -> str:
    return _mv_table_ref("net_events_ssh_ip_1h")


def clickhouse_ssh_user_1h_table_ref() -> str:
    return _mv_table_ref("net_events_ssh_user_1h")


_EXPECTED_MV_NAMES: tuple[str, ...] = (
    "mv_net_events_1m",
    "mv_net_events_proto_intel_1m",
    "mv_net_events_proto_intel_overview_1m",
    "mv_net_events_ddos_volume_1m",
    "mv_net_events_src_ips_1m",
    "mv_net_events_ssh_ip_1h",
    "mv_net_events_ssh_user_1h",
)


def expected_clickhouse_mv_names() -> tuple[str, ...]:
    return _EXPECTED_MV_NAMES


def clickhouse_missing_mvs(client: Any) -> list[str]:
    db = _safe_ident(getattr(settings, "SEAGULL_CLICKHOUSE_DATABASE", "seagull"), fallback="seagull")
    res = client.query(
        "SELECT name FROM system.tables WHERE database = {db:String} AND engine = 'MaterializedView'",
        parameters={"db": db},
    )
    present = {str(row[0]) for row in (getattr(res, "result_rows", []) or [])}
    return [name for name in _EXPECTED_MV_NAMES if name not in present]


def clickhouse_mvs_read_enabled() -> bool:
    return bool(getattr(settings, "SEAGULL_USE_CLICKHOUSE_MVS", False)) and clickhouse_is_enabled()


def mv_min_bucket_sql(table_ref: str) -> str:
    return f"SELECT minOrNull(bucket_ts) AS min_bucket FROM {table_ref}"


def clickhouse_mv_covers_window(client: Any, *, table_ref: str, start_ts: datetime) -> bool:
    try:
        row = client.query(mv_min_bucket_sql(table_ref)).first_row
    except Exception:
        return False
    if not row or row[0] is None:
        return False
    min_bucket = row[0]
    if not isinstance(min_bucket, datetime):
        return False
    if min_bucket.tzinfo is None:
        min_bucket = min_bucket.replace(tzinfo=timezone.utc)
    ref = start_ts if start_ts.tzinfo else start_ts.replace(tzinfo=timezone.utc)
    return min_bucket <= ref


def _mv_bucket_where(*, with_agent: bool, with_end: bool = True) -> str:
    where = "bucket_ts >= {start_ts:DateTime('UTC')}"
    if with_end:
        where += " AND bucket_ts <= {end_ts:DateTime('UTC')}"
    if with_agent:
        where += " AND agent_id = {agent_id:String}"
    return where


_SSH_ACTION_RE = re.compile(r"^[a-z_]+$")


def _ssh_actions_clause(actions: Sequence[str]) -> str:
    literals: list[str] = []
    for action in actions:
        value = str(action).strip()
        if not _SSH_ACTION_RE.match(value):
            raise ValueError(f"invalid ssh action literal: {action!r}")
        literals.append(f"'{value}'")
    return f"action IN ({', '.join(literals)})"


def ddos_volume_1m_read_sql(*, with_agent: bool) -> str:
    return (
        "SELECT bucket_ts, sum(packets) AS packets, max(peak_pps) AS peak_pps, max(peak_bps) AS peak_bps "
        f"FROM {clickhouse_ddos_volume_1m_table_ref()} "
        f"WHERE {_mv_bucket_where(with_agent=with_agent)} "
        "GROUP BY bucket_ts"
    )


def top_ports_1m_read_sql(*, with_agent: bool, limit: int) -> str:
    return (
        "SELECT dst_port AS port, sum(total_count) AS count "
        f"FROM {clickhouse_events_1m_table_ref()} "
        f"WHERE {_mv_bucket_where(with_agent=with_agent)} AND dst_port IS NOT NULL "
        "GROUP BY dst_port ORDER BY count DESC "
        f"LIMIT {int(limit)}"
    )


def top_src_ips_1m_read_sql(*, with_agent: bool, limit: int) -> str:
    return (
        "SELECT src_ip, sum(cnt) AS count "
        f"FROM {clickhouse_src_ips_1m_table_ref()} "
        f"WHERE {_mv_bucket_where(with_agent=with_agent)} AND src_ip != '' "
        "GROUP BY src_ip ORDER BY count DESC "
        f"LIMIT {int(limit)}"
    )


def ssh_action_totals_1h_read_sql(*, with_agent: bool, actions: Sequence[str]) -> str:
    return (
        "SELECT action, sum(cnt) AS count "
        f"FROM {clickhouse_ssh_ip_1h_table_ref()} "
        f"WHERE {_mv_bucket_where(with_agent=with_agent, with_end=False)} AND {_ssh_actions_clause(actions)} "
        "GROUP BY action"
    )


def ssh_unique_ips_1h_read_sql(*, with_agent: bool, actions: Sequence[str]) -> str:
    inner = (
        "SELECT src_ip, "
        "(max(geo_country) != '' OR max(geo_org) != '' OR max(asn) != '' OR max(asn_org) != '') AS has_geo "
        f"FROM {clickhouse_ssh_ip_1h_table_ref()} "
        f"WHERE {_mv_bucket_where(with_agent=with_agent, with_end=False)} "
        f"AND {_ssh_actions_clause(actions)} AND src_ip != '' "
        "GROUP BY src_ip"
    )
    return f"SELECT count() AS unique_source_ips, countIf(has_geo) AS enriched_source_ips FROM ({inner})"


def ssh_top_ips_1h_read_sql(*, with_agent: bool, actions: Sequence[str], limit: int) -> str:
    return (
        "SELECT src_ip, sum(cnt) AS count, "
        "max(geo_country) AS geo_country, max(geo_org) AS geo_org, max(asn) AS asn, max(asn_org) AS asn_org "
        f"FROM {clickhouse_ssh_ip_1h_table_ref()} "
        f"WHERE {_mv_bucket_where(with_agent=with_agent, with_end=False)} "
        f"AND {_ssh_actions_clause(actions)} AND src_ip != '' "
        "GROUP BY src_ip ORDER BY count DESC "
        f"LIMIT {int(limit)}"
    )


def ssh_top_users_1h_read_sql(*, with_agent: bool, actions: Sequence[str], limit: int) -> str:
    return (
        "SELECT username, sum(cnt) AS count "
        f"FROM {clickhouse_ssh_user_1h_table_ref()} "
        f"WHERE {_mv_bucket_where(with_agent=with_agent, with_end=False)} "
        f"AND {_ssh_actions_clause(actions)} AND username != '' "
        "GROUP BY username ORDER BY count DESC "
        f"LIMIT {int(limit)}"
    )


def ssh_source_ips_1h_read_sql(*, with_agent: bool, actions: Sequence[str], limit: int = 10000) -> str:
    return (
        "SELECT src_ip "
        f"FROM {clickhouse_ssh_ip_1h_table_ref()} "
        f"WHERE {_mv_bucket_where(with_agent=with_agent, with_end=False)} "
        f"AND {_ssh_actions_clause(actions)} AND src_ip != '' "
        "GROUP BY src_ip "
        f"LIMIT {int(limit)}"
    )


_PROTO_INTEL_PTYPE_EXPR = "ifNull(if(ifNull(ja4_ptype, '') = '', 't', ja4_ptype), 't')"

_PROTO_INTEL_FACET_ARRAY = (
    "arrayFilter(x -> x.2 != '', ["
    "('app_proto', ifNull(app_proto, ''), toInt32(0), ''),"
    "('transport', lowerUTF8(ifNull(proto, '')), toInt32(0), ''),"
    "('dst_port', ifNull(toString(dst_port), ''), toInt32(0), ''),"
    "('src_port', ifNull(toString(src_port), ''), toInt32(0), ''),"
    "('app_proto_reason', ifNull(app_proto_reason, ''), toInt32(0), ''),"
    "('app_proto_conf_band', ifNull(app_proto_conf_band, ''), toInt32(0), ''),"
    f"('ja4_ptype', {_PROTO_INTEL_PTYPE_EXPR}, toInt32(0), ''),"
    "('http_method', upperUTF8(ifNull(http_method, '')), toInt32(0), ''),"
    "('dns_qname', lowerUTF8(ifNull(dns_qname, '')), toInt32OrZero(JSONExtractString(extra_json, 'dns_risk')), ''),"
    "('http_host', lowerUTF8(ifNull(http_host, '')), toInt32(0), ''),"
    "('tls_sni', lowerUTF8(ifNull(tls_sni, '')), toInt32(0), ''),"
    "('tls_alpn_first', lowerUTF8(ifNull(tls_alpn_first, '')), toInt32(0), ''),"
    "('ja3', ifNull(ja3, ''), toInt32(0), ''),"
    f"('ja4', ifNull(ja4, ''), toInt32(0), {_PROTO_INTEL_PTYPE_EXPR})"
    "])"
)


_PROTO_INTEL_OVERVIEW_WITH_PROTO = (
    "ifNull(app_proto, '') != '' OR ifNull(dns_qname, '') != '' OR ifNull(http_host, '') != '' "
    "OR ifNull(http_method, '') != '' OR ifNull(ja4, '') != '' OR ifNull(ja3, '') != '' "
    "OR ifNull(tls_sni, '') != ''"
)


def proto_intel_facet_select_sql(*, db: str, table: str, where: str = "") -> str:
    where_clause = f" WHERE {where}" if where else ""
    return (
        "SELECT toStartOfMinute(timestamp) AS bucket_ts, agent_id, "
        "d.1 AS dimension, d.2 AS value, "
        "countState() AS cnt, maxState(d.3) AS risk_max, anyState(d.4) AS assoc "
        f"FROM {db}.{table} "
        f"ARRAY JOIN {_PROTO_INTEL_FACET_ARRAY} AS d"
        f"{where_clause} "
        "GROUP BY bucket_ts, agent_id, dimension, value"
    )


def proto_intel_overview_select_sql(*, db: str, table: str, where: str = "") -> str:
    where_clause = f" WHERE {where}" if where else ""
    return (
        "SELECT toStartOfMinute(timestamp) AS bucket_ts, agent_id, "
        "countState() AS total, "
        f"sumState(toUInt64({_PROTO_INTEL_OVERVIEW_WITH_PROTO})) AS with_proto, "
        "sumState(toUInt64(ifNull(dns_qname, '') != '')) AS dns, "
        "sumState(toUInt64(ifNull(http_host, '') != '' OR ifNull(http_method, '') != '')) AS http, "
        "sumState(toUInt64(ifNull(ja4, '') != '' OR ifNull(ja3, '') != '' OR ifNull(tls_sni, '') != '')) AS tls, "
        "maxState(timestamp) AS last_ts "
        f"FROM {db}.{table}"
        f"{where_clause} "
        "GROUP BY bucket_ts, agent_id"
    )


def _ensure_protocol_intel_schema(client: Any, *, db: str, table: str, retention_days: int) -> None:
    facet_table = "net_events_proto_intel_1m"
    facet_mv = "mv_net_events_proto_intel_1m"
    overview_table = "net_events_proto_intel_overview_1m"
    overview_mv = "mv_net_events_proto_intel_overview_1m"

    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {db}.{facet_table}
        (
            bucket_ts DateTime('UTC'),
            agent_id LowCardinality(String),
            dimension LowCardinality(String),
            value String,
            cnt AggregateFunction(count),
            risk_max AggregateFunction(max, Int32),
            assoc AggregateFunction(any, String)
        )
        ENGINE = AggregatingMergeTree
        PARTITION BY toYYYYMM(bucket_ts)
        ORDER BY (agent_id, dimension, value, bucket_ts)
        TTL bucket_ts + toIntervalDay({retention_days}) DELETE
        SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000
        """
    )
    client.command(
        f"ALTER TABLE {db}.{facet_table} "
        f"MODIFY TTL bucket_ts + toIntervalDay({retention_days}) DELETE"
    )
    client.command(
        f"ALTER TABLE {db}.{facet_table} MODIFY SETTING non_replicated_deduplication_window = 1000"
    )
    client.command(
        f"CREATE MATERIALIZED VIEW IF NOT EXISTS {db}.{facet_mv} TO {db}.{facet_table} AS "
        + proto_intel_facet_select_sql(db=db, table=table)
    )
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {db}.{overview_table}
        (
            bucket_ts DateTime('UTC'),
            agent_id LowCardinality(String),
            total AggregateFunction(count),
            with_proto AggregateFunction(sum, UInt64),
            dns AggregateFunction(sum, UInt64),
            http AggregateFunction(sum, UInt64),
            tls AggregateFunction(sum, UInt64),
            last_ts AggregateFunction(max, DateTime64(3, 'UTC'))
        )
        ENGINE = AggregatingMergeTree
        PARTITION BY toYYYYMM(bucket_ts)
        ORDER BY (agent_id, bucket_ts)
        TTL bucket_ts + toIntervalDay({retention_days}) DELETE
        SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000
        """
    )
    client.command(
        f"ALTER TABLE {db}.{overview_table} "
        f"MODIFY TTL bucket_ts + toIntervalDay({retention_days}) DELETE"
    )
    client.command(
        f"ALTER TABLE {db}.{overview_table} MODIFY SETTING non_replicated_deduplication_window = 1000"
    )
    client.command(
        f"CREATE MATERIALIZED VIEW IF NOT EXISTS {db}.{overview_mv} TO {db}.{overview_table} AS "
        + proto_intel_overview_select_sql(db=db, table=table)
    )


def ensure_clickhouse_events_schema() -> bool:

    if not clickhouse_is_enabled():
        return False

    client = get_clickhouse_client()
    db = _safe_ident(getattr(settings, "SEAGULL_CLICKHOUSE_DATABASE", "seagull"), fallback="seagull")
    table = _safe_ident(getattr(settings, "SEAGULL_CLICKHOUSE_EVENTS_TABLE", "net_events_raw"), fallback="net_events_raw")
    agg_table = "net_events_1m"
    agg_mv = "mv_net_events_1m"
    retention_days = max(1, int(getattr(settings, "SEAGULL_CLICKHOUSE_EVENTS_RETENTION_DAYS", 30) or 30))

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
        "MODIFY SETTING non_replicated_deduplication_window = 1000"
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

    _ensure_protocol_intel_schema(client, db=db, table=table, retention_days=retention_days)

    # Sanity check: table exists and is queryable.
    exists = client.query(f"EXISTS TABLE {db}.{table}").first_row
    if not (exists and int(exists[0]) == 1):
        return False
    client.query(f"SELECT pg_event_id FROM {db}.{table} LIMIT 0")
    client.query(f"SELECT app_proto FROM {db}.{table} LIMIT 0")
    client.query(f"SELECT total_count FROM {db}.{agg_table} LIMIT 0")
    client.query(f"SELECT dimension, value FROM {db}.net_events_proto_intel_1m LIMIT 0")
    client.query(f"SELECT countMerge(total) FROM {db}.net_events_proto_intel_overview_1m LIMIT 0")
    return True
