from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from app.core.config import settings
from app.core.config.env_secrets import getenv_compat
from app.core.db import engine
from app.core.db.lifecycle import ensure_database_ready
from app.core.integrations.clickhouse import (
    clickhouse_events_table_ref,
    ensure_clickhouse_events_schema,
    get_clickhouse_client,
)
from app.core.observability import log_event, setup_logging
from app.features.events.worker_runtime import NetEventModel, write_clickhouse_events

setup_logging("worker-clickhouse-backfill")
logger = logging.getLogger("seagull.worker.clickhouse_backfill")


def _env_int(name: str, default: int) -> int:
    raw = getenv_compat(name)
    if raw is None:
        return default
    try:
        return int(raw.strip() or str(default), 10)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    raw = getenv_compat(name)
    if raw is None:
        return default
    try:
        return float(raw.strip() or str(default))
    except Exception:
        return default


def _env_str(name: str, default: str = "") -> str:
    raw = getenv_compat(name)
    if raw is None:
        return default
    return raw.strip() or default


def _parse_backfill_config() -> Dict[str, Any]:
    return {
        "from_id": max(0, _env_int("SEAGULL_CLICKHOUSE_BACKFILL_FROM_ID", 0)),
        "batch_size": max(100, _env_int("SEAGULL_CLICKHOUSE_BACKFILL_BATCH_SIZE", 2000)),
        "max_rows": max(0, _env_int("SEAGULL_CLICKHOUSE_BACKFILL_MAX_ROWS", 0)),
        "sleep_seconds": max(0.0, _env_float("SEAGULL_CLICKHOUSE_BACKFILL_SLEEP_SECONDS", 0.0)),
        "agent_id": _env_str("SEAGULL_CLICKHOUSE_BACKFILL_AGENT_ID", "") or None,
    }


def _ch_max_pg_event_id(*, ch_client: Any, agent_id: Optional[str]) -> int:
    table = clickhouse_events_table_ref()
    params: Dict[str, Any] = {}
    where_sql = "pg_event_id > 0"
    if agent_id:
        where_sql += " AND agent_id = {agent_id:String}"
        params["agent_id"] = agent_id
    row = ch_client.query(
        f"SELECT max(pg_event_id) AS max_id FROM {table} WHERE {where_sql}",
        parameters=params,
    ).first_row
    if not row or row[0] is None:
        return 0
    try:
        return max(0, int(row[0]))
    except Exception:
        return 0


def _fetch_pg_batch(*, after_id: int, batch_size: int, agent_id: Optional[str]) -> List[Dict[str, Any]]:
    stmt = (
        select(
            NetEventModel.id,
            NetEventModel.agent_id,
            NetEventModel.event_type,
            NetEventModel.schema_version,
            NetEventModel.timestamp,
            NetEventModel.src_ip,
            NetEventModel.dst_ip,
            NetEventModel.src_port,
            NetEventModel.dst_port,
            NetEventModel.proto,
            NetEventModel.bytes,
            NetEventModel.app_proto,
            NetEventModel.app_proto_reason,
            NetEventModel.app_proto_conf_band,
            NetEventModel.dns_qname,
            NetEventModel.http_host,
            NetEventModel.http_method,
            NetEventModel.tls_sni,
            NetEventModel.tls_alpn_first,
            NetEventModel.ja3,
            NetEventModel.ja4,
            NetEventModel.ja4_ptype,
            NetEventModel.ssh_action,
            NetEventModel.ssh_username,
            NetEventModel.extra,
        )
        .where(NetEventModel.id > int(after_id))
        .order_by(NetEventModel.id.asc())
        .limit(int(batch_size))
    )
    if agent_id:
        stmt = stmt.where(NetEventModel.agent_id == agent_id)

    with engine.connect() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [dict(r) for r in rows]


def _pg_rows_to_hot_rows(pg_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in pg_rows:
        extra = row.get("extra") if isinstance(row.get("extra"), dict) else {}
        out.append(
            {
                "pg_event_id": int(row.get("id") or 0),
                "agent_id": row.get("agent_id"),
                "event_type": row.get("event_type"),
                "schema_version": int(row.get("schema_version") or 1),
                "timestamp": row.get("timestamp"),
                "src_ip": row.get("src_ip"),
                "dst_ip": row.get("dst_ip"),
                "src_port": row.get("src_port"),
                "dst_port": row.get("dst_port"),
                "proto": row.get("proto"),
                "bytes": row.get("bytes"),
                "app_proto": row.get("app_proto"),
                "app_proto_reason": row.get("app_proto_reason"),
                "app_proto_conf_band": row.get("app_proto_conf_band"),
                "dns_qname": row.get("dns_qname"),
                "http_host": row.get("http_host"),
                "http_method": row.get("http_method"),
                "tls_sni": row.get("tls_sni"),
                "tls_alpn_first": row.get("tls_alpn_first"),
                "ja3": row.get("ja3"),
                "ja4": row.get("ja4"),
                "ja4_ptype": row.get("ja4_ptype"),
                "ssh_action": row.get("ssh_action"),
                "ssh_username": row.get("ssh_username"),
                "extra": extra,
            }
        )
    return out


def run_backfill(
    *,
    ch_client: Any,
    from_id: int,
    batch_size: int,
    max_rows: int,
    sleep_seconds: float,
    agent_id: Optional[str],
) -> Dict[str, int]:
    cursor = int(from_id)
    if cursor <= 0:
        cursor = _ch_max_pg_event_id(ch_client=ch_client, agent_id=agent_id)

    processed = 0
    batches = 0
    last_id = cursor

    while True:
        if max_rows > 0 and processed >= max_rows:
            break

        remaining = max_rows - processed if max_rows > 0 else batch_size
        current_batch = min(batch_size, remaining) if max_rows > 0 else batch_size
        pg_rows = _fetch_pg_batch(after_id=last_id, batch_size=current_batch, agent_id=agent_id)
        if not pg_rows:
            break

        hot_rows = _pg_rows_to_hot_rows(pg_rows)
        write_clickhouse_events(ch_client=ch_client, hot_rows=hot_rows)

        last_id = int(pg_rows[-1]["id"])
        processed += len(pg_rows)
        batches += 1

        log_event(
            logger,
            "info",
            "clickhouse_backfill_batch_ok",
            batch=batches,
            rows=len(pg_rows),
            last_id=last_id,
            total_processed=processed,
        )
        if sleep_seconds > 0:
            time.sleep(float(sleep_seconds))

    return {
        "processed": int(processed),
        "batches": int(batches),
        "last_id": int(last_id),
    }


def main() -> None:
    ensure_database_ready()

    if not bool(getattr(settings, "SEAGULL_CLICKHOUSE_ENABLED", False)):
        log_event(logger, "error", "clickhouse_backfill_disabled")
        return

    cfg = _parse_backfill_config()

    ch_client = get_clickhouse_client()
    if not ensure_clickhouse_events_schema():
        log_event(logger, "error", "clickhouse_backfill_schema_unavailable")
        return

    result = run_backfill(
        ch_client=ch_client,
        from_id=int(cfg["from_id"]),
        batch_size=int(cfg["batch_size"]),
        max_rows=int(cfg["max_rows"]),
        sleep_seconds=float(cfg["sleep_seconds"]),
        agent_id=cfg["agent_id"],
    )
    log_event(
        logger,
        "info",
        "clickhouse_backfill_done",
        processed=result["processed"],
        batches=result["batches"],
        last_id=result["last_id"],
        agent_id=cfg["agent_id"] or "",
    )


if __name__ == "__main__":
    main()
