from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.core.integrations.clickhouse import clickhouse_events_table_ref


def _to_ch_ts(ts: Any) -> datetime:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def _norm_port(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        port = int(value)
    except Exception:
        return None
    if port < 0 or port > 65535:
        return None
    return port


def _severity_from_extra(extra: Dict[str, Any]) -> Optional[str]:
    if not isinstance(extra, dict):
        return None
    raw = extra.get("severity")
    if raw is None:
        return None
    value = str(raw).strip().lower()
    if value in {"low", "medium", "high", "critical"}:
        return value
    return None


def write_clickhouse_events(*, ch_client: Any, hot_rows: List[Dict[str, Any]]) -> int:
    if not hot_rows:
        return 0

    rows: List[Tuple[Any, ...]] = []
    for row in hot_rows:
        extra = row.get("extra") or {}
        if not isinstance(extra, dict):
            extra = {}
        is_sudo = str(row.get("event_type") or "") == "sudo_cmd"

        ts = _to_ch_ts(row.get("timestamp"))
        pg_event_id = row.get("pg_event_id")
        try:
            pg_event_id_i = int(pg_event_id) if pg_event_id is not None else 0
        except Exception:
            pg_event_id_i = 0

        rows.append(
            (
                ts,
                pg_event_id_i,
                str(row.get("agent_id") or ""),
                str(row.get("event_type") or ""),
                int(row.get("schema_version") or 1),
                _severity_from_extra(extra),
                (str(row.get("src_ip")) if row.get("src_ip") else None),
                (str(row.get("dst_ip")) if row.get("dst_ip") else None),
                _norm_port(row.get("src_port")),
                _norm_port(row.get("dst_port")),
                (str(row.get("proto")) if row.get("proto") else None),
                (int(row.get("bytes")) if row.get("bytes") is not None else None),
                (str(row.get("app_proto")) if row.get("app_proto") else None),
                (str(row.get("app_proto_reason")) if row.get("app_proto_reason") else None),
                (str(row.get("app_proto_conf_band")) if row.get("app_proto_conf_band") else None),
                (str(row.get("dns_qname")) if row.get("dns_qname") else None),
                (str(row.get("http_host")) if row.get("http_host") else None),
                (str(row.get("http_method")) if row.get("http_method") else None),
                (str(row.get("tls_sni")) if row.get("tls_sni") else None),
                (str(row.get("tls_alpn_first")) if row.get("tls_alpn_first") else None),
                (str(row.get("ja3")) if row.get("ja3") else None),
                (str(row.get("ja4")) if row.get("ja4") else None),
                (str(row.get("ja4_ptype")) if row.get("ja4_ptype") else None),
                (str(row.get("ssh_action")) if row.get("ssh_action") else None),
                (str(row.get("ssh_username")) if row.get("ssh_username") else None),
                (str(extra.get("username")) if is_sudo and extra.get("username") else None),
                (str(extra.get("target_user")) if is_sudo and extra.get("target_user") else None),
                (str(extra.get("command")) if is_sudo and extra.get("command") else None),
                (str(extra.get("tty")) if is_sudo and extra.get("tty") else None),
                (int(row.get("proc_pid")) if row.get("proc_pid") is not None else None),
                (int(row.get("proc_ppid")) if row.get("proc_ppid") is not None else None),
                (str(row.get("proc_name")) if row.get("proc_name") else None),
                (str(row.get("proc_exe")) if row.get("proc_exe") else None),
                (str(row.get("proc_parent_name")) if row.get("proc_parent_name") else None),
                (str(row.get("fim_path")) if row.get("fim_path") else None),
                (str(row.get("fim_category")) if row.get("fim_category") else None),
                (str(row.get("heuristic_name")) if row.get("heuristic_name") else None),
                (int(row.get("heuristic_confidence")) if row.get("heuristic_confidence") is not None else None),
                json.dumps(extra, ensure_ascii=False, separators=(",", ":"), default=str),
            )
        )

    ch_client.insert(
        clickhouse_events_table_ref(),
        rows,
        column_names=[
            "timestamp",
            "pg_event_id",
            "agent_id",
            "event_type",
            "schema_version",
            "severity",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "proto",
            "bytes",
            "app_proto",
            "app_proto_reason",
            "app_proto_conf_band",
            "dns_qname",
            "http_host",
            "http_method",
            "tls_sni",
            "tls_alpn_first",
            "ja3",
            "ja4",
            "ja4_ptype",
            "ssh_action",
            "ssh_username",
            "sudo_username",
            "sudo_target_user",
            "sudo_command",
            "sudo_tty",
            "proc_pid",
            "proc_ppid",
            "proc_name",
            "proc_exe",
            "proc_parent_name",
            "fim_path",
            "fim_category",
            "heuristic_name",
            "heuristic_confidence",
            "extra_json",
        ],
    )
    return len(rows)
