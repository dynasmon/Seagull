from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from app.core.observability import incr_counter
from app.features.events.storage_contract import (
    fit_agent_id,
    fit_byte_count,
    fit_event_type,
    fit_extra,
    fit_hot_text,
    fit_int32,
    fit_ip,
    fit_port,
    fit_proto,
    fit_schema_version,
    fit_smallint,
)

WIRE_AGENT_ID = 0
WIRE_EVENT_TYPE = 1
WIRE_SCHEMA_VERSION = 2
WIRE_TIMESTAMP = 3
WIRE_SRC_IP = 4
WIRE_DST_IP = 5
WIRE_SRC_PORT = 6
WIRE_DST_PORT = 7
WIRE_PROTO = 8
WIRE_BYTES = 9
WIRE_EXTRA = 10

_NORMALIZED_FIELD_POSITIONS: Dict[str, int] = {
    "agent_id": WIRE_AGENT_ID,
    "event_type": WIRE_EVENT_TYPE,
    "schema_version": WIRE_SCHEMA_VERSION,
    "src_ip": WIRE_SRC_IP,
    "dst_ip": WIRE_DST_IP,
    "src_port": WIRE_SRC_PORT,
    "dst_port": WIRE_DST_PORT,
    "proto": WIRE_PROTO,
    "bytes": WIRE_BYTES,
    "extra": WIRE_EXTRA,
}

_SSH_EVENT_TYPES = {"ssh_auth"}
_PROCESS_EVENT_TYPES = {"proc_exec"}
_FILE_EVENT_TYPES = {"fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"}
_HEURISTIC_EVENT_TYPES = {"beacon_suspect", "c2_suspect", "exfil_suspect", "egress_anomaly"}


def event_from_wire(ev: List[Any]) -> Dict[str, Any] | None:
    if not isinstance(ev, (list, tuple)):
        return None

    agent_id = fit_agent_id(_at(ev, WIRE_AGENT_ID))
    event_type = fit_event_type(_at(ev, WIRE_EVENT_TYPE))
    if not agent_id or not event_type:
        return None

    row: Dict[str, Any] = {
        "agent_id": agent_id,
        "event_type": event_type,
        "schema_version": fit_schema_version(_at(ev, WIRE_SCHEMA_VERSION)),
        "timestamp": _timestamp(_at(ev, WIRE_TIMESTAMP)),
        "src_ip": fit_ip(_at(ev, WIRE_SRC_IP)),
        "dst_ip": fit_ip(_at(ev, WIRE_DST_IP)),
        "src_port": fit_port(_at(ev, WIRE_SRC_PORT)),
        "dst_port": fit_port(_at(ev, WIRE_DST_PORT)),
        "proto": fit_proto(_at(ev, WIRE_PROTO)),
        "bytes": fit_byte_count(_at(ev, WIRE_BYTES)),
        "extra": fit_extra(_at(ev, WIRE_EXTRA)),
    }
    _report_normalization(ev, row)
    return row


def hot_event_from_wire(ev: List[Any]) -> Dict[str, Any] | None:
    row = event_from_wire(ev)
    if row is None:
        return None
    row.update(event_hot_columns(event_type=str(row["event_type"]), extra=row["extra"]))
    return row


def event_hot_columns(event_type: str, extra: Dict[str, Any]) -> Dict[str, Any]:
    values = extra if isinstance(extra, Mapping) else {}

    columns: Dict[str, Any] = {
        "app_proto": _text(values, "app_proto", column="app_proto"),
        "app_proto_reason": _text(values, "app_proto_reason", column="app_proto_reason"),
        "app_proto_conf_band": _text(values, "app_proto_conf_band", column="app_proto_conf_band"),
        "dns_qname": _text(values, "dns_qname", column="dns_qname", lower=True),
        "http_host": _text(values, "http_host", column="http_host", lower=True),
        "http_method": _text(values, "http_method", column="http_method", upper=True),
        "tls_sni": _text(values, "tls_sni", column="tls_sni", lower=True),
        "tls_alpn_first": _text(values, "tls_alpn_first", column="tls_alpn_first", lower=True),
        "ja3": _text(values, "ja3", column="ja3"),
        "ja4": _text(values, "ja4", column="ja4"),
        "ja4_ptype": _text(values, "ja4_ptype", column="ja4_ptype", default="t"),
        "ssh_action": None,
        "ssh_username": None,
        "proc_pid": None,
        "proc_ppid": None,
        "proc_name": None,
        "proc_exe": None,
        "proc_parent_name": None,
        "fim_path": None,
        "fim_category": None,
        "heuristic_name": None,
        "heuristic_confidence": None,
    }

    if event_type in _SSH_EVENT_TYPES:
        columns["ssh_action"] = _text(values, "action", column="ssh_action")
        columns["ssh_username"] = _text(values, "username", column="ssh_username")

    if event_type in _PROCESS_EVENT_TYPES:
        columns["proc_pid"] = fit_int32(values.get("pid"))
        columns["proc_ppid"] = fit_int32(values.get("ppid"))
        columns["proc_name"] = _text(values, "exe_name", "comm", "binary", column="proc_name")
        columns["proc_exe"] = _text(values, "exe_path", column="proc_exe")
        columns["proc_parent_name"] = _text(values, "parent_exe_name", "parent_comm", column="proc_parent_name")

    if event_type in _FILE_EVENT_TYPES:
        columns["fim_path"] = _text(values, "path", column="fim_path")
        columns["fim_category"] = _text(values, "path_category", column="fim_category")

    if event_type in _HEURISTIC_EVENT_TYPES:
        columns["heuristic_name"] = _text(
            values,
            "heuristic_name",
            "heuristic_kind",
            "reason_kind",
            column="heuristic_name",
        )
        columns["heuristic_confidence"] = fit_smallint(values.get("confidence"))

    return columns


def _at(ev: List[Any], position: int) -> Any:
    return ev[position] if len(ev) > position else None


def _text(
    values: Mapping[str, Any],
    *keys: str,
    column: str,
    lower: bool = False,
    upper: bool = False,
    default: Optional[str] = None,
) -> Optional[str]:
    for key in keys:
        text = fit_hot_text(column, values.get(key))
        if text is None:
            continue
        if lower:
            return text.lower()
        if upper:
            return text.upper()
        return text
    return default


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def _report_normalization(ev: List[Any], row: Dict[str, Any]) -> None:
    for field, position in _NORMALIZED_FIELD_POSITIONS.items():
        raw = _at(ev, position)
        if raw is None or raw == "":
            continue
        fitted = row[field]
        if fitted is not raw and fitted != raw:
            incr_counter("ingest_event_fields_normalized_total", field=field)
