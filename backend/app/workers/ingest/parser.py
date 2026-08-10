from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


def _event_hot_columns(event_type: str, extra: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(extra, dict):
        extra = {}

    def _s(k: str, *, lower: bool = False, upper: bool = False, default: Optional[str] = None) -> Optional[str]:
        raw = extra.get(k)
        if raw is None:
            return default
        v = str(raw).strip()
        if not v:
            return default
        if lower:
            return v.lower()
        if upper:
            return v.upper()
        return v

    def _i(k: str) -> Optional[int]:
        raw = extra.get(k)
        if raw is None or raw == "":
            return None
        try:
            return int(raw)
        except Exception:
            return None

    out: Dict[str, Any] = {
        "app_proto": _s("app_proto"),
        "app_proto_reason": _s("app_proto_reason"),
        "app_proto_conf_band": _s("app_proto_conf_band"),
        "dns_qname": _s("dns_qname", lower=True),
        "http_host": _s("http_host", lower=True),
        "http_method": _s("http_method", upper=True),
        "tls_sni": _s("tls_sni", lower=True),
        "tls_alpn_first": _s("tls_alpn_first", lower=True),
        "ja3": _s("ja3"),
        "ja4": _s("ja4"),
        "ja4_ptype": _s("ja4_ptype", default="t"),
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
    if event_type == "ssh_auth":
        out["ssh_action"] = _s("action")
        out["ssh_username"] = _s("username")
    else:
        out["ssh_action"] = None
        out["ssh_username"] = None

    if event_type == "proc_exec":
        out["proc_pid"] = _i("pid")
        out["proc_ppid"] = _i("ppid")
        out["proc_name"] = _s("exe_name") or _s("comm") or _s("binary")
        out["proc_exe"] = _s("exe_path")
        out["proc_parent_name"] = _s("parent_exe_name") or _s("parent_comm")

    if event_type in {"fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"}:
        out["fim_path"] = _s("path")
        out["fim_category"] = _s("path_category")

    if event_type in {"beacon_suspect", "c2_suspect", "exfil_suspect", "egress_anomaly"}:
        out["heuristic_name"] = _s("heuristic_name") or _s("heuristic_kind") or _s("reason_kind")
        out["heuristic_confidence"] = _i("confidence")
    return out


def event_from_wire(ev: List[Any]) -> Dict[str, Any] | None:
    agent_id = ev[0] if len(ev) > 0 else None
    event_type = ev[1] if len(ev) > 1 else None
    if not agent_id or not event_type:
        return None

    try:
        ts = datetime.fromisoformat(ev[3]) if (len(ev) > 3 and ev[3]) else datetime.utcnow()
    except Exception:
        ts = datetime.utcnow()

    try:
        schema_v = int(ev[2] or 1)
    except Exception:
        schema_v = 1

    src_ip = ev[4] if (len(ev) > 4 and ev[4]) else None
    dst_ip = ev[5] if (len(ev) > 5 and ev[5]) else None

    src_port = ev[6] if (len(ev) > 6) else None
    dst_port = ev[7] if (len(ev) > 7) else None
    try:
        src_port = int(src_port) if src_port is not None else None
    except Exception:
        src_port = None
    try:
        dst_port = int(dst_port) if dst_port is not None else None
    except Exception:
        dst_port = None

    proto = ev[8] if (len(ev) > 8 and ev[8]) else None

    bytes_v = ev[9] if (len(ev) > 9) else None
    try:
        bytes_v = int(bytes_v) if bytes_v is not None else 0
    except Exception:
        bytes_v = 0

    extra_v = ev[10] if (len(ev) > 10 and isinstance(ev[10], dict)) else {}
    return {
        "agent_id": agent_id,
        "event_type": event_type,
        "schema_version": schema_v,
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "bytes": bytes_v,
        "extra": extra_v,
    }


def hot_event_from_wire(ev: List[Any]) -> Dict[str, Any] | None:
    row = event_from_wire(ev)
    if row is None:
        return None
    row.update(_event_hot_columns(event_type=str(row["event_type"]), extra=row["extra"]))
    return row
