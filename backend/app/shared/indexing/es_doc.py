from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

EXTRA_SEARCH_KEYS = (
    "event_type",
    "app_proto",
    "dns_qname",
    "http_host",
    "tls_sni",
    "tls_alpn_first",
    "geo_country",
    "geo_org",
    "asn_org",
    "ssh_username",
    "sudo_username",
    "sudo_command",
    "proc_name",
    "proc_exe",
    "fim_path",
)

FIM_EVENT_TYPES = frozenset({"fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"})
HEURISTIC_EVENT_TYPES = frozenset({"beacon_suspect", "c2_suspect", "exfil_suspect", "egress_anomaly"})


def _as_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        vv = v.strip()
        return vv if vv else None
    return str(v)


def _as_int(v: Any) -> Optional[int]:
    try:
        if v is None:
            return None
        if isinstance(v, bool):
            return None
        return int(v)
    except Exception:
        return None


def build_event_doc(row: Dict[str, Any]) -> Dict[str, Any]:
    ts = row.get("timestamp")
    if isinstance(ts, datetime):
        ts_iso = ts.isoformat()
    else:
        ts_iso = str(ts) if ts is not None else None

    extra = row.get("extra") or {}
    if not isinstance(extra, dict):
        extra = {}

    event_type = _as_str(row.get("event_type"))

    doc: Dict[str, Any] = {
        "id": row.get("id"),
        "agent_id": row.get("agent_id"),
        "event_type": event_type,
        "schema_version": row.get("schema_version"),
        "@timestamp": ts_iso,
        "timestamp": ts_iso,
        "src_ip": row.get("src_ip"),
        "dst_ip": row.get("dst_ip"),
        "src_port": row.get("src_port"),
        "dst_port": row.get("dst_port"),
        "proto": row.get("proto"),
        "bytes": row.get("bytes"),
        "extra": extra,
    }

    app_proto = _as_str(extra.get("app_proto"))
    if app_proto:
        doc["app_proto"] = app_proto
    app_proto_reason = _as_str(extra.get("app_proto_reason"))
    if app_proto_reason:
        doc["app_proto_reason"] = app_proto_reason
    app_proto_conf_band = _as_str(extra.get("app_proto_conf_band"))
    if app_proto_conf_band:
        doc["app_proto_conf_band"] = app_proto_conf_band

    dns_qname = _as_str(extra.get("dns_qname"))
    if dns_qname:
        doc["dns_qname"] = dns_qname.lower()

    dns_risk = _as_int(extra.get("dns_risk"))
    if dns_risk is not None:
        doc["dns_risk"] = dns_risk

    http_host = _as_str(extra.get("http_host"))
    if http_host:
        doc["http_host"] = http_host.lower()

    http_method = _as_str(extra.get("http_method"))
    if http_method:
        doc["http_method"] = http_method.upper()

    tls_sni = _as_str(extra.get("tls_sni"))
    if tls_sni:
        doc["tls_sni"] = tls_sni.lower()

    tls_alpn = _as_str(extra.get("tls_alpn_first"))
    if tls_alpn:
        doc["tls_alpn_first"] = tls_alpn.lower()

    ja4 = _as_str(extra.get("ja4"))
    if ja4:
        doc["ja4"] = ja4

    ja4_ptype = _as_str(extra.get("ja4_ptype")) or "t"
    doc["ja4_ptype"] = ja4_ptype

    ja3 = _as_str(extra.get("ja3"))
    if ja3:
        doc["ja3"] = ja3

    for k in ["geo_country", "geo_org", "asn", "asn_org"]:
        vv = _as_str(extra.get(k))
        if vv:
            doc[k] = vv

    if event_type == "ssh_auth":
        ssh_action = _as_str(extra.get("action"))
        if ssh_action:
            doc["ssh_action"] = ssh_action
        ssh_username = _as_str(extra.get("username"))
        if ssh_username:
            doc["ssh_username"] = ssh_username

    if event_type == "sudo_cmd":
        for k_src, k_dst in [
            ("username", "sudo_username"),
            ("target_user", "sudo_target_user"),
            ("command", "sudo_command"),
            ("tty", "sudo_tty"),
            ("pwd", "sudo_pwd"),
        ]:
            vv = _as_str(extra.get(k_src))
            if vv:
                doc[k_dst] = vv

    if event_type == "proc_exec":
        doc["proc_pid"] = _as_int(extra.get("pid"))
        doc["proc_ppid"] = _as_int(extra.get("ppid"))
        doc["proc_name"] = _as_str(extra.get("exe_name") or extra.get("comm") or extra.get("binary"))
        doc["proc_exe"] = _as_str(extra.get("exe_path"))
        doc["proc_parent_name"] = _as_str(extra.get("parent_exe_name") or extra.get("parent_comm"))

    if event_type in FIM_EVENT_TYPES:
        doc["fim_path"] = _as_str(extra.get("path"))
        doc["fim_category"] = _as_str(extra.get("path_category"))

    if event_type in HEURISTIC_EVENT_TYPES:
        doc["heuristic_name"] = _as_str(
            extra.get("heuristic_name") or extra.get("heuristic_kind") or extra.get("reason_kind")
        )
        doc["heuristic_confidence"] = _as_int(extra.get("confidence"))

    tokens = [str(doc[k]) for k in EXTRA_SEARCH_KEYS if doc.get(k)]
    if tokens:
        doc["extra_search"] = " ".join(tokens)

    return {k: v for k, v in doc.items() if v is not None}
