from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from app.core.observability import log_event

from .config import WorkerConfig

logger = logging.getLogger("seagull.worker.ingest")


def _build_es_client(cfg: WorkerConfig):
    from elasticsearch import Elasticsearch

    kwargs: Dict[str, Any] = {
        "request_timeout": cfg.es_request_timeout_seconds,
        "verify_certs": bool(cfg.es_verify_certs),
    }
    if cfg.es_username and cfg.es_password:
        kwargs["basic_auth"] = (cfg.es_username, cfg.es_password)
    if cfg.es_ca_certs:
        kwargs["ca_certs"] = cfg.es_ca_certs
    return Elasticsearch(cfg.es_url, **kwargs)


def _index_for(prefix: str, ts: datetime) -> str:
    return f"{prefix}-{ts.strftime('%Y.%m.%d')}"


def _to_doc(row: Dict[str, Any]) -> Dict[str, Any]:

    ts = row.get("timestamp")
    ts_iso = ts.isoformat() if isinstance(ts, datetime) else (str(ts) if ts else None)

    extra = row.get("extra") or {}
    if not isinstance(extra, dict):
        extra = {}

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

    event_type = _as_str(row.get("event_type"))

    doc: Dict[str, Any] = {
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

    # Protocol intel and enrichments (optional)
    for k in ["app_proto", "app_proto_reason", "app_proto_conf_band", "dns_qname", "http_host", "tls_sni", "tls_alpn_first", "ja4", "ja4_ptype", "ja3"]:
        vv = _as_str(extra.get(k))
        if vv:
            doc[k] = vv.lower() if k in {"dns_qname", "http_host", "tls_sni", "tls_alpn_first"} else vv

    dns_risk = _as_int(extra.get("dns_risk"))
    if dns_risk is not None:
        doc["dns_risk"] = dns_risk

    http_method = _as_str(extra.get("http_method"))
    if http_method:
        doc["http_method"] = http_method.upper()

    # Geo/ASN
    for k in ["geo_country", "geo_org", "asn", "asn_org"]:
        vv = _as_str(extra.get(k))
        if vv:
            doc[k] = vv

    # SSH
    if event_type == "ssh_auth":
        vv = _as_str(extra.get("action"))
        if vv:
            doc["ssh_action"] = vv
        vv2 = _as_str(extra.get("username"))
        if vv2:
            doc["ssh_username"] = vv2

    # Sudo
    if event_type == "sudo_cmd":
        mapping = {
            "username": "sudo_username",
            "target_user": "sudo_target_user",
            "command": "sudo_command",
            "tty": "sudo_tty",
            "pwd": "sudo_pwd",
        }
        for src, dst in mapping.items():
            vv = _as_str(extra.get(src))
            if vv:
                doc[dst] = vv

    if event_type == "proc_exec":
        doc["proc_pid"] = _as_int(extra.get("pid"))
        doc["proc_ppid"] = _as_int(extra.get("ppid"))
        doc["proc_name"] = _as_str(extra.get("exe_name") or extra.get("comm") or extra.get("binary"))
        doc["proc_exe"] = _as_str(extra.get("exe_path"))
        doc["proc_parent_name"] = _as_str(extra.get("parent_exe_name") or extra.get("parent_comm"))

    if event_type in {"fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"}:
        doc["fim_path"] = _as_str(extra.get("path"))
        doc["fim_category"] = _as_str(extra.get("path_category"))

    if event_type in {"beacon_suspect", "c2_suspect", "exfil_suspect", "egress_anomaly"}:
        doc["heuristic_name"] = _as_str(extra.get("heuristic_name") or extra.get("heuristic_kind") or extra.get("reason_kind"))
        doc["heuristic_confidence"] = _as_int(extra.get("confidence"))

    return {k: v for k, v in doc.items() if v is not None}


def _ensure_warm_ilm_and_template(es, cfg: WorkerConfig) -> None:

    if not cfg.warm_ilm_enabled:
        return

    policy_name = cfg.warm_ilm_policy

    # Create/overwrite policy (idempotent).
    try:
        body = {
            "policy": {
                "phases": {
                    "hot": {"actions": {}},
                    "delete": {
                        "min_age": f"{int(cfg.warm_ilm_delete_after_days)}d",
                        "actions": {"delete": {}},
                    },
                }
            }
        }
        es.transport.perform_request("PUT", f"/_ilm/policy/{policy_name}", body=body)
    except Exception as e:
        log_event(logger, "warning", "ingest_ilm_policy_error", error_type=type(e).__name__)
        return

    try:
        name = f"{cfg.warm_index_prefix}-template"

        mappings = {
            "dynamic": True,
            "properties": {
                "@timestamp": {"type": "date"},
                "timestamp": {"type": "date"},
                "schema_version": {"type": "short"},
                "agent_id": {"type": "keyword"},
                "event_type": {"type": "keyword"},
                "proto": {"type": "keyword"},
                "src_ip": {"type": "ip"},
                "dst_ip": {"type": "ip"},
                "src_port": {"type": "integer"},
                "dst_port": {"type": "integer"},
                "bytes": {"type": "long"},

                # Protocol Intel
                "app_proto": {"type": "keyword"},
                "dns_qname": {"type": "keyword"},
                "dns_risk": {"type": "integer"},
                "http_host": {"type": "keyword"},
                "http_method": {"type": "keyword"},
                "tls_sni": {"type": "keyword"},
                "tls_alpn_first": {"type": "keyword"},
                "ja4": {"type": "keyword"},
                "ja4_ptype": {"type": "keyword"},
                "ja3": {"type": "keyword"},

                # Enrichment
                "geo_country": {"type": "keyword"},
                "geo_org": {"type": "keyword"},
                "asn": {"type": "keyword"},
                "asn_org": {"type": "keyword"},

                # SSH
                "ssh_action": {"type": "keyword"},
                "ssh_username": {"type": "keyword"},

                # Sudo
                "sudo_username": {"type": "keyword"},
                "sudo_target_user": {"type": "keyword"},
                "sudo_command": {"type": "keyword"},
                "sudo_tty": {"type": "keyword"},
                "sudo_pwd": {"type": "keyword"},

                # Process / FIM / heuristic signals
                "proc_pid": {"type": "integer"},
                "proc_ppid": {"type": "integer"},
                "proc_name": {"type": "keyword"},
                "proc_exe": {"type": "keyword"},
                "proc_parent_name": {"type": "keyword"},
                "fim_path": {"type": "keyword"},
                "fim_category": {"type": "keyword"},
                "heuristic_name": {"type": "keyword"},
                "heuristic_confidence": {"type": "integer"},

                "extra": {"type": "flattened"},
            },
        }

        body = {
            "index_patterns": [f"{cfg.warm_index_prefix}-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "30s",
                    "index.lifecycle.name": policy_name,
                },
                "mappings": mappings,
            },
            "priority": 190,
            "_meta": {
                "project": "dynasmon-seagull",
                "component": "ingest_worker",
                "tier": "warm",
            },
        }

        es.indices.put_index_template(name=name, body=body)
    except Exception as e:
        log_event(logger, "warning", "ingest_warm_template_error", error_type=type(e).__name__)
        return

    log_event(logger, "info", "ingest_warm_ilm_ready", warm_index_prefix=cfg.warm_index_prefix, policy=policy_name)
