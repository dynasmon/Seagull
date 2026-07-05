from __future__ import annotations

from typing import Any, Dict

# Single source of truth for the seagull-events* index mappings.
#
# The hot (es_indexer) and warm (ingest) templates previously kept separate
# copies of this dict and drifted apart: `app_proto_reason` and
# `app_proto_conf_band` were emitted in documents but missing from the
# templates, so Elasticsearch dynamic-mapped them as `text` and every terms
# aggregation on them failed with HTTP 400 ("Fielddata is disabled ...").
# Any field a `_to_doc` builder can emit at the top level must be listed here.
EVENT_INDEX_MAPPING_PROPERTIES: Dict[str, Dict[str, Any]] = {
    "@timestamp": {"type": "date"},
    "timestamp": {"type": "date"},
    "id": {"type": "long"},
    "schema_version": {"type": "short"},
    "agent_id": {"type": "keyword"},
    "event_type": {"type": "keyword"},
    "proto": {"type": "keyword"},
    "src_ip": {"type": "ip"},
    "dst_ip": {"type": "ip"},
    "src_port": {"type": "integer"},
    "dst_port": {"type": "integer"},
    "bytes": {"type": "long"},
    # Protocol intel
    "app_proto": {"type": "keyword"},
    "app_proto_reason": {"type": "keyword"},
    "app_proto_conf_band": {"type": "keyword"},
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
}


def event_index_mapping_properties() -> Dict[str, Dict[str, Any]]:
    return {name: dict(spec) for name, spec in EVENT_INDEX_MAPPING_PROPERTIES.items()}
