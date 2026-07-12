from __future__ import annotations

from typing import Dict, List, Tuple

from app.shared.indexing.es_mapping import event_index_mapping_properties

RUNTIME_FIELD_TYPES: Dict[str, str] = {
    "dst_port_class": "keyword",
    "proto_category": "keyword",
}

HUNT_FREE_TEXT_FIELDS: Tuple[str, ...] = (
    "agent_id^2",
    "event_type^2",
    "src_ip",
    "dst_ip",
    "proto",
    "ssh_username",
    "http_host",
    "dns_qname",
    "tls_sni",
    "ja3",
    "ja4",
    "extra_json",
    "extra.*",
)


def hunt_field_types() -> Dict[str, str]:
    fields = {
        name: str(spec.get("type") or "keyword")
        for name, spec in event_index_mapping_properties().items()
    }
    fields.update(RUNTIME_FIELD_TYPES)
    return fields


def hunt_field_listing() -> List[Tuple[str, str]]:
    fields = hunt_field_types()
    fields["extra.*"] = "flattened"
    return sorted(fields.items())
