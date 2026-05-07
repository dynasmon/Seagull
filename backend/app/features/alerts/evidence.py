"""Evidence spec extraction for alert evidence items.

Reads structured data already present in AlertModel.details and produces
the kwargs dicts used to construct AlertEvidenceModel rows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from app.features.alerts.models import AlertModel


def _safe_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s[:255] if s else None


def build_aggregate_evidence(
    *,
    group_fields: list[str],
    group_key: dict,
    count: int,
    window_seconds: int,
) -> list[dict]:
    primary_field = group_fields[0] if group_fields else None
    primary_val = _safe_str(group_key.get(primary_field)) if primary_field else None
    summary_parts = []
    if primary_field and primary_val:
        summary_parts.append(f"{primary_field}={primary_val}")
    summary_parts.append(f"{count} events in {window_seconds}s")
    return [{
        "evidence_type": "aggregate",
        "evidence_role": "trigger",
        "entity_type": primary_field,
        "entity_value": primary_val,
        "matched_field": "event_count",
        "matched_value": str(count),
        "summary": ": ".join(summary_parts),
        "raw_context": {
            "group_by": group_fields,
            "group_key": {k: str(v) for k, v in group_key.items() if v is not None},
            "window_seconds": window_seconds,
        },
    }]


def build_distinct_evidence(
    *,
    group_fields: list[str],
    group_key: dict,
    distinct_field: str,
    distinct_count: int,
    window_seconds: int,
) -> list[dict]:
    primary_field = group_fields[0] if group_fields else None
    primary_val = _safe_str(group_key.get(primary_field)) if primary_field else None
    if primary_field and primary_val and distinct_field:
        summary = f"{primary_field}={primary_val}: {distinct_count} distinct {distinct_field} in {window_seconds}s"
    else:
        summary = f"{distinct_count} distinct {distinct_field or 'values'} in {window_seconds}s"
    return [{
        "evidence_type": "distinct",
        "evidence_role": "trigger",
        "entity_type": primary_field,
        "entity_value": primary_val,
        "matched_field": distinct_field,
        "matched_value": str(distinct_count),
        "summary": summary,
        "raw_context": {
            "group_by": group_fields,
            "group_key": {k: str(v) for k, v in group_key.items() if v is not None},
            "distinct_field": distinct_field,
            "window_seconds": window_seconds,
        },
    }]


def build_multi_distinct_evidence(
    *,
    group_fields: list[str],
    group_key: dict,
    distinct_results: dict[str, int],
    window_seconds: int,
) -> list[dict]:
    primary_field = group_fields[0] if group_fields else None
    primary_val = _safe_str(group_key.get(primary_field)) if primary_field else None
    items = []
    for field, value in distinct_results.items():
        if primary_field and primary_val:
            summary = f"{primary_field}={primary_val}: {value} distinct {field} in {window_seconds}s"
        else:
            summary = f"{value} distinct {field} in {window_seconds}s"
        items.append({
            "evidence_type": "distinct",
            "evidence_role": "trigger",
            "entity_type": primary_field,
            "entity_value": primary_val,
            "matched_field": field,
            "matched_value": str(value),
            "summary": summary,
            "raw_context": {
                "group_by": group_fields,
                "group_key": {k: str(v) for k, v in group_key.items() if v is not None},
                "window_seconds": window_seconds,
            },
        })
    return items


def extract_evidence_specs(alert: AlertModel) -> list[dict]:
    """Derive evidence item specs from an AlertModel's existing fields."""
    details = alert.details or {}
    detector_type = str(alert.detector_type or "")
    rule_type = str(details.get("type") or "")
    window_seconds = int(details.get("window_seconds") or 300)
    group_fields = list(details.get("group_by") or [])
    group_key = dict(details.get("group_key") or {})

    if detector_type == "heuristic":
        heuristic_name = _safe_str(details.get("heuristic_name") or alert.rule_id or "")
        entity_type = "src_ip" if alert.src_ip else ("dst_ip" if alert.dst_ip else None)
        entity_val = alert.src_ip or alert.dst_ip
        return [{
            "evidence_type": "heuristic",
            "evidence_role": "trigger",
            "entity_type": entity_type,
            "entity_value": entity_val,
            "matched_field": "heuristic_name",
            "matched_value": heuristic_name,
            "summary": _safe_str(details.get("reason") or details.get("description") or heuristic_name),
            "raw_context": {},
        }]

    if detector_type == "correlation" or rule_type == "correlation":
        correlated = details.get("correlated_rules") or {}
        matched_val = ",".join(sorted(str(k) for k in correlated.keys())) if correlated else None
        return [{
            "evidence_type": "correlation",
            "evidence_role": "trigger",
            "entity_type": "dst_ip" if alert.dst_ip else None,
            "entity_value": alert.dst_ip,
            "matched_field": "correlated_rules",
            "matched_value": matched_val,
            "summary": _safe_str(alert.description) or "Correlated alert",
            "raw_context": {"correlated_rules": correlated},
        }]

    if detector_type == "inline":
        return _extract_inline_evidence(alert, details)

    if rule_type in ("aggregate_count", "threshold") and group_fields:
        count = int(details.get("count") or 0)
        return build_aggregate_evidence(
            group_fields=group_fields,
            group_key=group_key,
            count=count,
            window_seconds=window_seconds,
        )

    if rule_type in ("distinct_count", "cardinality") and group_fields:
        distinct_field = _safe_str(details.get("distinct_field")) or ""
        distinct_count = int(details.get("distinct_count") or 0)
        return build_distinct_evidence(
            group_fields=group_fields,
            group_key=group_key,
            distinct_field=distinct_field,
            distinct_count=distinct_count,
            window_seconds=window_seconds,
        )

    if rule_type in ("multi_distinct", "multi_cardinality") and group_fields:
        distinct_results = dict(details.get("distinct") or {})
        return build_multi_distinct_evidence(
            group_fields=group_fields,
            group_key=group_key,
            distinct_results={k: int(v) for k, v in distinct_results.items()},
            window_seconds=window_seconds,
        )

    return []


def _extract_inline_evidence(alert: AlertModel, details: dict) -> list[dict]:
    rule_id = str(alert.rule_id or "")

    if rule_id == "ssh_bruteforce_v1":
        count = int(details.get("event_count") or 0)
        minutes = int(details.get("time_window_minutes") or 0)
        return [{
            "evidence_type": "aggregate",
            "evidence_role": "trigger",
            "entity_type": "src_ip",
            "entity_value": alert.src_ip,
            "matched_field": "ssh_connection_count",
            "matched_value": str(count),
            "summary": f"{alert.src_ip}: {count} SSH connections in {minutes}m",
            "raw_context": {"time_window_minutes": minutes, "min_events": details.get("min_events")},
        }]

    if rule_id == "port_scan_v1":
        distinct_ports = int(details.get("distinct_ports") or 0)
        minutes = int(details.get("time_window_minutes") or 0)
        return [{
            "evidence_type": "distinct",
            "evidence_role": "trigger",
            "entity_type": "src_ip",
            "entity_value": alert.src_ip,
            "matched_field": "distinct_dst_ports",
            "matched_value": str(distinct_ports),
            "summary": f"{alert.src_ip}: {distinct_ports} distinct TCP ports in {minutes}m",
            "raw_context": {"time_window_minutes": minutes, "event_count": details.get("event_count")},
        }]

    if rule_id == "horizontal_scan_v1":
        distinct_targets = int(details.get("distinct_targets") or 0)
        dst_port = alert.dst_port
        minutes = int(details.get("time_window_minutes") or 0)
        return [{
            "evidence_type": "distinct",
            "evidence_role": "trigger",
            "entity_type": "src_ip",
            "entity_value": alert.src_ip,
            "matched_field": "distinct_dst_ips",
            "matched_value": str(distinct_targets),
            "summary": f"{alert.src_ip}: {distinct_targets} distinct hosts on port {dst_port} in {minutes}m",
            "raw_context": {"time_window_minutes": minutes, "dst_port": dst_port, "event_count": details.get("event_count")},
        }]

    if rule_id == "new_host_seen_v1":
        role = str(details.get("role") or "src")
        ip = alert.src_ip if role == "src" else alert.dst_ip
        first_seen = _safe_str(details.get("first_seen"))
        return [{
            "evidence_type": "entity",
            "evidence_role": "trigger",
            "entity_type": f"{role}_ip",
            "entity_value": ip,
            "matched_field": "first_seen",
            "matched_value": first_seen,
            "summary": f"New {role} host {ip} first observed at {first_seen}",
            "raw_context": {"role": role, "event_count": details.get("event_count")},
        }]

    return []
