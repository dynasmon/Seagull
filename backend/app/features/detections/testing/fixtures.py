from __future__ import annotations

from datetime import timezone
from typing import Any, Mapping

from app.features.detections.domain.canonical_fields import CANONICAL_FIELD_MAP
from app.features.detections.rules.registry import runtime_field_name
from app.features.events.schemas import NetEvent
from app.features.events.worker_runtime import NetEventModel

_JSONB_CANONICAL_FIELDS = tuple(
    (canonical_name, runtime_field_name(spec), spec.jsonb_path)
    for canonical_name, spec in CANONICAL_FIELD_MAP.items()
    if spec.storage_kind == "jsonb"
)

_HOT_EVENT_FIELDS = frozenset(
    {
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
        "proc_pid",
        "proc_ppid",
        "proc_name",
        "proc_exe",
        "proc_parent_name",
        "fim_path",
        "fim_category",
        "heuristic_name",
        "heuristic_confidence",
    }
)


def _hot_fields(event_type: str, extra: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "app_proto": extra.get("app_proto"),
        "app_proto_reason": extra.get("app_proto_reason"),
        "app_proto_conf_band": extra.get("app_proto_conf_band"),
        "dns_qname": str(extra.get("dns_qname") or "").lower() or None,
        "http_host": str(extra.get("http_host") or "").lower() or None,
        "http_method": str(extra.get("http_method") or "").upper() or None,
        "tls_sni": str(extra.get("tls_sni") or "").lower() or None,
        "tls_alpn_first": str(extra.get("tls_alpn_first") or "").lower() or None,
        "ja3": extra.get("ja3"),
        "ja4": extra.get("ja4"),
        "ja4_ptype": extra.get("ja4_ptype"),
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

    event_kind = str(event_type or "").strip().lower()
    if event_kind == "ssh_auth":
        out["ssh_action"] = extra.get("action")
        out["ssh_username"] = extra.get("username")
    if event_kind == "proc_exec":
        out["proc_name"] = extra.get("exe_name") or extra.get("comm") or extra.get("binary")
        out["proc_exe"] = extra.get("exe_path")
        try:
            out["proc_pid"] = int(extra.get("pid"))
        except Exception:
            out["proc_pid"] = None
        try:
            out["proc_ppid"] = int(extra.get("ppid"))
        except Exception:
            out["proc_ppid"] = None
        out["proc_parent_name"] = extra.get("parent_exe_name") or extra.get("parent_comm")
    if event_kind in {"fim_change", "persistence_systemd", "persistence_cron", "ssh_key_change"}:
        out["fim_path"] = extra.get("path")
        out["fim_category"] = extra.get("path_category")
    if event_kind in {"beacon_suspect", "c2_suspect", "exfil_suspect", "egress_anomaly"}:
        out["heuristic_name"] = extra.get("heuristic_name") or extra.get("heuristic_kind") or extra.get("reason_kind")
        try:
            out["heuristic_confidence"] = int(extra.get("confidence"))
        except Exception:
            out["heuristic_confidence"] = None
    return out


def _normalize_timestamp(value):
    ts = value
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _jsonb_field_value(extra: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = extra
    for segment in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(segment)
    return value


def _set_jsonb_field_value(extra: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    target = extra
    for segment in path[:-1]:
        nxt = target.get(segment)
        if not isinstance(nxt, dict):
            nxt = {}
            target[segment] = nxt
        target = nxt
    target[path[-1]] = value


def _fold_canonical_jsonb_fields(payload: dict[str, Any]) -> None:
    extra = dict(payload["extra"]) if isinstance(payload.get("extra"), dict) else {}
    for canonical_name, _runtime_field, path in _JSONB_CANONICAL_FIELDS:
        if canonical_name in payload:
            value = payload.pop(canonical_name)
            if _jsonb_field_value(extra, path) is None:
                _set_jsonb_field_value(extra, path, value)
    payload["extra"] = extra


def _promote_jsonb_fields(event: dict[str, Any], extra: Mapping[str, Any]) -> None:
    for _canonical_name, runtime_field, path in _JSONB_CANONICAL_FIELDS:
        value = _jsonb_field_value(extra, path)
        if value is not None:
            event[runtime_field] = value


def normalize_event_document(raw_event: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(raw_event or {})
    _fold_canonical_jsonb_fields(payload)
    passthrough = {field_name: payload.get(field_name) for field_name in _HOT_EVENT_FIELDS if field_name in payload}
    parsed = NetEvent(**payload)
    event = parsed.model_dump() if hasattr(parsed, "model_dump") else parsed.dict()
    extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}
    event.update(_hot_fields(str(event.get("event_type") or ""), extra))
    _promote_jsonb_fields(event, extra)
    for field_name, value in passthrough.items():
        if value is not None:
            event[field_name] = value
    event["timestamp"] = _normalize_timestamp(event["timestamp"])
    if payload.get("id") is not None:
        try:
            event["id"] = int(payload["id"])
        except Exception:
            event["id"] = payload["id"]
    return event


def netevent_row_to_document(row: NetEventModel) -> dict[str, Any]:
    extra = row.extra if isinstance(row.extra, dict) else {}
    event = {
        "id": row.id,
        "agent_id": row.agent_id,
        "event_type": row.event_type,
        "schema_version": int(row.schema_version or 1),
        "timestamp": _normalize_timestamp(row.timestamp),
        "src_ip": row.src_ip,
        "dst_ip": row.dst_ip,
        "src_port": row.src_port,
        "dst_port": row.dst_port,
        "proto": row.proto,
        "bytes": row.bytes,
        "extra": extra,
    }
    event.update(_hot_fields(str(row.event_type or ""), extra))
    _promote_jsonb_fields(event, extra)
    for field_name in _HOT_EVENT_FIELDS:
        value = getattr(row, field_name, None)
        if value is not None:
            event[field_name] = value
    return event


__all__ = [
    "netevent_row_to_document",
    "normalize_event_document",
]
