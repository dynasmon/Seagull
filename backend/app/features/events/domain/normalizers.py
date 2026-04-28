from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.features.events.schemas import (
    NetEventDB,
    ProtoCount,
    QueryProvenanceMeta,
    QuerySource,
)

_PROTO_EXTRA_NORMALIZERS: dict[str, tuple[bool, bool, str | None]] = {
    "app_proto": (False, False, None),
    "app_proto_reason": (False, False, None),
    "app_proto_conf_band": (False, False, None),
    "dns_qname": (True, False, None),
    "http_host": (True, False, None),
    "http_method": (False, True, None),
    "tls_sni": (True, False, None),
    "tls_alpn_first": (True, False, None),
    "ja3": (False, False, None),
    "ja4": (False, False, None),
    "ja4_ptype": (False, False, "t"),
}

_EVENT_ROW_FIELDS: tuple[str, ...] = (
    "id",
    "agent_id",
    "event_type",
    "schema_version",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "bytes",
    "extra",
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
)


def _coerce_utc_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid timestamp format; use ISO-8601")
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _freshness_seconds(now: datetime, ts: datetime | None) -> int | None:
    if ts is None:
        return None
    base = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return int(max(0.0, (now - base).total_seconds()))


def _parse_iso_dt(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    s = value.strip()
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s[:-1] + "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.now(timezone.utc)


def _parse_iso_dt_or_none(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str) and value.strip():
        s = value.strip()
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            parsed = datetime.fromisoformat(s)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None
    return None


def _meta(
    *,
    source: QuerySource,
    fallback_chain: list[str],
    degraded_reason: str | None,
    source_freshness_seconds: int | None,
    query_latency_ms: float | None,
    cache_hit: bool,
    approximate: bool,
    query_window_start: datetime | None,
    query_window_end: datetime | None,
) -> QueryProvenanceMeta:
    return QueryProvenanceMeta(
        source=source,
        fallback_chain=[str(x) for x in fallback_chain if str(x).strip()],
        degraded_reason=(str(degraded_reason) if degraded_reason else None),
        source_freshness_seconds=(int(source_freshness_seconds) if source_freshness_seconds is not None else None),
        query_latency_ms=(round(float(query_latency_ms), 2) if query_latency_ms is not None else None),
        cache_hit=bool(cache_hit),
        approximate=bool(approximate),
        query_window_start=query_window_start,
        query_window_end=query_window_end,
    )


def _strip_large_extra(extra: Any) -> Dict[str, Any]:
    if not isinstance(extra, dict):
        return {}
    max_keys = 128
    max_value_chars = 4096
    out: Dict[str, Any] = {}
    for i, (k, v) in enumerate(extra.items()):
        if i >= max_keys:
            break
        key = str(k)[:128]
        if isinstance(v, str):
            out[key] = v[:max_value_chars]
        else:
            out[key] = v
    return out


def _merge_protocol_fields_into_extra(extra: Dict[str, Any], row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(extra or {})
    for key, (lower, upper, default) in _PROTO_EXTRA_NORMALIZERS.items():
        if out.get(key) not in (None, ""):
            continue
        raw = row.get(key, default)
        if raw is None:
            continue
        value = str(raw).strip()
        if not value:
            continue
        if lower:
            value = value.lower()
        elif upper:
            value = value.upper()
        out[key] = value
    return out


def _row_to_event_safe(row: Dict[str, Any]) -> NetEventDB | None:
    if not isinstance(row, dict):
        return None

    ts = _parse_iso_dt_or_none(row.get("timestamp")) or datetime.now(timezone.utc)
    try:
        row_id = int(row.get("id") or 0)
    except Exception:
        row_id = 0
    try:
        schema_version = int(row.get("schema_version") or 1)
    except Exception:
        schema_version = 1
    if schema_version < 1 or schema_version > 16:
        schema_version = 1

    extra = _strip_large_extra(row.get("extra") or {})
    if not extra and isinstance(row.get("extra"), str):
        try:
            parsed = json.loads(row.get("extra") or "")
            extra = _strip_large_extra(parsed)
        except Exception:
            extra = {}
    extra = _merge_protocol_fields_into_extra(extra, row)

    try:
        return NetEventDB(
            id=row_id,
            agent_id=str(row.get("agent_id") or ""),
            event_type=str(row.get("event_type") or ""),
            schema_version=schema_version,
            timestamp=ts,
            src_ip=row.get("src_ip"),
            dst_ip=row.get("dst_ip"),
            src_port=row.get("src_port"),
            dst_port=row.get("dst_port"),
            proto=row.get("proto"),
            bytes=row.get("bytes"),
            extra=extra,
        )
    except Exception:
        return None


def _event_obj_to_event_safe(item: Any) -> NetEventDB | None:
    if item is None:
        return None
    if isinstance(item, NetEventDB):
        return item
    if isinstance(item, dict):
        return _row_to_event_safe(item)

    row: Dict[str, Any] = {}
    for field in _EVENT_ROW_FIELDS:
        try:
            row[field] = getattr(item, field)
        except Exception:
            continue
    if not row:
        return None
    return _row_to_event_safe(row)


def _hit_to_event(hit: Dict[str, Any]) -> NetEventDB:
    src = hit.get("_source") or {}

    # Prefer explicit 'id' stored in _source, fallback to _id.
    try:
        row_id = int(src.get("id") or hit.get("_id"))
    except Exception:
        row_id = 0

    ts_raw = src.get("timestamp") or src.get("@timestamp")
    ts = _parse_iso_dt(ts_raw if isinstance(ts_raw, str) else None)
    try:
        schema_version = int(src.get("schema_version") or 1)
    except Exception:
        schema_version = 1
    if schema_version < 1 or schema_version > 16:
        schema_version = 1
    extra = src.get("extra") or {}
    if not isinstance(extra, dict):
        extra = {}
    extra = _merge_protocol_fields_into_extra(extra, src)

    return NetEventDB(
        id=row_id,
        agent_id=str(src.get("agent_id") or ""),
        event_type=str(src.get("event_type") or ""),
        schema_version=schema_version,
        timestamp=ts,
        src_ip=src.get("src_ip"),
        dst_ip=src.get("dst_ip"),
        src_port=src.get("src_port"),
        dst_port=src.get("dst_port"),
        proto=src.get("proto"),
        bytes=src.get("bytes"),
        extra=extra,
    )


def _ch_row_to_event(row: Dict[str, Any]) -> NetEventDB | None:
    try:
        row_id = int(row.get("pg_event_id") or 0)
    except Exception:
        row_id = 0
    ts_raw = row.get("timestamp")
    ts = ts_raw if isinstance(ts_raw, datetime) else _parse_iso_dt(str(ts_raw) if ts_raw else None)
    try:
        schema_version = int(row.get("schema_version") or 1)
    except Exception:
        schema_version = 1
    if schema_version < 1 or schema_version > 16:
        schema_version = 1

    extra: Dict[str, Any] = {}
    extra_raw = row.get("extra_json")
    if isinstance(extra_raw, str) and extra_raw.strip():
        try:
            payload = json.loads(extra_raw)
            if isinstance(payload, dict):
                extra = payload
        except Exception:
            extra = {}
    extra = _merge_protocol_fields_into_extra(extra, row)

    try:
        return NetEventDB(
            id=row_id,
            agent_id=str(row.get("agent_id") or ""),
            event_type=str(row.get("event_type") or ""),
            schema_version=schema_version,
            timestamp=ts,
            src_ip=row.get("src_ip"),
            dst_ip=row.get("dst_ip"),
            src_port=row.get("src_port"),
            dst_port=row.get("dst_port"),
            proto=row.get("proto"),
            bytes=row.get("bytes"),
            extra=extra,
        )
    except Exception:
        return None


def _feed_row_to_event(row: Dict[str, Any]) -> NetEventDB | None:
    payload = dict(row or {})
    payload["extra"] = _strip_large_extra(payload.get("extra") or {})
    if not payload.get("id"):
        payload["id"] = 0
    return _row_to_event_safe(payload)


def _guess_app_proto_from_port(port: int | None, transport: str | None) -> str:
    if port in {53, 5353}:
        return "dns"
    if port in {80, 8080, 8000, 8888}:
        return "http"
    if port in {443, 8443}:
        return "tls"
    if port == 22:
        return "ssh"
    t = (transport or "").strip().lower()
    return t if t else "unknown"


def _guess_app_protocols_from_port_counts(port_counts: List[ProtoCount]) -> List[ProtoCount]:
    acc: Dict[str, int] = {}
    for item in port_counts:
        try:
            port = int(str(item.key))
        except Exception:
            continue
        guessed = _guess_app_proto_from_port(port, None)
        acc[guessed] = int(acc.get(guessed, 0)) + int(item.count or 0)
    out = [ProtoCount(key=k, count=v) for k, v in acc.items() if v > 0]
    out.sort(key=lambda x: int(x.count or 0), reverse=True)
    return out
