from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from app.features.exposure.domain.constants import (
    ASSET_STATUS_ACTIVE,
    ASSET_STATUS_STALE,
    ASSET_STATUS_UNKNOWN,
    EVIDENCE_SOURCE_TYPES,
    FINDING_STATUS_OPEN,
    FINDING_STATUSES,
    FINDING_TYPES,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_SCORE_BANDS,
    SEVERITY_UNKNOWN,
)
from app.features.exposure.domain.types import EvidenceRef

_ASSET_KEY_RE = re.compile(r"^(agent|ip|host|url):[^\s]{1,200}$")

_SEVERITY_ALIASES: dict[str, str] = {
    "info": SEVERITY_INFORMATIONAL,
    "informational": SEVERITY_INFORMATIONAL,
    "none": SEVERITY_INFORMATIONAL,
    "low": SEVERITY_LOW,
    "medium": SEVERITY_MEDIUM,
    "med": SEVERITY_MEDIUM,
    "moderate": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "critical": SEVERITY_CRITICAL,
    "crit": SEVERITY_CRITICAL,
    "urgent": SEVERITY_CRITICAL,
}


def normalize_asset_key(agent_id: str | None, *, ip: str | None = None, hostname: str | None = None, url: str | None = None) -> str:
    if agent_id:
        clean = re.sub(r"[^\w\-\.]", "", str(agent_id))[:64]
        if clean:
            return f"agent:{clean}"
    if ip:
        clean_ip = re.sub(r"[^\w\.\:\-]", "", str(ip))[:45]
        if clean_ip:
            return f"ip:{clean_ip}"
    if hostname:
        clean_host = re.sub(r"[^\w\.\-]", "", str(hostname).lower())[:128]
        if clean_host:
            return f"host:{clean_host}"
    if url:
        clean_url = str(url).strip()[:200]
        if clean_url:
            return f"url:{clean_url}"
    raise ValueError("Cannot derive asset key: no stable identity provided")


def validate_asset_key(key: str) -> bool:
    return bool(_ASSET_KEY_RE.match(key))


def extract_inventory_os_context(os_data: Any) -> dict[str, Any]:
    data = os_data if isinstance(os_data, dict) else {}
    hostname = str(data.get("hostname") or data.get("fqdn") or "").strip() or None
    os_name = str(data.get("name") or data.get("os_name") or "").strip() or None

    open_ports: list[int] = []
    raw_ports = data.get("open_ports") or data.get("listening_ports") or []
    if isinstance(raw_ports, list):
        for port in raw_ports[:64]:
            try:
                open_ports.append(int(port))
            except (TypeError, ValueError):
                continue

    ip_addresses: list[str] = []
    raw_addresses = data.get("addresses") or data.get("ip_addresses") or []
    if isinstance(raw_addresses, list):
        for raw in raw_addresses[:32]:
            value = str(raw or "").strip()
            if value:
                ip_addresses.append(value)

    interfaces = data.get("interfaces") or []
    if isinstance(interfaces, list):
        for iface in interfaces[:16]:
            if not isinstance(iface, dict):
                continue
            for key in ("ip", "ip_address", "address"):
                value = str(iface.get(key) or "").strip()
                if value and value not in ip_addresses:
                    ip_addresses.append(value)

    return {
        "hostname": hostname,
        "os_name": os_name,
        "open_ports": open_ports,
        "ip_addresses": ip_addresses,
    }


def normalize_severity(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    return _SEVERITY_ALIASES.get(raw, SEVERITY_UNKNOWN)


def severity_from_score(score: int) -> str:
    clamped = max(0, min(100, int(score)))
    for threshold, label in SEVERITY_SCORE_BANDS:
        if clamped >= threshold:
            return label
    return SEVERITY_INFORMATIONAL


def normalize_finding_status(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    return raw if raw in FINDING_STATUSES else FINDING_STATUS_OPEN


def normalize_finding_type(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    return raw if raw in FINDING_TYPES else "event"


def normalize_evidence_source_type(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    return raw if raw in EVIDENCE_SOURCE_TYPES else "event"


def clamp_score(value: int | float) -> int:
    return max(0, min(100, int(round(float(value)))))


def clamp_confidence(value: int | float) -> int:
    return max(1, min(99, int(round(float(value)))))


def stable_hash(*parts: str) -> str:
    joined = "\x00".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode()).hexdigest()[:64]


def make_node_key(node_type: str, identifier: str) -> str:
    return f"{node_type}:{stable_hash(node_type, identifier)}"


def make_edge_key(source_node_key: str, target_node_key: str, edge_type: str) -> str:
    return stable_hash(source_node_key, target_node_key, edge_type)


def make_finding_key(finding_type: str, asset_key: str, source_id: str) -> str:
    return stable_hash(finding_type, asset_key, source_id)


def normalize_evidence_ref(raw: Any) -> EvidenceRef | None:
    if not isinstance(raw, dict):
        return None
    source_type = normalize_evidence_source_type(raw.get("source_type"))
    source_id = str(raw.get("source_id") or "").strip()
    if not source_id:
        return None
    observed_at = parse_dt(raw.get("observed_at"))
    if observed_at is None:
        observed_at = datetime.now(tz=timezone.utc)
    title = str(raw.get("title") or "")[:256]
    summary = str(raw.get("summary") or "")[:1024]
    meta = raw.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
    return EvidenceRef(
        source_type=source_type,
        source_id=source_id,
        observed_at=observed_at,
        title=title,
        summary=summary,
        metadata=meta,
    )


def parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
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


def asset_status_from_age(last_seen_at: datetime | None, *, active_threshold_hours: int = 24, stale_threshold_hours: int = 168) -> str:
    if last_seen_at is None:
        return ASSET_STATUS_UNKNOWN
    now = datetime.now(tz=timezone.utc)
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)
    age_hours = (now - last_seen_at).total_seconds() / 3600.0
    if age_hours <= active_threshold_hours:
        return ASSET_STATUS_ACTIVE
    if age_hours <= stale_threshold_hours:
        return "inactive"
    return ASSET_STATUS_STALE
