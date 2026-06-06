from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from app.core.observability import incr_counter
from app.features.network_topology import realtime as topology_realtime
from app.features.realtime.projectors import project_alerts_delta_patch
from app.features.realtime.service import publish_realtime

_MAX_DESCRIPTION_LEN = 240


def _iso8601(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat()


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _safe_text(value: Any, *, max_len: int | None = None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if max_len is not None:
        return text[: max(1, int(max_len))]
    return text


def build_alert_realtime_payload(
    *,
    alert_id: int,
    created_at: datetime | None,
    rule_id: str | None,
    severity: str | None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    description: str | None = None,
    confidence: int | None = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"alert_id": int(alert_id)}

    created_iso = _iso8601(created_at)
    if created_iso:
        payload["created_at"] = created_iso

    rule = _safe_text(rule_id, max_len=64)
    if rule:
        payload["rule_id"] = rule

    sev = _safe_text(severity, max_len=16)
    if sev:
        payload["severity"] = sev

    src = _safe_text(src_ip, max_len=45)
    if src:
        payload["src_ip"] = src

    dst = _safe_text(dst_ip, max_len=45)
    if dst:
        payload["dst_ip"] = dst

    if dst_port is not None:
        try:
            payload["dst_port"] = int(dst_port)
        except Exception:
            pass

    desc = _safe_text(description, max_len=_MAX_DESCRIPTION_LEN)
    if desc:
        payload["description"] = desc

    conf = _safe_int(confidence)
    if conf is not None:
        payload["confidence"] = max(0, min(100, conf))

    return payload


def build_alert_realtime_payload_from_row(row: Any) -> Dict[str, Any]:
    return build_alert_realtime_payload(
        alert_id=int(row.id),
        created_at=getattr(row, "created_at", None),
        rule_id=getattr(row, "rule_id", None),
        severity=getattr(row, "severity", None),
        src_ip=getattr(row, "src_ip", None),
        dst_ip=getattr(row, "dst_ip", None),
        dst_port=getattr(row, "dst_port", None),
        description=getattr(row, "description", None),
        confidence=getattr(row, "confidence", None),
    )


def publish_alert_created_payload(payload: Dict[str, Any]) -> None:
    try:
        projected = project_alerts_delta_patch(action="upsert", alert=payload, alerts_60m_delta=1)
        publish_realtime("ui.alerts.delta.patch", projected)
        topology_realtime.publish_topology_invalidate(
            reason="alert_created",
            source="alerts",
            alert_id=_safe_int(payload.get("alert_id") if "alert_id" in payload else payload.get("id")),
            high_priority=True,
        )
    except Exception:
        return


def publish_alert_created_from_row(row: Any) -> None:
    try:
        incr_counter(
            "alert_created_total",
            severity=getattr(row, "severity", None),
            detector_type=getattr(row, "detector_type", None),
        )
    except Exception:
        pass
    try:
        payload = build_alert_realtime_payload_from_row(row)
    except Exception:
        return
    publish_alert_created_payload(payload)


def publish_alert_updated_payload(payload: Dict[str, Any]) -> None:
    try:
        projected = project_alerts_delta_patch(action="patch", alert=payload, alerts_60m_delta=0)
        publish_realtime("ui.alerts.delta.patch", projected)
        topology_realtime.publish_topology_invalidate(
            reason="alert_updated",
            source="alerts",
            alert_id=_safe_int(payload.get("alert_id") if "alert_id" in payload else payload.get("id")),
            high_priority=True,
        )
    except Exception:
        return
