from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping


def _to_int(value: Any, *, minimum: int | None = None, maximum: int | None = None) -> int | None:
    try:
        out = int(value)
    except Exception:
        return None
    if minimum is not None and out < minimum:
        out = minimum
    if maximum is not None and out > maximum:
        out = maximum
    return out


def _to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _to_text(value: Any, *, max_len: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[: max(1, int(max_len))]


def _to_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat()
    text = _to_text(value, max_len=64)
    if not text:
        return None
    return text


def project_overview_kpi_patch(
    *,
    received: int,
    backlog_events: int,
    backlog_messages: int,
    protection_active: bool,
    phase: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "events_5m_delta": int(max(0, int(received))),
        "backlog_events": int(max(0, int(backlog_events))),
        "backlog_messages": int(max(0, int(backlog_messages))),
        "protection_active": bool(protection_active),
        "phase": str(phase or "ok"),
        "reason": str(reason or "ok"),
    }


def project_storm_status_patch(raw: Mapping[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if not isinstance(raw, Mapping):
        return payload

    for key in (
        "active",
        "phase",
        "eps",
        "ingest_rate_eps",
        "process_rate_eps",
        "processed_messages_per_sec",
        "sample_hot_percent",
        "sample_warm_percent",
        "drop_percent",
        "shed_percent",
        "rejected_events",
        "rollup_only_events",
        "backlog_events",
        "backlog_messages",
        "workers_active",
        "draining_seconds",
        "reason",
        "since",
        "open_alert_id",
    ):
        value = raw.get(key)
        if key in {"active"}:
            bool_value = _to_bool(value)
            if bool_value is not None:
                payload[key] = bool_value
            continue
        if key in {
            "eps",
            "ingest_rate_eps",
            "process_rate_eps",
            "processed_messages_per_sec",
            "sample_hot_percent",
            "sample_warm_percent",
            "drop_percent",
            "shed_percent",
            "rejected_events",
            "rollup_only_events",
            "backlog_events",
            "backlog_messages",
            "workers_active",
            "draining_seconds",
            "open_alert_id",
        }:
            n = _to_int(value)
            if n is not None:
                payload[key] = n
            continue
        if key in {"phase", "reason"}:
            text = _to_text(value, max_len=32)
            if text is not None:
                payload[key] = text
            continue
        if key == "since":
            text = _to_iso(value)
            payload[key] = text
            continue

    return payload


def project_alert_compact(alert: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(alert, Mapping):
        return out

    alert_id = _to_int(alert.get("alert_id") if "alert_id" in alert else alert.get("id"), minimum=1)
    if alert_id is None:
        return out
    out["id"] = alert_id

    created_at = _to_iso(alert.get("created_at"))
    if created_at:
        out["created_at"] = created_at

    for key, max_len in (("rule_id", 64), ("severity", 16), ("src_ip", 45), ("dst_ip", 45), ("description", 240), ("status", 24)):
        text = _to_text(alert.get(key), max_len=max_len)
        if text is not None:
            out[key] = text

    dst_port = _to_int(alert.get("dst_port"), minimum=0)
    if dst_port is not None:
        out["dst_port"] = dst_port

    confidence = _to_int(alert.get("confidence"), minimum=0, maximum=100)
    if confidence is not None:
        out["confidence"] = confidence

    updated_at = _to_iso(alert.get("updated_at"))
    if updated_at:
        out["updated_at"] = updated_at

    return out


def project_alerts_delta_patch(*, action: str, alert: Mapping[str, Any], alerts_60m_delta: int = 0) -> dict[str, Any]:
    normalized_action = str(action or "").strip().lower()
    if normalized_action not in {"upsert", "patch"}:
        normalized_action = "patch"

    compact = project_alert_compact(alert)
    payload: dict[str, Any] = {
        "action": normalized_action,
        "alert": compact,
    }
    delta = _to_int(alerts_60m_delta)
    if delta:
        payload["counters"] = {"alerts_60m_delta": delta}
    return payload


def project_agent_presence_patch(*, agent_id: Any, status: Any, is_revoked: Any, last_seen_at: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    agent = _to_text(agent_id, max_len=64)
    if not agent:
        return out
    out["agent_id"] = agent

    status_text = _to_text(status, max_len=32)
    if status_text is not None:
        out["status"] = status_text

    revoked = _to_bool(is_revoked)
    if revoked is not None:
        out["is_revoked"] = revoked

    last_seen = _to_iso(last_seen_at)
    if last_seen is not None:
        out["last_seen_at"] = last_seen

    return out


def project_investigation_workspace_patch(workspace: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(workspace, Mapping):
        return out

    workspace_id = _to_int(workspace.get("id"), minimum=1)
    if workspace_id is None:
        return out

    out["id"] = workspace_id

    updated_at = _to_iso(workspace.get("updated_at"))
    if updated_at is not None:
        out["updated_at"] = updated_at

    for key, max_len in (("status", 16), ("severity", 16), ("priority", 8), ("triage_state", 24), ("assignee", 128), ("updated_by", 64)):
        text = _to_text(workspace.get(key), max_len=max_len)
        if text is not None:
            out[key] = text

    notes_count = _to_int(workspace.get("notes_count"), minimum=0)
    if notes_count is not None:
        out["notes_count"] = notes_count

    bookmarks_count = _to_int(workspace.get("bookmarks_count"), minimum=0)
    if bookmarks_count is not None:
        out["bookmarks_count"] = bookmarks_count

    evidence = workspace.get("evidence_type_counts")
    if isinstance(evidence, Mapping):
        evidence_out: dict[str, int] = {}
        for key, value in evidence.items():
            k = _to_text(key, max_len=64)
            v = _to_int(value, minimum=0)
            if k and v is not None:
                evidence_out[k] = v
        out["evidence_type_counts"] = evidence_out

    return out


def project_investigation_timeline_append(
    *,
    workspace_id: int,
    activity: Mapping[str, Any],
    workspace_patch: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "workspace_id": int(max(1, int(workspace_id))),
    }

    if isinstance(activity, Mapping):
        activity_out: dict[str, Any] = {}
        created_at = _to_iso(activity.get("created_at"))
        if created_at is not None:
            activity_out["created_at"] = created_at
        for key, max_len in (
            ("id", 80),
            ("activity_type", 48),
            ("action", 96),
            ("actor_username", 64),
            ("outcome", 24),
            ("target_type", 48),
            ("target_id", 64),
            ("summary", 240),
        ):
            text = _to_text(activity.get(key), max_len=max_len)
            if text is not None:
                activity_out[key] = text

        changed_fields = activity.get("changed_fields")
        if isinstance(changed_fields, list):
            safe_fields: list[str] = []
            for raw in changed_fields[:12]:
                text = _to_text(raw, max_len=64)
                if text is not None:
                    safe_fields.append(text)
            activity_out["changed_fields"] = safe_fields

        if activity_out:
            out["activity"] = activity_out

    if isinstance(workspace_patch, Mapping):
        patch = project_investigation_workspace_patch(workspace_patch)
        if patch:
            out["workspace_patch"] = patch

    return out
