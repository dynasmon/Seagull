from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


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


def _compact_mapping(raw: Any, *, max_items: int, max_key_len: int, max_text_len: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}

    out: dict[str, Any] = {}
    for index, (key, value) in enumerate(raw.items()):
        if index >= max(1, int(max_items)):
            break
        normalized_key = _to_text(key, max_len=max_key_len)
        if not normalized_key:
            continue
        if isinstance(value, str):
            out[normalized_key] = value[: max(1, int(max_text_len))]
            continue
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            trimmed: list[Any] = []
            for item in list(value)[:8]:
                if isinstance(item, Mapping):
                    trimmed.append(_compact_mapping(item, max_items=8, max_key_len=max_key_len, max_text_len=max_text_len))
                elif isinstance(item, str):
                    trimmed.append(item[: max(1, int(max_text_len))])
                else:
                    trimmed.append(item)
            out[normalized_key] = trimmed
            continue
        if isinstance(value, Mapping):
            out[normalized_key] = _compact_mapping(value, max_items=8, max_key_len=max_key_len, max_text_len=max_text_len)
            continue
        out[normalized_key] = value
    return out


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


def project_response_action_compact(action: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(action, Mapping):
        return out

    action_id = _to_int(action.get("id"), minimum=1)
    if action_id is None:
        return out
    out["id"] = action_id

    for key, max_len in (
        ("action_type", 64),
        ("agent_id", 64),
        ("status", 24),
        ("requested_by", 64),
        ("cancelled_by", 64),
        ("last_error", 240),
    ):
        text = _to_text(action.get(key), max_len=max_len)
        if text is not None:
            out[key] = text

    for key in (
        "requested_at",
        "delivered_at",
        "started_at",
        "finished_at",
        "cancelled_at",
        "created_at",
        "updated_at",
        "expires_at",
    ):
        iso_value = _to_iso(action.get(key))
        if iso_value is not None:
            out[key] = iso_value

    return out


def project_response_action_result_summary(result: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(result, Mapping):
        return out

    result_id = _to_int(result.get("id"), minimum=1)
    if result_id is not None:
        out["id"] = result_id

    response_action_id = _to_int(result.get("response_action_id"), minimum=1)
    if response_action_id is not None:
        out["response_action_id"] = response_action_id

    for key, max_len in (("agent_id", 64), ("status", 24), ("error", 240)):
        text = _to_text(result.get(key), max_len=max_len)
        if text is not None:
            out[key] = text

    for key in ("started_at", "finished_at", "created_at", "updated_at"):
        iso_value = _to_iso(result.get(key))
        if iso_value is not None:
            out[key] = iso_value

    payload = result.get("result_payload")
    if isinstance(payload, Mapping):
        keys: list[str] = []
        for raw_key in list(payload.keys())[:12]:
            key = _to_text(raw_key, max_len=64)
            if key is not None:
                keys.append(key)
        out["has_payload"] = bool(keys)
        out["payload_keys"] = keys

        progress_raw = payload.get("progress") if isinstance(payload.get("progress"), Mapping) else payload
        progress_percent = _to_int(
            progress_raw.get("percent") if isinstance(progress_raw, Mapping) else None,
            minimum=0,
            maximum=100,
        )
        progress_stage = _to_text(progress_raw.get("stage") if isinstance(progress_raw, Mapping) else None, max_len=64)
        progress_message = _to_text(
            progress_raw.get("message") if isinstance(progress_raw, Mapping) else None,
            max_len=160,
        )
        if progress_percent is not None or progress_stage is not None or progress_message is not None:
            progress: dict[str, Any] = {}
            if progress_percent is not None:
                progress["percent"] = progress_percent
            if progress_stage is not None:
                progress["stage"] = progress_stage
            if progress_message is not None:
                progress["message"] = progress_message
            out["progress"] = progress

    return out


def project_response_action_lifecycle_patch(
    *,
    lifecycle_event: str,
    workflow: Mapping[str, Any],
    result: Mapping[str, Any] | None = None,
    requires_reconcile: bool = False,
) -> dict[str, Any]:
    workflow_out = project_response_action_compact(workflow)
    if not workflow_out:
        return {}

    out: dict[str, Any] = {
        "action_id": int(workflow_out["id"]),
        "agent_id": str(workflow_out.get("agent_id") or ""),
        "lifecycle_event": str(lifecycle_event or "heartbeat").strip().lower() or "heartbeat",
        "workflow": workflow_out,
        "requires_reconcile": bool(requires_reconcile),
    }

    if isinstance(result, Mapping):
        result_out = project_response_action_result_summary(result)
        if result_out:
            out["result"] = result_out

    return out


def project_compact_event_row(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}

    out: dict[str, Any] = {}

    event_id = _to_int(raw.get("id"), minimum=0)
    if event_id is not None:
        out["id"] = event_id

    agent_id = _to_text(raw.get("agent_id"), max_len=64)
    if agent_id is not None:
        out["agent_id"] = agent_id

    event_type = _to_text(raw.get("event_type"), max_len=64)
    if event_type is not None:
        out["event_type"] = event_type

    schema_version = _to_int(raw.get("schema_version"), minimum=1, maximum=16)
    if schema_version is not None:
        out["schema_version"] = schema_version

    timestamp = _to_iso(raw.get("timestamp"))
    if timestamp is not None:
        out["timestamp"] = timestamp

    for key, max_len in (("src_ip", 64), ("dst_ip", 64), ("proto", 24)):
        value = _to_text(raw.get(key), max_len=max_len)
        if value is not None:
            out[key] = value

    for key in ("src_port", "dst_port", "bytes"):
        value = _to_int(raw.get(key), minimum=0)
        if value is not None:
            out[key] = value

    out["extra"] = _compact_mapping(raw.get("extra"), max_items=24, max_key_len=64, max_text_len=240)
    return out


def project_events_stream_append(
    *,
    agent_id: str,
    rows: Sequence[Mapping[str, Any]],
    batch_size: int,
    coalesced_events: int,
    high_priority: bool,
    domains: Sequence[str],
    event_types: Sequence[str],
    requires_reconcile: bool,
) -> dict[str, Any]:
    return {
        "channel": "events.stream",
        "agent_id": str(agent_id or "").strip(),
        "batch_size": int(max(0, int(batch_size or 0))),
        "coalesced_events": int(max(0, int(coalesced_events or 0))),
        "truncated_events": int(max(0, int(batch_size or 0)) - int(max(0, int(coalesced_events or 0)))),
        "high_priority": bool(high_priority),
        "domains": [str(value) for value in domains if str(value or "").strip()][:8],
        "event_types": [str(value) for value in event_types if str(value or "").strip()][:12],
        "requires_reconcile": bool(requires_reconcile),
        "events": [project_compact_event_row(row) for row in rows if isinstance(row, Mapping)],
    }


def project_ddos_live_patch(
    *,
    agent_id: str,
    rows: Sequence[Mapping[str, Any]],
    batch_size: int,
    coalesced_events: int,
    requires_reconcile: bool,
    summary: Mapping[str, Any] | None,
    pressure: Mapping[str, Any] | None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "channel": "ddos.live",
        "agent_id": str(agent_id or "").strip(),
        "batch_size": int(max(0, int(batch_size or 0))),
        "coalesced_events": int(max(0, int(coalesced_events or 0))),
        "truncated_events": int(max(0, int(batch_size or 0)) - int(max(0, int(coalesced_events or 0)))),
        "requires_reconcile": bool(requires_reconcile),
        "events": [project_compact_event_row(row) for row in rows if isinstance(row, Mapping)],
    }

    if isinstance(summary, Mapping):
        summary_out: dict[str, Any] = {}
        for key in (
            "ddos_packets_estimated",
            "ddos_samples",
            "ddos_peak_pps",
            "ddos_peak_bps",
            "ddos_peak_syn_ratio",
            "ddos_peak_flow_rps",
        ):
            value = summary.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                summary_out[key] = value
        if summary_out:
            out["live_summary"] = summary_out

    if isinstance(pressure, Mapping):
        pressure_out: dict[str, Any] = {}
        for key in ("active", "protection_active"):
            value = _to_bool(pressure.get(key))
            if value is not None:
                pressure_out[key] = value
        for key in ("phase", "reason"):
            value = _to_text(pressure.get(key), max_len=32)
            if value is not None:
                pressure_out[key] = value
        for key in ("backlog_events", "backlog_messages"):
            value = _to_int(pressure.get(key), minimum=0)
            if value is not None:
                pressure_out[key] = value
        if pressure_out:
            out["pressure"] = pressure_out

    return out
