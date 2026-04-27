from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Optional
from urllib.parse import urlencode

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.core.recent_feed import fetch_event_by_id as fetch_recent_feed_event_by_id
from app.core.pagination import decode_cursor, encode_cursor, make_cursor_ts_id, parse_cursor_ts_id
from app.core.portal_auth import PortalPrincipal
from app.features.investigations import repository
from app.features.investigations.models import (
    InvestigationEvidenceBookmarkModel,
    InvestigationNoteModel,
    InvestigationWorkspaceModel,
)
from app.features.investigations.schemas import (
    EvidenceType,
    InvestigationActivityOut,
    InvestigationBookmarkCreateIn,
    InvestigationBookmarkCreateResult,
    InvestigationBookmarkOut,
    InvestigationNoteCreateIn,
    InvestigationNoteOut,
    InvestigationNoteUpdateIn,
    InvestigationPinOptionsIn,
    InvestigationWorkspaceCreateIn,
    InvestigationWorkspaceOut,
    InvestigationWorkspaceUpdateIn,
    WorkspacePriority,
    WorkspaceSeverity,
    WorkspaceStatus,
    WorkspaceTriageState,
)
from app.features.realtime.projectors import project_investigation_timeline_append, project_investigation_workspace_patch
from app.features.realtime.service import publish_realtime
from app.shared.schemas import CursorPage

_ALLOWED_STATUS: set[str] = {"open", "contained", "resolved", "closed"}
_ALLOWED_SEVERITY: set[str] = {"low", "medium", "high", "critical"}
_ALLOWED_PRIORITY: set[str] = {"p1", "p2", "p3", "p4"}
_ALLOWED_TRIAGE: set[str] = {"untriaged", "triage", "assigned", "investigating", "contained", "closed"}
_ALLOWED_EVIDENCE: set[str] = {
    "net_event",
    "protocol_intel",
    "inventory_snapshot",
    "response_action_result",
    "attack_chain_case",
    "attack_chain_step",
    "alert",
    "vulnerability",
    "exposure_finding",
}

_MAX_SNAPSHOT_BYTES = 64 * 1024
_MAX_JSON_DEPTH = 6
_MAX_JSON_KEYS = 96
_MAX_JSON_LIST = 96
_MAX_JSON_STR = 1024


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _build_deep_link(path: str, **params: Any) -> str:
    items: list[tuple[str, str]] = []
    for key, value in params.items():
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        items.append((str(key), text))
    if not items:
        return path
    return f"{path}?{urlencode(items)}"


def _parse_activity_cursor(cursor: str) -> tuple[datetime, str]:
    obj = decode_cursor(cursor)
    ts_raw = obj.get("ts")
    id_raw = obj.get("id")
    if not isinstance(ts_raw, str) or not isinstance(id_raw, str):
        raise HTTPException(status_code=400, detail="Invalid cursor")
    try:
        ts = datetime.fromisoformat(ts_raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor")
    row_id = id_raw.strip()
    if not row_id:
        raise HTTPException(status_code=400, detail="Invalid cursor")
    return ts, row_id


def _make_activity_cursor(ts: datetime, row_id: str) -> str:
    return encode_cursor({"ts": ts.isoformat(), "id": str(row_id)})


def _clip_text(value: Any, *, max_len: int) -> str:
    s = str(value or "").strip()
    if len(s) <= max_len:
        return s
    return s[:max_len]


def _norm_optional(value: Any, *, max_len: int) -> str | None:
    s = _clip_text(value, max_len=max_len)
    return s or None


def _norm_key(value: str) -> str:
    v = (value or "").strip().lower()
    v = re.sub(r"[^a-z0-9._-]+", "_", v)
    return v[:64] or "investigations"


def _coerce_status(v: Optional[str], *, allow_none: bool = False) -> str | None:
    if v is None:
        return None if allow_none else "open"
    s = _clip_text(v, max_len=16).lower()
    if s not in _ALLOWED_STATUS:
        raise HTTPException(status_code=422, detail="status must be one of: open, contained, resolved, closed")
    return s


def _coerce_severity(v: Optional[str], *, allow_none: bool = False) -> str | None:
    if v is None:
        return None if allow_none else "medium"
    s = _clip_text(v, max_len=16).lower()
    if s not in _ALLOWED_SEVERITY:
        raise HTTPException(status_code=422, detail="severity must be one of: low, medium, high, critical")
    return s


def _coerce_priority(v: Optional[str], *, allow_none: bool = False) -> str | None:
    if v is None:
        return None if allow_none else "p3"
    s = _clip_text(v, max_len=8).lower()
    if s not in _ALLOWED_PRIORITY:
        raise HTTPException(status_code=422, detail="priority must be one of: p1, p2, p3, p4")
    return s


def _coerce_triage(v: Optional[str], *, allow_none: bool = False) -> str | None:
    if v is None:
        return None if allow_none else "untriaged"
    s = _clip_text(v, max_len=16).lower()
    if s not in _ALLOWED_TRIAGE:
        raise HTTPException(
            status_code=422,
            detail="triage_state must be one of: untriaged, triage, assigned, investigating, contained, closed",
        )
    return s


def _status_from_triage(triage_state: str) -> WorkspaceStatus:
    if triage_state == "contained":
        return "contained"
    if triage_state == "closed":
        return "closed"
    return "open"


def _ensure_workspace_or_404(db: Session, workspace_id: int, *, for_update: bool = False) -> InvestigationWorkspaceModel:
    row = repository.get_workspace(db, int(workspace_id), for_update=for_update)
    if not row:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return row


def _ensure_note_or_404(db: Session, note_id: int, *, for_update: bool = False) -> InvestigationNoteModel:
    row = repository.get_note(db, int(note_id), for_update=for_update)
    if not row:
        raise HTTPException(status_code=404, detail="Note not found")
    return row


def _ensure_bookmark_or_404(db: Session, bookmark_id: int, *, for_update: bool = False) -> InvestigationEvidenceBookmarkModel:
    row = repository.get_bookmark(db, int(bookmark_id), for_update=for_update)
    if not row:
        raise HTTPException(status_code=404, detail="Bookmark not found")
    return row


def _workspace_summary(row: InvestigationWorkspaceModel) -> dict[str, Any]:
    if isinstance(row.summary, dict):
        return dict(row.summary)
    return {}


def _ensure_workspace_summary_shape(summary: dict[str, Any]) -> dict[str, Any]:
    out = dict(summary or {})

    notes_count = out.get("notes_count")
    bookmarks_count = out.get("bookmarks_count")
    evidence = out.get("evidence_type_counts")
    triage = out.get("triage_state")

    out["notes_count"] = int(notes_count) if isinstance(notes_count, (int, float)) else 0
    out["bookmarks_count"] = int(bookmarks_count) if isinstance(bookmarks_count, (int, float)) else 0
    out["evidence_type_counts"] = evidence if isinstance(evidence, dict) else {}
    out["triage_state"] = _coerce_triage(str(triage) if triage is not None else "untriaged")
    return out


def _workspace_snapshot(row: InvestigationWorkspaceModel) -> dict[str, Any]:
    summary = _ensure_workspace_summary_shape(_workspace_summary(row))
    return {
        "id": row.id,
        "workspace_key": row.workspace_key,
        "title": row.title,
        "description": row.description,
        "status": row.status,
        "severity": row.severity,
        "priority": row.priority,
        "triage_state": summary.get("triage_state", "untriaged"),
        "assignee": row.assignee,
        "created_by": row.created_by,
        "updated_by": row.updated_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "closed_at": row.closed_at.isoformat() if row.closed_at else None,
        "linked_attack_chain_case_id": row.linked_attack_chain_case_id,
        "primary_agent_id": row.primary_agent_id,
        "summary": summary,
    }


def _workspace_out(row: InvestigationWorkspaceModel) -> InvestigationWorkspaceOut:
    summary = _ensure_workspace_summary_shape(_workspace_summary(row))
    return InvestigationWorkspaceOut(
        id=int(row.id),
        workspace_key=str(row.workspace_key),
        title=str(row.title),
        description=row.description,
        status=row.status,
        severity=row.severity,
        priority=row.priority,
        triage_state=summary.get("triage_state", "untriaged"),
        assignee=row.assignee,
        created_by=row.created_by,
        updated_by=row.updated_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        closed_at=row.closed_at,
        linked_attack_chain_case_id=row.linked_attack_chain_case_id,
        primary_agent_id=row.primary_agent_id,
        summary=summary,
        notes_count=int(summary.get("notes_count") or 0),
        bookmarks_count=int(summary.get("bookmarks_count") or 0),
        evidence_type_counts={
            str(k): int(v)
            for k, v in (summary.get("evidence_type_counts") or {}).items()
            if str(k) in _ALLOWED_EVIDENCE
        },
    )


def _workspace_realtime_patch(row: InvestigationWorkspaceModel) -> dict[str, Any]:
    workspace = _workspace_out(row).dict()
    return project_investigation_workspace_patch(workspace)


def _publish_investigation_timeline_append(
    *,
    workspace: InvestigationWorkspaceModel,
    action: str,
    before: dict[str, Any],
    after: dict[str, Any],
    actor_username: str,
    resource_id: str | None,
    changed_fields: list[str] | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    try:
        workspace_patch = _workspace_realtime_patch(workspace)
        row = SimpleNamespace(
            id=f"rt:{uuid.uuid4().hex}",
            action=str(action or ""),
            before=dict(before or {}),
            after=dict(after or {}),
            context=dict(context or {}),
            changed_fields=list(changed_fields or []),
            actor_username=str(actor_username or "") or None,
            created_at=_utc_now(),
            outcome="success",
            resource_id=str(resource_id or ""),
        )
        activity = _activity_out(row, workspace_id=int(workspace.id)).dict()
        payload = project_investigation_timeline_append(
            workspace_id=int(workspace.id),
            activity=activity,
            workspace_patch=workspace_patch,
        )
        publish_realtime("ui.investigations.timeline.append", payload)
        if workspace_patch:
            publish_realtime(
                "ui.investigations.workspace.patch",
                {
                    "workspace_id": int(workspace.id),
                    "workspace_patch": workspace_patch,
                },
            )
    except Exception:
        return


def _note_out(row: InvestigationNoteModel) -> InvestigationNoteOut:
    edited = bool(row.updated_at and row.created_at and row.updated_at > row.created_at)
    return InvestigationNoteOut(
        id=int(row.id),
        workspace_id=int(row.workspace_id),
        author=str(row.author),
        body=str(row.body),
        created_at=row.created_at,
        updated_at=row.updated_at,
        edited=edited,
    )


def _bookmark_out(row: InvestigationEvidenceBookmarkModel) -> InvestigationBookmarkOut:
    tags = row.tags if isinstance(row.tags, list) else []
    metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
    payload_snapshot = row.payload_snapshot if isinstance(row.payload_snapshot, dict) else {}
    return InvestigationBookmarkOut(
        id=int(row.id),
        workspace_id=int(row.workspace_id),
        evidence_type=row.evidence_type,
        evidence_subtype=row.evidence_subtype,
        source_module=row.source_module,
        title=row.title,
        summary=row.summary,
        agent_id=row.agent_id,
        observed_at=row.observed_at,
        created_by=row.created_by,
        created_at=row.created_at,
        ref_id=row.ref_id,
        ref_table=row.ref_table,
        fingerprint=row.fingerprint,
        tags=[str(t) for t in tags if str(t).strip()],
        payload_snapshot=payload_snapshot,
        metadata=metadata,
    )


def _sanitize_json(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_JSON_DEPTH:
        return "<max_depth>"
    if value is None:
        return None
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:_MAX_JSON_STR]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for idx, (k, v) in enumerate(value.items()):
            if idx >= _MAX_JSON_KEYS:
                break
            key = str(k)[:96]
            out[key] = _sanitize_json(v, depth=depth + 1)
        return out
    if isinstance(value, list):
        return [_sanitize_json(v, depth=depth + 1) for v in value[:_MAX_JSON_LIST]]
    if isinstance(value, tuple):
        return [_sanitize_json(v, depth=depth + 1) for v in list(value)[:_MAX_JSON_LIST]]
    return str(value)[:_MAX_JSON_STR]


def _json_size_bytes(value: Any) -> int:
    try:
        payload = json.dumps(value, ensure_ascii=True, separators=(",", ":"), default=str)
    except Exception:
        payload = json.dumps(_sanitize_json(value), ensure_ascii=True, separators=(",", ":"), default=str)
    return len(payload.encode("utf-8"))


def _ensure_snapshot_size(snapshot: dict[str, Any]) -> dict[str, Any]:
    payload = _sanitize_json(snapshot)
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="invalid evidence snapshot")

    if _json_size_bytes(payload) <= _MAX_SNAPSHOT_BYTES:
        return payload

    # Strip high-entropy keys first to keep snapshots useful but bounded.
    for key in ("extra", "details", "result_payload", "context", "metadata"):
        if key in payload:
            payload[key] = {"truncated": True}

    if _json_size_bytes(payload) <= _MAX_SNAPSHOT_BYTES:
        return payload

    raise HTTPException(status_code=413, detail="evidence snapshot payload too large")


def _event_addr_summary(event) -> str:
    src = str(event.src_ip or "-")
    if event.src_port is not None:
        src = f"{src}:{int(event.src_port)}"
    dst = str(event.dst_ip or "-")
    if event.dst_port is not None:
        dst = f"{dst}:{int(event.dst_port)}"
    proto = str(event.proto or "-")
    return f"{src} -> {dst} ({proto})"


def _event_extra(event) -> dict[str, Any]:
    if isinstance(getattr(event, "extra", None), dict):
        return dict(event.extra)
    return {}


def _parse_event_ts(value: Any) -> datetime | None:
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


def _to_int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _event_from_feed_row(row: dict[str, Any], *, event_id: int) -> Any | None:
    if not isinstance(row, dict):
        return None
    extra = row.get("extra")
    if not isinstance(extra, dict):
        extra = {}

    resolved_id = _to_int_or_none(row.get("id")) or int(event_id)
    resolved_ts = _parse_event_ts(row.get("timestamp")) or _utc_now()

    return SimpleNamespace(
        id=resolved_id,
        timestamp=resolved_ts,
        agent_id=_norm_optional(row.get("agent_id"), max_len=64),
        event_type=_clip_text(row.get("event_type"), max_len=64) or "event",
        src_ip=_norm_optional(row.get("src_ip"), max_len=128),
        dst_ip=_norm_optional(row.get("dst_ip"), max_len=128),
        src_port=_to_int_or_none(row.get("src_port")),
        dst_port=_to_int_or_none(row.get("dst_port")),
        proto=_norm_optional(row.get("proto"), max_len=32),
        bytes=_to_int_or_none(row.get("bytes")),
        app_proto=_norm_optional(row.get("app_proto"), max_len=64) or _norm_optional(extra.get("app_proto"), max_len=64),
        app_proto_reason=_norm_optional(row.get("app_proto_reason"), max_len=128)
        or _norm_optional(extra.get("app_proto_reason"), max_len=128),
        app_proto_conf_band=_norm_optional(row.get("app_proto_conf_band"), max_len=64)
        or _norm_optional(extra.get("app_proto_conf_band"), max_len=64),
        dns_qname=_norm_optional(row.get("dns_qname"), max_len=512) or _norm_optional(extra.get("dns_qname"), max_len=512),
        http_host=_norm_optional(row.get("http_host"), max_len=512) or _norm_optional(extra.get("http_host"), max_len=512),
        http_method=_norm_optional(row.get("http_method"), max_len=32) or _norm_optional(extra.get("http_method"), max_len=32),
        tls_sni=_norm_optional(row.get("tls_sni"), max_len=512) or _norm_optional(extra.get("tls_sni"), max_len=512),
        tls_alpn_first=_norm_optional(row.get("tls_alpn_first"), max_len=64)
        or _norm_optional(extra.get("tls_alpn_first"), max_len=64),
        ja3=_norm_optional(row.get("ja3"), max_len=256) or _norm_optional(extra.get("ja3"), max_len=256),
        ja4=_norm_optional(row.get("ja4"), max_len=256) or _norm_optional(extra.get("ja4"), max_len=256),
        ja4_ptype=_norm_optional(row.get("ja4_ptype"), max_len=16) or _norm_optional(extra.get("ja4_ptype"), max_len=16),
        extra=extra,
    )


def _resolve_event_for_pin(db: Session, *, event_id: int, agent_id_hint: str | None = None) -> Any | None:
    event = repository.get_event(db, int(event_id))
    if event:
        return event

    feed_row = fetch_recent_feed_event_by_id(event_id=int(event_id), agent_id=agent_id_hint)
    if feed_row is None and agent_id_hint:
        feed_row = fetch_recent_feed_event_by_id(event_id=int(event_id), agent_id=None)
    if feed_row is None:
        return None
    return _event_from_feed_row(feed_row, event_id=int(event_id))


def _build_net_event_snapshot(event) -> dict[str, Any]:
    extra = _event_extra(event)
    payload = {
        "event_id": int(event.id),
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "agent_id": event.agent_id,
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "proto": event.proto,
        "bytes": event.bytes,
        "app_proto": getattr(event, "app_proto", None) or extra.get("app_proto"),
        "dns_qname": getattr(event, "dns_qname", None) or extra.get("dns_qname"),
        "http_host": getattr(event, "http_host", None) or extra.get("http_host"),
        "http_method": getattr(event, "http_method", None) or extra.get("http_method"),
        "tls_sni": getattr(event, "tls_sni", None) or extra.get("tls_sni"),
        "ja3": getattr(event, "ja3", None) or extra.get("ja3"),
        "ja4": getattr(event, "ja4", None) or extra.get("ja4"),
        "extra": extra,
        "deep_link": _build_deep_link(
            "/events",
            event_id=int(event.id),
            agent_id=event.agent_id,
            event_type=event.event_type,
            window_minutes=1440,
        ),
    }
    return _ensure_snapshot_size(payload)


def _build_protocol_intel_snapshot(event, *, indicator_context: dict[str, Any] | None = None) -> dict[str, Any]:
    extra = _event_extra(event)
    app_proto = (getattr(event, "app_proto", None) or extra.get("app_proto") or "unknown")
    indicator_context = indicator_context if isinstance(indicator_context, dict) else {}
    indicator_kind = _norm_optional(indicator_context.get("protocol_indicator_kind"), max_len=64)
    indicator_value = _norm_optional(indicator_context.get("protocol_indicator_value"), max_len=256)
    if not indicator_kind:
        indicator_kind = "app_proto"
    if not indicator_value:
        indicator_value = str(app_proto)
    payload = {
        "source_event_id": int(event.id),
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "agent_id": event.agent_id,
        "event_type": event.event_type,
        "app_proto": app_proto,
        "app_proto_reason": getattr(event, "app_proto_reason", None) or extra.get("app_proto_reason"),
        "app_proto_conf_band": getattr(event, "app_proto_conf_band", None) or extra.get("app_proto_conf_band"),
        "dns_qname": getattr(event, "dns_qname", None) or extra.get("dns_qname"),
        "http_host": getattr(event, "http_host", None) or extra.get("http_host"),
        "http_method": getattr(event, "http_method", None) or extra.get("http_method"),
        "tls_sni": getattr(event, "tls_sni", None) or extra.get("tls_sni"),
        "tls_alpn_first": getattr(event, "tls_alpn_first", None) or extra.get("tls_alpn_first"),
        "ja3": getattr(event, "ja3", None) or extra.get("ja3"),
        "ja4": getattr(event, "ja4", None) or extra.get("ja4"),
        "ja4_ptype": getattr(event, "ja4_ptype", None) or extra.get("ja4_ptype"),
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "proto": event.proto,
        "deep_link": _build_deep_link(
            "/events/network",
            agent_id=event.agent_id,
            since_minutes=720,
            focus_event_id=int(event.id),
            indicator_kind=indicator_kind,
            indicator_value=indicator_value,
        ),
    }
    return _ensure_snapshot_size(payload)


def _build_inventory_snapshot(snapshot) -> dict[str, Any]:
    os_data = snapshot.os if isinstance(snapshot.os, dict) else {}
    extra = snapshot.extra if isinstance(snapshot.extra, dict) else {}
    payload = {
        "snapshot_id": int(snapshot.id),
        "agent_id": snapshot.agent_id,
        "collected_at": snapshot.collected_at.isoformat() if snapshot.collected_at else None,
        "manager": snapshot.manager,
        "packages_count": int(snapshot.packages_count or 0),
        "packages_hash": snapshot.packages_hash,
        "os_summary": {
            "pretty_name": os_data.get("pretty_name"),
            "name": os_data.get("name"),
            "id": os_data.get("id"),
            "version": os_data.get("version"),
            "goos": os_data.get("goos"),
        },
        "warnings": extra.get("warnings") or extra.get("warning") or [],
        "deep_link": _build_deep_link(
            "/inventory",
            agent_id=snapshot.agent_id,
            snapshot_id=int(snapshot.id),
            open_drawer=1,
        ),
    }
    return _ensure_snapshot_size(payload)


def _build_response_result_snapshot(result, action) -> dict[str, Any]:
    result_payload = result.result_payload if isinstance(result.result_payload, dict) else {}
    payload = {
        "result_id": int(result.id),
        "response_action_id": int(result.response_action_id),
        "agent_id": result.agent_id,
        "action_type": getattr(action, "action_type", None),
        "action_status": getattr(action, "status", None),
        "result_status": result.status,
        "started_at": result.started_at.isoformat() if result.started_at else None,
        "finished_at": result.finished_at.isoformat() if result.finished_at else None,
        "error": result.error,
        "result_payload": result_payload,
        "deep_link": _build_deep_link(
            "/agents",
            agent_id=result.agent_id,
            open_response_action=1,
            response_action_id=int(result.response_action_id),
            response_result_id=int(result.id),
            response_tab="result",
        ),
    }
    return _ensure_snapshot_size(payload)


def _build_attack_chain_case_snapshot(case) -> dict[str, Any]:
    context = case.context if isinstance(case.context, dict) else {}
    payload = {
        "case_id": int(case.id),
        "agent_id": case.agent_id,
        "suspect_ip": case.suspect_ip,
        "status": case.status,
        "score": int(case.score or 0),
        "max_stage": case.max_stage,
        "first_seen_at": case.first_seen_at.isoformat() if case.first_seen_at else None,
        "last_seen_at": case.last_seen_at.isoformat() if case.last_seen_at else None,
        "step_count": int(case.step_count or 0),
        "context": context,
        "deep_link": _build_deep_link("/attack-chain", case_id=int(case.id)),
    }
    return _ensure_snapshot_size(payload)


def _build_attack_chain_step_snapshot(step, case_agent_id: str | None) -> dict[str, Any]:
    details = step.details if isinstance(step.details, dict) else {}
    payload = {
        "step_id": int(step.id),
        "case_id": int(step.case_id),
        "agent_id": case_agent_id,
        "stage": step.stage,
        "label": step.label,
        "score_delta": int(step.score_delta or 0),
        "event_id": step.event_id,
        "event_type": step.event_type,
        "timestamp": step.timestamp.isoformat() if step.timestamp else None,
        "src_ip": step.src_ip,
        "dst_ip": step.dst_ip,
        "src_port": step.src_port,
        "dst_port": step.dst_port,
        "proto": step.proto,
        "details": details,
        "deep_link": _build_deep_link("/attack-chain", case_id=int(step.case_id), step_id=int(step.id)),
    }
    return _ensure_snapshot_size(payload)


def _make_dedupe_key(
    *,
    workspace_id: int,
    evidence_type: str,
    ref_table: str | None,
    ref_id: str | None,
    fingerprint: str | None,
    payload_snapshot: dict[str, Any],
) -> str:
    material = f"{workspace_id}|{evidence_type}|{ref_table or ''}|{ref_id or ''}|{fingerprint or ''}"
    if not ref_id:
        payload_key = json.dumps(payload_snapshot, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)
        material = f"{material}|{payload_key}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _issue_workspace_key(db: Session, title: str) -> str:
    base = _clip_text(title, max_len=96).lower()
    base = re.sub(r"[^a-z0-9]+", "-", base).strip("-")
    if not base:
        base = "workspace"
    base = base[:32]

    for _ in range(8):
        candidate = f"{base}-{uuid.uuid4().hex[:8]}"[:48]
        if repository.get_workspace_by_key(db, candidate) is None:
            return candidate
    return f"ws-{uuid.uuid4().hex[:12]}"


def _refresh_workspace_summary(db: Session, row: InvestigationWorkspaceModel) -> None:
    summary = _ensure_workspace_summary_shape(_workspace_summary(row))
    summary["notes_count"] = repository.count_notes_by_workspace(db, int(row.id))
    summary["bookmarks_count"] = repository.count_bookmarks_by_workspace(db, int(row.id))
    summary["evidence_type_counts"] = repository.count_bookmarks_grouped_by_type(db, int(row.id))
    row.summary = summary
    repository.save_workspace(db, row)


def _ensure_linked_case_exists_if_set(db: Session, case_id: Optional[int]) -> None:
    if case_id is None:
        return
    row = repository.get_attack_chain_case(db, int(case_id))
    if not row:
        raise HTTPException(status_code=404, detail="Linked attack chain case not found")


def list_workspaces(
    db: Session,
    *,
    page_size: int,
    cursor: Optional[str],
    status: Optional[str],
    severity: Optional[str],
    priority: Optional[str],
    assignee: Optional[str],
    linked_attack_chain_case_id: Optional[int],
    agent_id: Optional[str],
    search: Optional[str],
) -> CursorPage[InvestigationWorkspaceOut]:
    cursor_parsed = parse_cursor_ts_id(cursor) if cursor else None

    rows = repository.list_workspaces_page(
        db,
        page_size=int(page_size),
        status=_coerce_status(status, allow_none=True),
        severity=_coerce_severity(severity, allow_none=True),
        priority=_coerce_priority(priority, allow_none=True),
        assignee=_norm_optional(assignee, max_len=128),
        linked_attack_chain_case_id=(int(linked_attack_chain_case_id) if linked_attack_chain_case_id is not None else None),
        agent_id=_norm_optional(agent_id, max_len=64),
        search=_norm_optional(search, max_len=128),
        cursor_parsed=cursor_parsed,
    )

    has_more = len(rows) > int(page_size)
    items = rows[: int(page_size)]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = make_cursor_ts_id(last.updated_at, int(last.id))

    return CursorPage(items=[_workspace_out(r) for r in items], next_cursor=next_cursor, has_more=has_more)


def create_workspace(
    db: Session,
    *,
    payload: InvestigationWorkspaceCreateIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationWorkspaceOut:
    title = _clip_text(payload.title, max_len=200)
    if not title:
        raise HTTPException(status_code=422, detail="title is required")

    _ensure_linked_case_exists_if_set(db, payload.linked_attack_chain_case_id)

    triage_state = _coerce_triage(payload.triage_state)
    status = _coerce_status(payload.status)
    # Keep triage/status coherent by default.
    if triage_state in {"contained", "closed"}:
        status = _status_from_triage(triage_state)

    summary = _ensure_workspace_summary_shape(
        {
            "notes_count": 0,
            "bookmarks_count": 0,
            "evidence_type_counts": {},
            "triage_state": triage_state,
        }
    )

    row = repository.create_workspace(
        db,
        workspace_key=_issue_workspace_key(db, title),
        title=title,
        description=_norm_optional(payload.description, max_len=4000),
        status=status,
        severity=_coerce_severity(payload.severity),
        priority=_coerce_priority(payload.priority),
        assignee=_norm_optional(payload.assignee, max_len=128),
        created_by=_clip_text(user.username, max_len=64) or "unknown",
        updated_by=_clip_text(user.username, max_len=64) or "unknown",
        closed_at=(_utc_now() if status == "closed" else None),
        linked_attack_chain_case_id=payload.linked_attack_chain_case_id,
        primary_agent_id=_norm_optional(payload.primary_agent_id, max_len=64),
        summary=summary,
    )
    repository.flush(db)

    if payload.initial_note:
        body = _clip_text(payload.initial_note, max_len=4000)
        if body:
            repository.create_note(
                db,
                workspace_id=int(row.id),
                author=_clip_text(user.username, max_len=64) or "analyst",
                body=body,
            )
            _refresh_workspace_summary(db, row)

    audit_writer(
        db,
        request=request,
        actor=audit_actor(user.id, user.username),
        event_type="admin_action",
        action="workspace.create",
        resource_type="investigation_workspace",
        resource_id=str(row.id),
        outcome="success",
        before={},
        after=_workspace_snapshot(row),
    )

    repository.commit(db)
    repository.refresh(db, row)
    _publish_investigation_timeline_append(
        workspace=row,
        action="workspace.create",
        before={},
        after=_workspace_snapshot(row),
        actor_username=user.username,
        resource_id=str(row.id),
    )
    return _workspace_out(row)


def get_workspace(db: Session, *, workspace_id: int) -> InvestigationWorkspaceOut:
    row = _ensure_workspace_or_404(db, int(workspace_id))
    return _workspace_out(row)


def update_workspace(
    db: Session,
    *,
    workspace_id: int,
    payload: InvestigationWorkspaceUpdateIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationWorkspaceOut:
    row = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)
    fields_set: set[str] = set(getattr(payload, "__fields_set__", set()) or set())

    before = _workspace_snapshot(row)
    summary = _ensure_workspace_summary_shape(_workspace_summary(row))

    if "title" in fields_set:
        title = _clip_text(payload.title, max_len=200)
        if not title:
            raise HTTPException(status_code=422, detail="title must not be empty")
        row.title = title
    if "description" in fields_set:
        row.description = _norm_optional(payload.description, max_len=4000)
    if "assignee" in fields_set:
        row.assignee = _norm_optional(payload.assignee, max_len=128)
    if payload.severity is not None:
        row.severity = _coerce_severity(payload.severity)
    if payload.priority is not None:
        row.priority = _coerce_priority(payload.priority)
    if "primary_agent_id" in fields_set:
        row.primary_agent_id = _norm_optional(payload.primary_agent_id, max_len=64)
    if "linked_attack_chain_case_id" in fields_set:
        _ensure_linked_case_exists_if_set(db, payload.linked_attack_chain_case_id)
        row.linked_attack_chain_case_id = (
            int(payload.linked_attack_chain_case_id) if payload.linked_attack_chain_case_id is not None else None
        )

    status_explicit = payload.status is not None
    triage_explicit = payload.triage_state is not None

    if payload.triage_state is not None:
        triage = _coerce_triage(payload.triage_state)
        summary["triage_state"] = triage
        if not status_explicit:
            row.status = _status_from_triage(triage)

    if payload.status is not None:
        row.status = _coerce_status(payload.status)
        if not triage_explicit:
            if row.status == "closed":
                summary["triage_state"] = "closed"
            elif row.status == "contained":
                summary["triage_state"] = "contained"
            elif summary.get("triage_state") in {"contained", "closed"}:
                summary["triage_state"] = "investigating"

    if row.status == "closed":
        row.closed_at = row.closed_at or _utc_now()
    elif payload.status is not None:
        row.closed_at = None

    row.summary = summary
    row.updated_by = _clip_text(user.username, max_len=64) or row.updated_by

    repository.save_workspace(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(user.id, user.username),
        event_type="admin_action",
        action="workspace.update",
        resource_type="investigation_workspace",
        resource_id=str(row.id),
        outcome="success",
        before=before,
        after=_workspace_snapshot(row),
    )

    repository.commit(db)
    repository.refresh(db, row)
    _publish_investigation_timeline_append(
        workspace=row,
        action="workspace.update",
        before=before,
        after=_workspace_snapshot(row),
        actor_username=user.username,
        resource_id=str(row.id),
        changed_fields=sorted(fields_set),
    )
    return _workspace_out(row)


def close_workspace(
    db: Session,
    *,
    workspace_id: int,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationWorkspaceOut:
    row = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)
    before = _workspace_snapshot(row)

    row.status = "closed"
    row.closed_at = row.closed_at or _utc_now()
    row.updated_by = _clip_text(user.username, max_len=64) or row.updated_by

    summary = _ensure_workspace_summary_shape(_workspace_summary(row))
    summary["triage_state"] = "closed"
    row.summary = summary

    repository.save_workspace(db, row)

    audit_writer(
        db,
        request=request,
        actor=audit_actor(user.id, user.username),
        event_type="admin_action",
        action="workspace.close",
        resource_type="investigation_workspace",
        resource_id=str(row.id),
        outcome="success",
        before=before,
        after=_workspace_snapshot(row),
    )

    repository.commit(db)
    repository.refresh(db, row)
    _publish_investigation_timeline_append(
        workspace=row,
        action="workspace.close",
        before=before,
        after=_workspace_snapshot(row),
        actor_username=user.username,
        resource_id=str(row.id),
    )
    return _workspace_out(row)


def reopen_workspace(
    db: Session,
    *,
    workspace_id: int,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationWorkspaceOut:
    row = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)
    before = _workspace_snapshot(row)

    row.status = "open"
    row.closed_at = None
    row.updated_by = _clip_text(user.username, max_len=64) or row.updated_by

    summary = _ensure_workspace_summary_shape(_workspace_summary(row))
    if summary.get("triage_state") == "closed":
        summary["triage_state"] = "investigating"
    row.summary = summary

    repository.save_workspace(db, row)

    audit_writer(
        db,
        request=request,
        actor=audit_actor(user.id, user.username),
        event_type="admin_action",
        action="workspace.reopen",
        resource_type="investigation_workspace",
        resource_id=str(row.id),
        outcome="success",
        before=before,
        after=_workspace_snapshot(row),
    )

    repository.commit(db)
    repository.refresh(db, row)
    _publish_investigation_timeline_append(
        workspace=row,
        action="workspace.reopen",
        before=before,
        after=_workspace_snapshot(row),
        actor_username=user.username,
        resource_id=str(row.id),
    )
    return _workspace_out(row)


def list_notes(db: Session, *, workspace_id: int, limit: int) -> list[InvestigationNoteOut]:
    _ensure_workspace_or_404(db, int(workspace_id))
    rows = repository.list_notes_by_workspace(db, workspace_id=int(workspace_id), limit=max(1, min(int(limit), 1000)))
    return [_note_out(r) for r in rows]


def create_note(
    db: Session,
    *,
    workspace_id: int,
    payload: InvestigationNoteCreateIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationNoteOut:
    workspace = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)

    body = _clip_text(payload.body, max_len=4000)
    if not body:
        raise HTTPException(status_code=422, detail="body is required")

    row = repository.create_note(
        db,
        workspace_id=int(workspace_id),
        author=_clip_text(user.username, max_len=64) or "analyst",
        body=body,
    )
    repository.flush(db)

    workspace.updated_by = _clip_text(user.username, max_len=64) or workspace.updated_by
    _refresh_workspace_summary(db, workspace)

    audit_writer(
        db,
        request=request,
        actor=audit_actor(user.id, user.username),
        event_type="admin_action",
        action="workspace.note.create",
        resource_type="investigation_note",
        resource_id=str(row.id),
        outcome="success",
        before={},
        after={
            "id": row.id,
            "workspace_id": row.workspace_id,
            "author": row.author,
        },
    )

    repository.commit(db)
    repository.refresh(db, row)
    repository.refresh(db, workspace)
    _publish_investigation_timeline_append(
        workspace=workspace,
        action="workspace.note.create",
        before={},
        after={
            "id": row.id,
            "workspace_id": row.workspace_id,
            "author": row.author,
        },
        actor_username=user.username,
        resource_id=str(row.id),
    )
    return _note_out(row)


def update_note(
    db: Session,
    *,
    note_id: int,
    payload: InvestigationNoteUpdateIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationNoteOut:
    row = _ensure_note_or_404(db, int(note_id), for_update=True)
    workspace = _ensure_workspace_or_404(db, int(row.workspace_id), for_update=True)

    before = {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "author": row.author,
        "body": row.body,
    }

    body = _clip_text(payload.body, max_len=4000)
    if not body:
        raise HTTPException(status_code=422, detail="body is required")

    row.body = body
    repository.save_note(db, row)

    workspace.updated_by = _clip_text(user.username, max_len=64) or workspace.updated_by
    repository.save_workspace(db, workspace)

    audit_writer(
        db,
        request=request,
        actor=audit_actor(user.id, user.username),
        event_type="admin_action",
        action="workspace.note.update",
        resource_type="investigation_note",
        resource_id=str(row.id),
        outcome="success",
        before=before,
        after={
            "id": row.id,
            "workspace_id": row.workspace_id,
            "author": row.author,
            "body": row.body,
        },
    )

    repository.commit(db)
    repository.refresh(db, row)
    repository.refresh(db, workspace)
    _publish_investigation_timeline_append(
        workspace=workspace,
        action="workspace.note.update",
        before=before,
        after={
            "id": row.id,
            "workspace_id": row.workspace_id,
            "author": row.author,
            "body": row.body,
        },
        actor_username=user.username,
        resource_id=str(row.id),
        changed_fields=["body"],
    )
    return _note_out(row)


def delete_note(db: Session, *, note_id: int) -> dict[str, Any]:
    row = _ensure_note_or_404(db, int(note_id), for_update=True)
    workspace = _ensure_workspace_or_404(db, int(row.workspace_id), for_update=True)

    repository.delete_note(db, row)
    _refresh_workspace_summary(db, workspace)
    repository.commit(db)

    return {"status": "ok", "note_id": int(note_id)}


def list_bookmarks(
    db: Session,
    *,
    workspace_id: int,
    evidence_type: Optional[str],
    page_size: int,
    cursor: Optional[str],
) -> CursorPage[InvestigationBookmarkOut]:
    _ensure_workspace_or_404(db, int(workspace_id))

    ev_type = _clip_text(evidence_type, max_len=32).lower() if evidence_type else None
    if ev_type and ev_type not in _ALLOWED_EVIDENCE:
        raise HTTPException(status_code=422, detail="invalid evidence_type filter")

    cursor_parsed = parse_cursor_ts_id(cursor) if cursor else None
    rows = repository.list_bookmarks_page(
        db,
        workspace_id=int(workspace_id),
        evidence_type=ev_type,
        page_size=max(1, min(int(page_size), 200)),
        cursor_parsed=cursor_parsed,
    )

    has_more = len(rows) > int(page_size)
    items = rows[: int(page_size)]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = make_cursor_ts_id(last.created_at, int(last.id))

    return CursorPage(items=[_bookmark_out(r) for r in items], next_cursor=next_cursor, has_more=has_more)


def _audit_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _classify_activity_type(action: str, *, before: dict[str, Any], after: dict[str, Any]) -> str:
    normalized = str(action or "").strip().lower()
    if normalized == "workspace.create":
        return "workspace_created"
    if normalized == "workspace.close":
        return "workspace_closed"
    if normalized == "workspace.reopen":
        return "workspace_reopened"
    if normalized == "workspace.update":
        before_case = before.get("linked_attack_chain_case_id")
        after_case = after.get("linked_attack_chain_case_id")
        if after_case and str(after_case) != str(before_case):
            return "attack_chain_case_linked"
        return "workspace_updated"
    if normalized == "workspace.note.create":
        return "note_created"
    if normalized == "workspace.note.update":
        return "note_updated"
    if normalized == "workspace.bookmark.create":
        if str(after.get("evidence_type") or "").strip().lower() == "attack_chain_step":
            return "attack_chain_step_pinned"
        return "bookmark_created"
    if normalized == "workspace.bookmark.delete":
        return "bookmark_deleted"
    return "workspace_action"


def _activity_summary(
    *,
    activity_type: str,
    action: str,
    changed_fields: list[str],
    before: dict[str, Any],
    after: dict[str, Any],
) -> str:
    if activity_type == "workspace_created":
        return "Workspace created"
    if activity_type == "workspace_closed":
        return "Workspace closed"
    if activity_type == "workspace_reopened":
        return "Workspace reopened"
    if activity_type == "workspace_updated":
        fields = [str(f).strip() for f in changed_fields if str(f).strip()]
        if fields:
            return f"Workspace updated ({', '.join(fields[:4])})"
        return "Workspace updated"
    if activity_type == "attack_chain_case_linked":
        case_id = after.get("linked_attack_chain_case_id")
        return f"Linked attack chain case #{case_id}" if case_id is not None else "Linked attack chain case"
    if activity_type == "note_created":
        return "Note added"
    if activity_type == "note_updated":
        return "Note edited"
    if activity_type == "bookmark_created":
        ev_type = str(after.get("evidence_type") or "").strip()
        return f"Evidence pinned ({ev_type})" if ev_type else "Evidence pinned"
    if activity_type == "bookmark_deleted":
        ev_type = str(before.get("evidence_type") or "").strip()
        return f"Evidence removed ({ev_type})" if ev_type else "Evidence removed"
    if activity_type == "attack_chain_step_pinned":
        step_id = after.get("ref_id")
        return f"Pinned attack chain step #{step_id}" if step_id is not None else "Pinned attack chain step"
    action_label = str(action or "").strip() or "workspace.action"
    return f"Workspace action: {action_label}"


def _activity_out(row, *, workspace_id: int) -> InvestigationActivityOut:
    before = _audit_dict(getattr(row, "before", {}))
    after = _audit_dict(getattr(row, "after", {}))
    context = _audit_dict(getattr(row, "context", {}))
    action = str(getattr(row, "action", "") or "")
    changed_fields = [str(x) for x in (getattr(row, "changed_fields", []) or []) if str(x).strip()]
    activity_type = _classify_activity_type(action, before=before, after=after)

    target_type: str | None = None
    target_id: str | None = None
    if activity_type in {"workspace_created", "workspace_updated", "workspace_closed", "workspace_reopened", "workspace_action"}:
        target_type = "workspace"
        target_id = str(workspace_id)
    elif activity_type in {"note_created", "note_updated"}:
        target_type = "note"
        target_id = str(getattr(row, "resource_id", "") or "")
    elif activity_type in {"bookmark_created", "bookmark_deleted"}:
        target_type = "bookmark"
        target_id = str(getattr(row, "resource_id", "") or "")
    elif activity_type == "attack_chain_case_linked":
        target_type = "attack_chain_case"
        case_id = after.get("linked_attack_chain_case_id")
        target_id = str(case_id) if case_id is not None else None
    elif activity_type == "attack_chain_step_pinned":
        target_type = "attack_chain_step"
        step_id = after.get("ref_id")
        target_id = str(step_id) if step_id is not None else None

    return InvestigationActivityOut(
        id=str(getattr(row, "id", "")),
        workspace_id=int(workspace_id),
        activity_type=activity_type,
        action=action,
        actor_username=getattr(row, "actor_username", None),
        created_at=getattr(row, "created_at"),
        outcome=str(getattr(row, "outcome", "success") or "success"),
        target_type=target_type,
        target_id=(target_id if target_id else None),
        summary=_activity_summary(
            activity_type=activity_type,
            action=action,
            changed_fields=changed_fields,
            before=before,
            after=after,
        ),
        changed_fields=changed_fields,
        context=context,
    )


def list_activity(
    db: Session,
    *,
    workspace_id: int,
    page_size: int,
    cursor: Optional[str],
) -> CursorPage[InvestigationActivityOut]:
    _ensure_workspace_or_404(db, int(workspace_id))

    cursor_parsed = _parse_activity_cursor(cursor) if cursor else None
    size = max(1, min(int(page_size), 200))
    rows = repository.list_workspace_activity_audit_page(
        db,
        workspace_id=int(workspace_id),
        page_size=size,
        cursor_parsed=cursor_parsed,
    )

    has_more = len(rows) > size
    items = rows[:size]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = _make_activity_cursor(last.created_at, str(last.id))

    return CursorPage(
        items=[_activity_out(r, workspace_id=int(workspace_id)) for r in items],
        next_cursor=next_cursor,
        has_more=has_more,
    )


def _pin_bookmark_from_event(
    db: Session,
    *,
    workspace: InvestigationWorkspaceModel,
    event_id: int,
    created_by: str,
    evidence_type: EvidenceType,
    opts: InvestigationPinOptionsIn,
    request,
    actor: PortalPrincipal,
    audit_writer,
) -> InvestigationBookmarkCreateResult:
    metadata = _sanitize_json(opts.metadata or {}) if isinstance(opts.metadata, dict) else {}
    agent_id_hint = _norm_optional(metadata.get("agent_id"), max_len=64) if isinstance(metadata, dict) else None

    event = _resolve_event_for_pin(db, event_id=int(event_id), agent_id_hint=agent_id_hint)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    if evidence_type == "protocol_intel":
        snapshot = _build_protocol_intel_snapshot(
            event,
            indicator_context=metadata,
        )
        subtype = _norm_optional(opts.evidence_subtype, max_len=64) or str(snapshot.get("app_proto") or "protocol")[:64]
        title = f"Protocol intel · event #{int(event.id)}"
        summary = f"{snapshot.get('app_proto') or 'unknown'} · {_event_addr_summary(event)}"
    else:
        snapshot = _build_net_event_snapshot(event)
        subtype = _norm_optional(opts.evidence_subtype, max_len=64)
        title = f"{_clip_text(event.event_type, max_len=48)} · event #{int(event.id)}"
        summary = _event_addr_summary(event)

    return _create_bookmark(
        db,
        workspace=workspace,
        evidence_type=evidence_type,
        evidence_subtype=subtype,
        source_module=_norm_key(opts.source_module or "events"),
        title=title,
        summary=summary,
        agent_id=_norm_optional(event.agent_id, max_len=64),
        observed_at=event.timestamp,
        created_by=created_by,
        ref_id=str(int(event.id)),
        ref_table="net_events",
        fingerprint=str(int(event.id)),
        tags=opts.tags,
        payload_snapshot=snapshot,
        metadata=metadata,
        note_text=_norm_optional(opts.note, max_len=1000),
        request=request,
        actor=actor,
        audit_writer=audit_writer,
    )


def _pin_bookmark_from_inventory_snapshot(
    db: Session,
    *,
    workspace: InvestigationWorkspaceModel,
    snapshot_id: int,
    created_by: str,
    opts: InvestigationPinOptionsIn,
    request,
    actor: PortalPrincipal,
    audit_writer,
) -> InvestigationBookmarkCreateResult:
    snapshot = repository.get_inventory_snapshot(db, int(snapshot_id))
    if not snapshot:
        raise HTTPException(status_code=404, detail="Inventory snapshot not found")

    payload = _build_inventory_snapshot(snapshot)
    title = f"Inventory snapshot #{int(snapshot.id)}"
    summary = f"agent {snapshot.agent_id} · {int(snapshot.packages_count or 0)} packages"

    return _create_bookmark(
        db,
        workspace=workspace,
        evidence_type="inventory_snapshot",
        evidence_subtype=_norm_optional(opts.evidence_subtype, max_len=64),
        source_module=_norm_key(opts.source_module or "inventory"),
        title=title,
        summary=summary,
        agent_id=_norm_optional(snapshot.agent_id, max_len=64),
        observed_at=snapshot.collected_at,
        created_by=created_by,
        ref_id=str(int(snapshot.id)),
        ref_table="agent_inventory_snapshots",
        fingerprint=f"inv:{int(snapshot.id)}",
        tags=opts.tags,
        payload_snapshot=payload,
        metadata=_sanitize_json(opts.metadata or {}),
        note_text=_norm_optional(opts.note, max_len=1000),
        request=request,
        actor=actor,
        audit_writer=audit_writer,
    )


def _pin_bookmark_from_response_result(
    db: Session,
    *,
    workspace: InvestigationWorkspaceModel,
    result_id: int,
    created_by: str,
    opts: InvestigationPinOptionsIn,
    request,
    actor: PortalPrincipal,
    audit_writer,
) -> InvestigationBookmarkCreateResult:
    result = repository.get_response_action_result(db, int(result_id))
    if not result:
        raise HTTPException(status_code=404, detail="Response action result not found")

    action = repository.get_response_action(db, int(result.response_action_id))
    payload = _build_response_result_snapshot(result, action)
    action_type = _clip_text(getattr(action, "action_type", "action"), max_len=48) if action else "action"

    title = f"Response result #{int(result.id)} · {action_type}"
    summary = f"status {result.status}" + (f" · {result.error[:120]}" if result.error else "")

    observed_at = result.finished_at or result.created_at

    return _create_bookmark(
        db,
        workspace=workspace,
        evidence_type="response_action_result",
        evidence_subtype=_norm_optional(opts.evidence_subtype, max_len=64) or action_type,
        source_module=_norm_key(opts.source_module or "response"),
        title=title,
        summary=summary,
        agent_id=_norm_optional(result.agent_id, max_len=64),
        observed_at=observed_at,
        created_by=created_by,
        ref_id=str(int(result.id)),
        ref_table="response_action_results",
        fingerprint=f"rr:{int(result.id)}",
        tags=opts.tags,
        payload_snapshot=payload,
        metadata=_sanitize_json(opts.metadata or {}),
        note_text=_norm_optional(opts.note, max_len=1000),
        request=request,
        actor=actor,
        audit_writer=audit_writer,
    )


def _pin_bookmark_from_attack_case(
    db: Session,
    *,
    workspace: InvestigationWorkspaceModel,
    case_id: int,
    created_by: str,
    opts: InvestigationPinOptionsIn,
    request,
    actor: PortalPrincipal,
    audit_writer,
) -> InvestigationBookmarkCreateResult:
    case = repository.get_attack_chain_case(db, int(case_id))
    if not case:
        raise HTTPException(status_code=404, detail="Attack chain case not found")

    payload = _build_attack_chain_case_snapshot(case)

    title = f"Attack Chain case #{int(case.id)}"
    summary = f"{case.status} · score {int(case.score or 0)} · stage {case.max_stage}"

    return _create_bookmark(
        db,
        workspace=workspace,
        evidence_type="attack_chain_case",
        evidence_subtype=_norm_optional(opts.evidence_subtype, max_len=64),
        source_module=_norm_key(opts.source_module or "attack_chain"),
        title=title,
        summary=summary,
        agent_id=_norm_optional(case.agent_id, max_len=64),
        observed_at=case.last_seen_at,
        created_by=created_by,
        ref_id=str(int(case.id)),
        ref_table="attack_chain_cases",
        fingerprint=f"ac:{int(case.id)}",
        tags=opts.tags,
        payload_snapshot=payload,
        metadata=_sanitize_json(opts.metadata or {}),
        note_text=_norm_optional(opts.note, max_len=1000),
        request=request,
        actor=actor,
        audit_writer=audit_writer,
    )


def _pin_bookmark_from_attack_step(
    db: Session,
    *,
    workspace: InvestigationWorkspaceModel,
    step_id: int,
    created_by: str,
    opts: InvestigationPinOptionsIn,
    request,
    actor: PortalPrincipal,
    audit_writer,
) -> InvestigationBookmarkCreateResult:
    step = repository.get_attack_chain_step(db, int(step_id))
    if not step:
        raise HTTPException(status_code=404, detail="Attack chain step not found")

    case = repository.get_attack_chain_case(db, int(step.case_id))
    agent_id = _norm_optional(getattr(case, "agent_id", None), max_len=64)

    payload = _build_attack_chain_step_snapshot(step, agent_id)

    title = f"Attack Chain step #{int(step.id)} · {step.stage}"
    summary = _clip_text(step.label or "", max_len=200) or f"case #{int(step.case_id)}"

    return _create_bookmark(
        db,
        workspace=workspace,
        evidence_type="attack_chain_step",
        evidence_subtype=_norm_optional(opts.evidence_subtype, max_len=64),
        source_module=_norm_key(opts.source_module or "attack_chain"),
        title=title,
        summary=summary,
        agent_id=agent_id,
        observed_at=step.timestamp,
        created_by=created_by,
        ref_id=str(int(step.id)),
        ref_table="attack_chain_steps",
        fingerprint=_norm_optional(step.fingerprint, max_len=128) or f"acs:{int(step.id)}",
        tags=opts.tags,
        payload_snapshot=payload,
        metadata=_sanitize_json(opts.metadata or {}),
        note_text=_norm_optional(opts.note, max_len=1000),
        request=request,
        actor=actor,
        audit_writer=audit_writer,
    )


def _create_bookmark(
    db: Session,
    *,
    workspace: InvestigationWorkspaceModel,
    evidence_type: str,
    evidence_subtype: str | None,
    source_module: str,
    title: str,
    summary: str | None,
    agent_id: str | None,
    observed_at,
    created_by: str,
    ref_id: str | None,
    ref_table: str | None,
    fingerprint: str | None,
    tags: list[str],
    payload_snapshot: dict[str, Any],
    metadata: dict[str, Any],
    note_text: str | None,
    request,
    actor: PortalPrincipal,
    audit_writer,
) -> InvestigationBookmarkCreateResult:
    if evidence_type not in _ALLOWED_EVIDENCE:
        raise HTTPException(status_code=422, detail="unsupported evidence_type")

    snapshot = _ensure_snapshot_size(payload_snapshot)
    dedupe_key = _make_dedupe_key(
        workspace_id=int(workspace.id),
        evidence_type=evidence_type,
        ref_table=ref_table,
        ref_id=ref_id,
        fingerprint=fingerprint,
        payload_snapshot=snapshot,
    )

    existing = repository.find_bookmark_by_dedupe(
        db,
        workspace_id=int(workspace.id),
        dedupe_key=dedupe_key,
    )
    if existing:
        return InvestigationBookmarkCreateResult(created=False, duplicate_of_id=int(existing.id), bookmark=_bookmark_out(existing))

    try:
        row = repository.create_bookmark(
            db,
            workspace_id=int(workspace.id),
            evidence_type=evidence_type,
            evidence_subtype=evidence_subtype,
            source_module=source_module,
            title=_clip_text(title, max_len=200),
            summary=_norm_optional(summary, max_len=4000),
            agent_id=_norm_optional(agent_id, max_len=64),
            observed_at=observed_at,
            created_by=_clip_text(created_by, max_len=64) or "analyst",
            ref_id=_norm_optional(ref_id, max_len=128),
            ref_table=_norm_optional(ref_table, max_len=64),
            fingerprint=_norm_optional(fingerprint, max_len=128),
            dedupe_key=dedupe_key,
            tags=tags,
            payload_snapshot=snapshot,
            metadata=(metadata if isinstance(metadata, dict) else {}),
        )
        repository.flush(db)
    except IntegrityError:
        if hasattr(db, "rollback"):
            db.rollback()
        existing = repository.find_bookmark_by_dedupe(
            db,
            workspace_id=int(workspace.id),
            dedupe_key=dedupe_key,
        )
        if existing:
            return InvestigationBookmarkCreateResult(created=False, duplicate_of_id=int(existing.id), bookmark=_bookmark_out(existing))
        raise HTTPException(status_code=409, detail="Evidence already pinned in this workspace")

    workspace.updated_by = _clip_text(actor.username, max_len=64) or workspace.updated_by
    repository.save_workspace(db, workspace)

    note_row = None
    if note_text:
        note_row = repository.create_note(
            db,
            workspace_id=int(workspace.id),
            author=_clip_text(actor.username, max_len=64) or "analyst",
            body=note_text,
        )
        repository.flush(db)
        audit_writer(
            db,
            request=request,
            actor=audit_actor(actor.id, actor.username),
            event_type="admin_action",
            action="workspace.note.create",
            resource_type="investigation_note",
            resource_id=str(note_row.id),
            outcome="success",
            before={},
            after={
                "id": note_row.id,
                "workspace_id": note_row.workspace_id,
                "author": note_row.author,
            },
            context={"source": "bookmark_pin"},
        )

    _refresh_workspace_summary(db, workspace)

    audit_writer(
        db,
        request=request,
        actor=audit_actor(actor.id, actor.username),
        event_type="admin_action",
        action="workspace.bookmark.create",
        resource_type="investigation_bookmark",
        resource_id=str(row.id),
        outcome="success",
        before={},
        after={
            "id": row.id,
            "workspace_id": row.workspace_id,
            "evidence_type": row.evidence_type,
            "ref_id": row.ref_id,
            "ref_table": row.ref_table,
        },
    )

    repository.commit(db)
    repository.refresh(db, row)
    repository.refresh(db, workspace)
    _publish_investigation_timeline_append(
        workspace=workspace,
        action="workspace.bookmark.create",
        before={},
        after={
            "id": row.id,
            "workspace_id": row.workspace_id,
            "evidence_type": row.evidence_type,
            "ref_id": row.ref_id,
            "ref_table": row.ref_table,
        },
        actor_username=actor.username,
        resource_id=str(row.id),
        context={"source": "bookmark_pin"} if note_row is not None else {},
    )
    if note_row is not None:
        _publish_investigation_timeline_append(
            workspace=workspace,
            action="workspace.note.create",
            before={},
            after={
                "id": note_row.id,
                "workspace_id": note_row.workspace_id,
                "author": note_row.author,
            },
            actor_username=actor.username,
            resource_id=str(note_row.id),
            context={"source": "bookmark_pin"},
        )
    return InvestigationBookmarkCreateResult(created=True, duplicate_of_id=None, bookmark=_bookmark_out(row))


def create_bookmark(
    db: Session,
    *,
    workspace_id: int,
    payload: InvestigationBookmarkCreateIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationBookmarkCreateResult:
    workspace = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)
    created_by = _clip_text(user.username, max_len=64) or "analyst"

    opts = InvestigationPinOptionsIn(
        source_module=payload.source_module,
        evidence_subtype=payload.evidence_subtype,
        note=payload.note,
        tags=payload.tags,
        metadata=payload.metadata,
    )

    if payload.evidence_type == "net_event":
        return _pin_bookmark_from_event(
            db,
            workspace=workspace,
            event_id=int(payload.source_event_id),
            created_by=created_by,
            evidence_type="net_event",
            opts=opts,
            request=request,
            actor=user,
            audit_writer=audit_writer,
        )
    if payload.evidence_type == "protocol_intel":
        return _pin_bookmark_from_event(
            db,
            workspace=workspace,
            event_id=int(payload.source_event_id),
            created_by=created_by,
            evidence_type="protocol_intel",
            opts=opts,
            request=request,
            actor=user,
            audit_writer=audit_writer,
        )
    if payload.evidence_type == "inventory_snapshot":
        return _pin_bookmark_from_inventory_snapshot(
            db,
            workspace=workspace,
            snapshot_id=int(payload.inventory_snapshot_id),
            created_by=created_by,
            opts=opts,
            request=request,
            actor=user,
            audit_writer=audit_writer,
        )
    if payload.evidence_type == "response_action_result":
        return _pin_bookmark_from_response_result(
            db,
            workspace=workspace,
            result_id=int(payload.response_action_result_id),
            created_by=created_by,
            opts=opts,
            request=request,
            actor=user,
            audit_writer=audit_writer,
        )
    if payload.evidence_type == "attack_chain_case":
        return _pin_bookmark_from_attack_case(
            db,
            workspace=workspace,
            case_id=int(payload.attack_chain_case_id),
            created_by=created_by,
            opts=opts,
            request=request,
            actor=user,
            audit_writer=audit_writer,
        )
    if payload.evidence_type == "attack_chain_step":
        return _pin_bookmark_from_attack_step(
            db,
            workspace=workspace,
            step_id=int(payload.attack_chain_step_id),
            created_by=created_by,
            opts=opts,
            request=request,
            actor=user,
            audit_writer=audit_writer,
        )

    raise HTTPException(status_code=422, detail="Unsupported evidence_type")


def delete_bookmark(
    db: Session,
    *,
    bookmark_id: int,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> dict[str, Any]:
    row = _ensure_bookmark_or_404(db, int(bookmark_id), for_update=True)
    workspace = _ensure_workspace_or_404(db, int(row.workspace_id), for_update=True)

    before = {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "evidence_type": row.evidence_type,
        "ref_id": row.ref_id,
        "ref_table": row.ref_table,
    }

    repository.delete_bookmark(db, row)

    workspace.updated_by = _clip_text(user.username, max_len=64) or workspace.updated_by
    _refresh_workspace_summary(db, workspace)

    audit_writer(
        db,
        request=request,
        actor=audit_actor(user.id, user.username),
        event_type="admin_action",
        action="workspace.bookmark.delete",
        resource_type="investigation_bookmark",
        resource_id=str(bookmark_id),
        outcome="success",
        before=before,
        after={},
    )

    repository.commit(db)
    repository.refresh(db, workspace)
    _publish_investigation_timeline_append(
        workspace=workspace,
        action="workspace.bookmark.delete",
        before=before,
        after={},
        actor_username=user.username,
        resource_id=str(bookmark_id),
    )
    return {"status": "ok", "bookmark_id": int(bookmark_id)}


def pin_event(
    db: Session,
    *,
    workspace_id: int,
    event_id: int,
    payload: InvestigationPinOptionsIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationBookmarkCreateResult:
    workspace = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)
    return _pin_bookmark_from_event(
        db,
        workspace=workspace,
        event_id=int(event_id),
        created_by=_clip_text(user.username, max_len=64) or "analyst",
        evidence_type="net_event",
        opts=payload,
        request=request,
        actor=user,
        audit_writer=audit_writer,
    )


def pin_protocol_intel_event(
    db: Session,
    *,
    workspace_id: int,
    event_id: int,
    payload: InvestigationPinOptionsIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationBookmarkCreateResult:
    workspace = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)
    return _pin_bookmark_from_event(
        db,
        workspace=workspace,
        event_id=int(event_id),
        created_by=_clip_text(user.username, max_len=64) or "analyst",
        evidence_type="protocol_intel",
        opts=payload,
        request=request,
        actor=user,
        audit_writer=audit_writer,
    )


def pin_inventory_snapshot(
    db: Session,
    *,
    workspace_id: int,
    snapshot_id: int,
    payload: InvestigationPinOptionsIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationBookmarkCreateResult:
    workspace = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)
    return _pin_bookmark_from_inventory_snapshot(
        db,
        workspace=workspace,
        snapshot_id=int(snapshot_id),
        created_by=_clip_text(user.username, max_len=64) or "analyst",
        opts=payload,
        request=request,
        actor=user,
        audit_writer=audit_writer,
    )


def pin_response_result(
    db: Session,
    *,
    workspace_id: int,
    result_id: int,
    payload: InvestigationPinOptionsIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationBookmarkCreateResult:
    workspace = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)
    return _pin_bookmark_from_response_result(
        db,
        workspace=workspace,
        result_id=int(result_id),
        created_by=_clip_text(user.username, max_len=64) or "analyst",
        opts=payload,
        request=request,
        actor=user,
        audit_writer=audit_writer,
    )


def pin_attack_chain_case(
    db: Session,
    *,
    workspace_id: int,
    case_id: int,
    payload: InvestigationPinOptionsIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationBookmarkCreateResult:
    workspace = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)
    return _pin_bookmark_from_attack_case(
        db,
        workspace=workspace,
        case_id=int(case_id),
        created_by=_clip_text(user.username, max_len=64) or "analyst",
        opts=payload,
        request=request,
        actor=user,
        audit_writer=audit_writer,
    )


def pin_attack_chain_step(
    db: Session,
    *,
    workspace_id: int,
    step_id: int,
    payload: InvestigationPinOptionsIn,
    request,
    user: PortalPrincipal,
    audit_writer=write_audit_event,
) -> InvestigationBookmarkCreateResult:
    workspace = _ensure_workspace_or_404(db, int(workspace_id), for_update=True)
    return _pin_bookmark_from_attack_step(
        db,
        workspace=workspace,
        step_id=int(step_id),
        created_by=_clip_text(user.username, max_len=64) or "analyst",
        opts=payload,
        request=request,
        actor=user,
        audit_writer=audit_writer,
    )
