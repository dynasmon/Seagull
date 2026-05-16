from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.features.network_topology.models import TopologyEdgeModel, TopologyNodeModel, TopologyObservationModel
from app.features.network_topology.schemas import (
    TopologyEdgeOut,
    TopologyEvidencePageMetaOut,
    TopologyEvidenceSourceOut,
    TopologyNodeOut,
    TopologyObservationOut,
    TopologyRelatedAlertOut,
    TopologyRelatedAttackChainCaseOut,
    TopologyRelatedExposureFindingOut,
    TopologyRelatedFlowOut,
    TopologySubnetOut,
)

_UTC = timezone.utc
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "private_key",
    "session",
)


def _node_to_out(node: TopologyNodeModel) -> TopologyNodeOut:
    return TopologyNodeOut(
        node_key=node.node_key,
        node_type=node.node_type,
        agent_id=node.agent_id,
        label=node.label,
        ip=node.ip,
        cidr=node.cidr,
        port=node.port,
        protocol=node.protocol,
        severity=node.severity,
        risk_score=int(node.risk_score or 0),
        confidence=int(node.confidence or 0),
        is_stale=bool(node.is_stale),
        event_count=int(node.event_count or 0),
        alert_count=int(node.alert_count or 0),
        observation_count=int(node.observation_count or 0),
        first_seen_at=_to_utc(node.first_seen_at),
        last_seen_at=_to_utc(node.last_seen_at),
        updated_at=_to_utc(node.updated_at),
        metadata=_sanitize_public_json(node.extra_data or {}),
    )

def _edge_to_out(edge: TopologyEdgeModel) -> TopologyEdgeOut:
    return TopologyEdgeOut(
        edge_key=edge.edge_key,
        source_node_key=edge.source_node_key,
        target_node_key=edge.target_node_key,
        edge_type=edge.edge_type,
        agent_id=edge.agent_id,
        weight=float(edge.weight or 1.0),
        confidence=int(edge.confidence or 0),
        severity=edge.severity,
        port=edge.port,
        protocol=edge.protocol,
        event_count=int(edge.event_count or 0),
        alert_count=int(edge.alert_count or 0),
        first_seen_at=_to_utc(edge.first_seen_at),
        last_seen_at=_to_utc(edge.last_seen_at),
        updated_at=_to_utc(edge.updated_at),
        metadata=_sanitize_public_json(edge.extra_data or {}),
    )

def _obs_to_out(obs: TopologyObservationModel) -> TopologyObservationOut:
    raw_context = _sanitize_public_json(obs.raw_context or {})
    return TopologyObservationOut(
        id=int(obs.id),
        node_key=obs.node_key,
        edge_key=obs.edge_key,
        agent_id=obs.agent_id,
        source_type=obs.source_type,
        source_id=obs.source_id,
        observed_at=_to_utc(obs.observed_at),
        summary=obs.summary,
        confidence=_confidence_from_context(raw_context),
        raw_context=raw_context,
    )

def _subnet_node_to_out(node: TopologyNodeModel) -> TopologySubnetOut:
    return TopologySubnetOut(
        node_key=node.node_key,
        cidr=str(node.cidr or node.label),
        label=node.label,
        agent_id=node.agent_id,
        severity=node.severity,
        confidence=int(node.confidence or 0),
        first_seen_at=_to_utc(node.first_seen_at),
        last_seen_at=_to_utc(node.last_seen_at),
        metadata=_sanitize_public_json(node.extra_data or {}),
    )

def _evidence_meta(limit: int, total: int) -> TopologyEvidencePageMetaOut:
    return TopologyEvidencePageMetaOut(
        limit=int(limit),
        total=max(0, int(total or 0)),
        omitted=max(0, int(total or 0) - int(limit)),
    )

def _evidence_source_to_out(row: tuple[str, int, datetime | None]) -> TopologyEvidenceSourceOut:
    source_type, count, latest = row
    return TopologyEvidenceSourceOut(
        source_type=str(source_type or "unknown"),
        count=int(count or 0),
        latest_observed_at=_to_utc(latest) if latest else None,
    )

def _flow_to_out(flow: Any) -> TopologyRelatedFlowOut:
    return TopologyRelatedFlowOut(
        id=int(getattr(flow, "id", 0) or 0),
        timestamp=_to_utc(getattr(flow, "timestamp", None)),
        agent_id=str(getattr(flow, "agent_id", "") or ""),
        event_type=str(getattr(flow, "event_type", "") or "event"),
        src_ip=getattr(flow, "src_ip", None),
        dst_ip=getattr(flow, "dst_ip", None),
        src_port=getattr(flow, "src_port", None),
        dst_port=getattr(flow, "dst_port", None),
        protocol=getattr(flow, "proto", None),
        bytes=getattr(flow, "bytes", None),
        app_proto=getattr(flow, "app_proto", None),
    )

def _alert_to_out(alert: Any) -> TopologyRelatedAlertOut:
    return TopologyRelatedAlertOut(
        id=int(getattr(alert, "id", 0) or 0),
        created_at=_to_utc(getattr(alert, "created_at", None)),
        rule_id=str(getattr(alert, "rule_id", "") or ""),
        severity=str(getattr(alert, "severity", "unknown") or "unknown"),
        status=str(getattr(alert, "status", "open") or "open"),
        confidence=int(getattr(alert, "confidence", 0) or 0),
        description=str(getattr(alert, "description", "") or ""),
        src_ip=getattr(alert, "src_ip", None),
        dst_ip=getattr(alert, "dst_ip", None),
        dst_port=getattr(alert, "dst_port", None),
    )

def _exposure_finding_to_out(finding: Any) -> TopologyRelatedExposureFindingOut:
    return TopologyRelatedExposureFindingOut(
        finding_key=str(getattr(finding, "finding_key", "") or ""),
        asset_key=str(getattr(finding, "asset_key", "") or ""),
        agent_id=getattr(finding, "agent_id", None),
        finding_type=str(getattr(finding, "finding_type", "") or "finding"),
        severity=str(getattr(finding, "severity", "unknown") or "unknown"),
        status=str(getattr(finding, "status", "open") or "open"),
        confidence=int(getattr(finding, "confidence", 0) or 0),
        title=str(getattr(finding, "title", "") or ""),
        summary=str(getattr(finding, "summary", "") or ""),
        last_seen_at=_to_utc(getattr(finding, "last_seen_at", None)),
    )

def _attack_chain_case_to_out(case: Any) -> TopologyRelatedAttackChainCaseOut:
    return TopologyRelatedAttackChainCaseOut(
        id=int(getattr(case, "id", 0) or 0),
        agent_id=str(getattr(case, "agent_id", "") or ""),
        suspect_ip=getattr(case, "suspect_ip", None),
        status=str(getattr(case, "status", "open") or "open"),
        score=int(getattr(case, "score", 0) or 0),
        max_stage=str(getattr(case, "max_stage", "initial_access") or "initial_access"),
        step_count=int(getattr(case, "step_count", 0) or 0),
        first_seen_at=_to_utc(getattr(case, "first_seen_at", None)),
        last_seen_at=_to_utc(getattr(case, "last_seen_at", None)),
    )

def _app_protocols_for_edge(edge: TopologyEdgeModel, flows: list[Any], aggregate_protocols: list[str] | None = None) -> list[str]:
    protocols: list[str] = []
    metadata = edge.extra_data if isinstance(edge.extra_data, dict) else {}
    raw = metadata.get("application_protocols") or metadata.get("app_protocols")
    if isinstance(raw, list):
        protocols.extend(str(item).strip().lower() for item in raw if str(item or "").strip())
    elif isinstance(raw, str) and raw.strip():
        protocols.append(raw.strip().lower())
    for flow in flows:
        app_proto = str(getattr(flow, "app_proto", "") or "").strip().lower()
        if app_proto:
            protocols.append(app_proto)
    for app_proto in aggregate_protocols or []:
        proto = str(app_proto or "").strip().lower()
        if proto:
            protocols.append(proto)
    out: list[str] = []
    seen: set[str] = set()
    for proto in protocols:
        if proto in seen:
            continue
        seen.add(proto)
        out.append(proto)
    return out[:12]

def _confidence_from_context(context: dict[str, Any]) -> int:
    raw = context.get("confidence")
    try:
        value = int(raw)
    except Exception:
        return 50
    return max(0, min(100, value))

def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)

def _sanitize_public_json(value: Any, *, depth: int = 0) -> Any:
    if depth >= 6:
        return "[truncated]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            if _is_sensitive_key(text_key):
                continue
            out[text_key] = _sanitize_public_json(item, depth=depth + 1)
        return out
    if isinstance(value, list):
        return [_sanitize_public_json(item, depth=depth + 1) for item in value[:50]]
    if isinstance(value, tuple):
        return [_sanitize_public_json(item, depth=depth + 1) for item in value[:50]]
    if isinstance(value, str) and len(value) > 2048:
        return value[:2048] + "...[truncated]"
    return value

def _to_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(_UTC)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=_UTC)
    return dt
