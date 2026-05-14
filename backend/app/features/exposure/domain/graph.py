from __future__ import annotations

from datetime import datetime
from typing import Any

from app.features.exposure.domain.constants import (
    EDGE_TYPE_HAS_CVE,
    EDGE_TYPE_PART_OF_ATTACK_CHAIN,
    EDGE_TYPE_TRIGGERED_ALERT,
    NODE_TYPE_ALERT,
    NODE_TYPE_ASSET,
    NODE_TYPE_ATTACK_CHAIN_CASE,
    NODE_TYPE_CVE,
)
from app.features.exposure.domain.normalization import (
    clamp_confidence,
    clamp_score,
    make_edge_key,
    make_node_key,
    normalize_severity,
)
from app.features.exposure.domain.types import EdgeInput, NodeInput


def asset_node(
    asset_key: str,
    *,
    agent_id: str | None,
    display_name: str,
    severity: str,
    risk_score: int,
    confidence: int,
    first_seen_at: datetime,
    last_seen_at: datetime,
    properties: dict[str, Any] | None = None,
) -> NodeInput:
    node_key = make_node_key(NODE_TYPE_ASSET, asset_key)
    return NodeInput(
        node_key=node_key,
        node_type=NODE_TYPE_ASSET,
        label=display_name,
        severity=normalize_severity(severity),
        risk_score=clamp_score(risk_score),
        confidence=clamp_confidence(confidence),
        asset_key=asset_key,
        agent_id=agent_id,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
        properties=properties or {},
    )


def cve_node(
    cve_id: str,
    *,
    asset_key: str | None,
    agent_id: str | None,
    severity: str,
    cvss_score: float | None,
    first_seen_at: datetime,
    last_seen_at: datetime,
    properties: dict[str, Any] | None = None,
) -> NodeInput:
    node_key = make_node_key(NODE_TYPE_CVE, cve_id.upper())
    risk_score = int((cvss_score or 0) * 10) if cvss_score is not None else 0
    return NodeInput(
        node_key=node_key,
        node_type=NODE_TYPE_CVE,
        label=cve_id.upper(),
        severity=normalize_severity(severity),
        risk_score=clamp_score(risk_score),
        confidence=70,
        asset_key=asset_key,
        agent_id=agent_id,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
        properties=properties or {},
    )


def alert_node(
    alert_id: str | int,
    *,
    asset_key: str | None,
    agent_id: str | None,
    title: str,
    severity: str,
    first_seen_at: datetime,
    last_seen_at: datetime,
    properties: dict[str, Any] | None = None,
) -> NodeInput:
    node_key = make_node_key(NODE_TYPE_ALERT, str(alert_id))
    sev = normalize_severity(severity)
    from app.features.exposure.domain.constants import _SEVERITY_SCORE_MAP  # noqa: PLC0415
    risk_score = _SEVERITY_SCORE_MAP.get(sev, 50) if hasattr(
        __import__("app.features.exposure.domain.constants", fromlist=["_SEVERITY_SCORE_MAP"]),
        "_SEVERITY_SCORE_MAP",
    ) else 50
    return NodeInput(
        node_key=node_key,
        node_type=NODE_TYPE_ALERT,
        label=str(title)[:256],
        severity=sev,
        risk_score=clamp_score(risk_score),
        confidence=75,
        asset_key=asset_key,
        agent_id=agent_id,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
        properties=properties or {},
    )


def attack_chain_case_node(
    case_id: int,
    *,
    asset_key: str | None,
    agent_id: str | None,
    score: int,
    max_stage: str,
    first_seen_at: datetime,
    last_seen_at: datetime,
) -> NodeInput:
    node_key = make_node_key(NODE_TYPE_ATTACK_CHAIN_CASE, str(case_id))
    from app.features.exposure.domain.normalization import severity_from_score  # noqa: PLC0415
    return NodeInput(
        node_key=node_key,
        node_type=NODE_TYPE_ATTACK_CHAIN_CASE,
        label=f"Attack chain case {case_id} [{max_stage}]",
        severity=severity_from_score(score),
        risk_score=clamp_score(score),
        confidence=72,
        asset_key=asset_key,
        agent_id=agent_id,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
        properties={"max_stage": max_stage, "case_id": case_id},
    )


def asset_to_cve_edge(
    asset_node_key: str,
    cve_node_key: str,
    *,
    asset_key: str | None,
    agent_id: str | None,
    confidence: int,
    first_seen_at: datetime,
    last_seen_at: datetime,
) -> EdgeInput:
    edge_key = make_edge_key(asset_node_key, cve_node_key, EDGE_TYPE_HAS_CVE)
    return EdgeInput(
        edge_key=edge_key,
        source_node_key=asset_node_key,
        target_node_key=cve_node_key,
        edge_type=EDGE_TYPE_HAS_CVE,
        weight=1.0,
        confidence=clamp_confidence(confidence),
        asset_key=asset_key,
        agent_id=agent_id,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
    )


def asset_to_alert_edge(
    asset_node_key: str,
    alert_node_key: str,
    *,
    asset_key: str | None,
    agent_id: str | None,
    confidence: int,
    first_seen_at: datetime,
    last_seen_at: datetime,
) -> EdgeInput:
    edge_key = make_edge_key(asset_node_key, alert_node_key, EDGE_TYPE_TRIGGERED_ALERT)
    return EdgeInput(
        edge_key=edge_key,
        source_node_key=asset_node_key,
        target_node_key=alert_node_key,
        edge_type=EDGE_TYPE_TRIGGERED_ALERT,
        weight=1.0,
        confidence=clamp_confidence(confidence),
        asset_key=asset_key,
        agent_id=agent_id,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
    )


def asset_to_attack_chain_edge(
    asset_node_key: str,
    case_node_key: str,
    *,
    asset_key: str | None,
    agent_id: str | None,
    confidence: int,
    first_seen_at: datetime,
    last_seen_at: datetime,
) -> EdgeInput:
    edge_key = make_edge_key(asset_node_key, case_node_key, EDGE_TYPE_PART_OF_ATTACK_CHAIN)
    return EdgeInput(
        edge_key=edge_key,
        source_node_key=asset_node_key,
        target_node_key=case_node_key,
        edge_type=EDGE_TYPE_PART_OF_ATTACK_CHAIN,
        weight=1.5,
        confidence=clamp_confidence(confidence),
        asset_key=asset_key,
        agent_id=agent_id,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
    )
