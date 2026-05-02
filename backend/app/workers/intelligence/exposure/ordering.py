from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.features.exposure.domain.recommendations import generate_recommendations


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _dt_key(dt: datetime | None) -> float:
    safe = _as_utc(dt) or datetime.min.replace(tzinfo=timezone.utc)
    return safe.timestamp()


def _order_nodes(nodes: list[Any], *, limit: int) -> list[Any]:
    by_key = {node.node_key: node for node in nodes}
    ordered = sorted(
        by_key.values(),
        key=lambda row: (row.risk_score, row.confidence, _dt_key(row.last_seen_at)),
        reverse=True,
    )
    return ordered[:limit]


def _order_edges(edges: list[Any], *, keep_node_keys: set[str], asset_node_key: str, limit: int) -> list[Any]:
    allowed_keys = set(keep_node_keys)
    allowed_keys.add(asset_node_key)
    by_key = {edge.edge_key: edge for edge in edges}
    ordered = [
        edge for edge in sorted(
            by_key.values(),
            key=lambda row: (row.confidence, row.weight, _dt_key(row.last_seen_at)),
            reverse=True,
        )
        if edge.source_node_key in allowed_keys and edge.target_node_key in allowed_keys
    ]
    return ordered[:limit]


def _prepare_findings(findings: list[Any], *, limit: int) -> list[Any]:
    deduped: dict[str, Any] = {}
    for finding in findings:
        finding.recommendations = [
            rec.to_dict()
            for rec in generate_recommendations(
                finding.reason_codes,
                evidence_refs=[ref.to_dict() for ref in finding.evidence_refs],
            )
        ]
        deduped[finding.finding_key] = finding
    ordered = sorted(
        deduped.values(),
        key=lambda row: (row.score_delta, row.confidence, _dt_key(row.last_seen_at)),
        reverse=True,
    )
    return ordered[:limit]
