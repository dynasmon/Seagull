from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.core.cache import get_redis
from app.features.network_topology.schemas import (
    NetworkTopologyGraphPatchPayload,
    NetworkTopologyInvalidatePayload,
    NetworkTopologySummaryPatchPayload,
)
from app.features.realtime.service import publish_realtime

logger = logging.getLogger("seagull.network_topology.realtime")

NETWORK_TOPOLOGY_RECALC_REQUEST_KEY = "seagull:network_topology:recalc:request"
NETWORK_TOPOLOGY_RECALC_REQUEST_GATE_KEY = "seagull:network_topology:recalc:request:gate"
NETWORK_TOPOLOGY_INVALIDATE_GATE_KEY = "seagull:realtime:network_topology:invalidate:2s"
NETWORK_TOPOLOGY_SUMMARY_GATE_KEY = "seagull:realtime:network_topology:summary:2s"
NETWORK_TOPOLOGY_RECALC_REQUEST_TTL_SECONDS = 3600
NETWORK_TOPOLOGY_RECALC_DEBOUNCE_SECONDS = 10
NETWORK_TOPOLOGY_GRAPH_PATCH_MAX_NODES = 50
NETWORK_TOPOLOGY_GRAPH_PATCH_MAX_EDGES = 100
NETWORK_TOPOLOGY_GRAPH_PATCH_MAX_BYTES = 32 * 1024


def graph_nodes_hard_limit() -> int:
    return 2000


def graph_edges_hard_limit() -> int:
    return 3000


def _to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def _payload_dict(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json", exclude_none=True)
    return json.loads(model.json(exclude_none=True))


def _gate_once(*, key: str, ttl_s: int) -> bool:
    ttl = max(1, int(ttl_s))
    redis_client = get_redis()
    if redis_client is None:
        return True
    try:
        return bool(redis_client.set(str(key), "1", ex=ttl, nx=True))
    except Exception:
        return True


def request_recalculation(
    *,
    requested_at: datetime,
    requested_by: str,
    request_id: str | None = None,
    reason: str = "refresh",
    mode: str = "full",
    debounce_seconds: int = NETWORK_TOPOLOGY_RECALC_DEBOUNCE_SECONDS,
) -> bool:
    redis_client = get_redis()
    if redis_client is None:
        return False

    if debounce_seconds > 0:
        try:
            allowed = redis_client.set(
                NETWORK_TOPOLOGY_RECALC_REQUEST_GATE_KEY,
                "1",
                ex=max(1, int(debounce_seconds)),
                nx=True,
            )
            if not bool(allowed):
                return False
        except Exception:
            pass

    payload = {
        "requested_at": _to_iso(requested_at),
        "requested_by": str(requested_by or "").strip() or "unknown",
        "request_id": str(request_id or "").strip() or None,
        "reason": str(reason or "refresh").strip()[:64] or "refresh",
        "mode": str(mode or "full").strip()[:32] or "full",
    }
    try:
        redis_client.set(
            NETWORK_TOPOLOGY_RECALC_REQUEST_KEY,
            json.dumps(payload, separators=(",", ":"), ensure_ascii=True),
            ex=NETWORK_TOPOLOGY_RECALC_REQUEST_TTL_SECONDS,
        )
        return True
    except Exception:
        return False


def load_recalculation_request(request_key: str = NETWORK_TOPOLOGY_RECALC_REQUEST_KEY) -> dict[str, Any] | None:
    redis_client = get_redis()
    if redis_client is None:
        return None
    try:
        raw = redis_client.get(request_key)
    except Exception:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def publish_topology_invalidate(
    *,
    reason: str,
    source: str | None = None,
    agent_id: str | None = None,
    alert_id: int | None = None,
    batch_size: int | None = None,
    event_types: list[str] | None = None,
    degraded: bool = False,
    sampled: bool = False,
    high_priority: bool = False,
    projected_at: datetime | None = None,
    schedule_recalculation: bool = True,
) -> None:
    requested_at = datetime.now(timezone.utc)
    if schedule_recalculation:
        request_recalculation(
            requested_at=requested_at,
            requested_by=str(source or "realtime_trigger"),
            reason=reason,
            mode="full",
        )

    if not _gate_once(key=NETWORK_TOPOLOGY_INVALIDATE_GATE_KEY, ttl_s=2):
        return

    payload = NetworkTopologyInvalidatePayload(
        reason=str(reason or "refresh"),
        source=str(source).strip() if source else None,
        agent_id=str(agent_id).strip() if agent_id else None,
        alert_id=alert_id,
        batch_size=batch_size,
        event_types=[str(x or "").strip().lower() for x in (event_types or []) if str(x or "").strip()][:12],
        degraded=bool(degraded),
        sampled=bool(sampled),
        high_priority=bool(high_priority),
        requested_at=_to_iso(requested_at),
        projected_at=_to_iso(projected_at),
    )
    publish_realtime("ui.network_topology.invalidate", _payload_dict(payload))


def publish_summary_patch(
    *,
    generated_at: datetime,
    projected_at: datetime | None,
    total_nodes: int,
    total_edges: int,
    agent_count: int,
    subnet_count: int,
    external_ip_count: int,
    freshness_seconds: int | None,
    stale: bool,
    source_coverage: dict[str, Any],
    truncation: dict[str, Any],
) -> None:
    if not _gate_once(key=NETWORK_TOPOLOGY_SUMMARY_GATE_KEY, ttl_s=2):
        return
    payload = NetworkTopologySummaryPatchPayload(
        generated_at=_to_iso(generated_at) or "",
        projected_at=_to_iso(projected_at),
        total_nodes=max(0, int(total_nodes or 0)),
        total_edges=max(0, int(total_edges or 0)),
        agent_count=max(0, int(agent_count or 0)),
        subnet_count=max(0, int(subnet_count or 0)),
        external_ip_count=max(0, int(external_ip_count or 0)),
        freshness_seconds=freshness_seconds,
        stale=bool(stale),
        source_coverage=source_coverage if isinstance(source_coverage, dict) else {},
        truncation=truncation if isinstance(truncation, dict) else {},
    )
    publish_realtime("ui.network_topology.summary.patch", _payload_dict(payload))


def publish_graph_patch(
    *,
    generated_at: datetime,
    projected_at: datetime | None,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    graph_health: dict[str, Any],
) -> bool:
    if len(nodes) > NETWORK_TOPOLOGY_GRAPH_PATCH_MAX_NODES or len(edges) > NETWORK_TOPOLOGY_GRAPH_PATCH_MAX_EDGES:
        publish_topology_invalidate(
            reason="graph_patch_too_large",
            source="network_topology",
            schedule_recalculation=False,
        )
        return False

    payload = NetworkTopologyGraphPatchPayload(
        generated_at=_to_iso(generated_at) or "",
        projected_at=_to_iso(projected_at),
        nodes=nodes,
        edges=edges,
        graph_health=graph_health,
        requires_reconcile=False,
    )
    payload_dict = _payload_dict(payload)
    payload_bytes = len(
        json.dumps(payload_dict, ensure_ascii=True, separators=(",", ":"), default=str).encode("utf-8")
    )
    if payload_bytes > NETWORK_TOPOLOGY_GRAPH_PATCH_MAX_BYTES:
        publish_topology_invalidate(
            reason="graph_patch_too_large",
            source="network_topology",
            schedule_recalculation=False,
        )
        return False

    return publish_realtime("ui.network_topology.graph.patch", payload_dict)


def publish_topology_updated(*, projected_nodes: int, projected_edges: int) -> None:
    logger.debug(
        "topology_updated nodes=%d edges=%d",
        projected_nodes,
        projected_edges,
    )
