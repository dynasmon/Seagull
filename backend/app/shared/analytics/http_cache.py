from __future__ import annotations

from collections.abc import Mapping
from typing import Awaitable, Callable

from fastapi import Request, Response

from app.shared.analytics.read_model import get_read_model

SWR_ROUTE_READ_MODELS: dict[str, str] = {
    "/overview": "overview",
    "/alerts/recent": "alerts_recent",
    "/events/network/summary": "protocol_intel",
    "/events/ssh/summary": "ssh_summary",
    "/exposure/summary": "exposure_summary",
    "/exposure/paths": "exposure_paths",
    "/network-topology/summary": "network_topology_summary",
    "/network-topology/graph": "network_topology_graph",
    "/vuln/summary": "vuln_summary",
    "/vuln/posture": "vuln_posture",
}


def swr_cache_control(route_path: str | None, query_params: Mapping[str, str] | None = None) -> str | None:
    if not route_path:
        return None
    model_name = SWR_ROUTE_READ_MODELS.get(route_path)
    if route_path == "/overview" and query_params:
        if query_params.get("start_ts") and query_params.get("end_ts"):
            model_name = "overview_fixed_range"
    if not model_name:
        return None
    model = get_read_model(model_name)
    if model is None:
        return None
    fresh_s = max(0, int(model.fresh_s))
    stale_s = max(0, int(model.stale_s))
    return f"private, max-age={fresh_s}, stale-while-revalidate={stale_s}"


async def swr_cache_control_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    response = await call_next(request)
    if request.method not in ("GET", "HEAD"):
        return response
    if response.status_code not in (200, 304):
        return response
    route = request.scope.get("route")
    value = swr_cache_control(getattr(route, "path_format", None), request.query_params)
    if value:
        response.headers.setdefault("Cache-Control", value)
    return response
