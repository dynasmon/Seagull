from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List


def _search_tokens(search: str | None) -> list[str]:
    if not search:
        return []
    raw = str(search).strip()
    if not raw:
        return []
    return [tok for tok in raw.split() if tok][:8]


def _es_base_filters(
    *,
    since: datetime | None = None,
    agent_id: str | None = None,
    event_type: str | None = None,
) -> List[Dict[str, Any]]:
    filters: List[Dict[str, Any]] = []

    if since is not None:
        filters.append({"range": {"timestamp": {"gte": since.isoformat()}}})

    if agent_id:
        filters.append({"term": {"agent_id": agent_id}})

    if event_type:
        filters.append({"term": {"event_type": event_type}})

    return filters


def _ch_where(
    *,
    since: datetime | None = None,
    agent_id: str | None = None,
    event_type: str | None = None,
) -> tuple[str, Dict[str, Any]]:
    conds = ["1=1"]
    params: Dict[str, Any] = {}
    if since is not None:
        conds.append("timestamp >= {since:DateTime64(3)}")
        params["since"] = since
    if agent_id:
        conds.append("agent_id = {agent_id:String}")
        params["agent_id"] = agent_id
    if event_type:
        conds.append("event_type = {event_type:String}")
        params["event_type"] = event_type
    return " AND ".join(conds), params
