from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import Request, Response

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.overview import api as overview_api
from app.features.overview import service as overview_service


def _get_request(headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": raw_headers})


def _overview_payload() -> dict:
    return {
        "query_meta": {
            "source": "rollup_1s",
            "fallback_chain": ["rollup_1s"],
            "degraded_reason": None,
            "source_freshness_seconds": 1,
            "query_latency_ms": 5.0,
            "cache_hit": False,
            "approximate": False,
            "query_window_start": "2026-04-06T09:00:00+00:00",
            "query_window_end": "2026-04-06T10:00:00+00:00",
        },
        "meta": {"sources": {}},
        "kpis": {},
    }


def test_get_overview_delegates_without_local_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []

    def _get_overview_payload(_db: Any, **kwargs: Any) -> dict:
        calls.append(kwargs)
        return _overview_payload()

    monkeypatch.setattr(overview_service, "get_overview_payload", _get_overview_payload)

    first = overview_service.get_overview(db=object(), window_minutes=60, agent_id=None, lite=True)
    second = overview_service.get_overview(db=object(), window_minutes=60, agent_id=None, lite=True)

    assert first["query_meta"]["source"] == "rollup_1s"
    assert second["query_meta"]["source"] == "rollup_1s"
    assert len(calls) == 2


def test_overview_swr_hit_marks_query_meta(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _serve_read_model(_model: Any, _params: dict) -> tuple[dict, str, str]:
        return _overview_payload(), 'W/"1-overview"', "fresh"

    monkeypatch.setattr(overview_service, "serve_read_model", _serve_read_model)

    payload, etag, outcome = asyncio.run(
        overview_service.get_overview_async(window_minutes=60, agent_id=None, lite=True)
    )

    assert etag == 'W/"1-overview"'
    assert outcome == "fresh"
    assert payload["meta"]["cache_hit"] is True
    assert payload["query_meta"]["cache_hit"] is True
    assert payload["query_meta"]["query_latency_ms"] == payload["meta"]["query_latency_ms"]


def test_overview_handler_sets_cache_headers_and_metric(monkeypatch: pytest.MonkeyPatch) -> None:
    metric_calls: list[tuple[str, dict]] = []

    async def _get_overview_async(**_kwargs: Any) -> tuple[dict, str, str]:
        return _overview_payload(), 'W/"1-overview"', "stale"

    monkeypatch.setattr(overview_api, "get_overview_async", _get_overview_async)
    monkeypatch.setattr(overview_api, "incr_counter", lambda name, **labels: metric_calls.append((name, labels)))
    response = Response()

    payload = asyncio.run(
        overview_api.get_overview_endpoint(
            request=_get_request(),
            response=response,
            window_minutes=60,
            start_ts=None,
            end_ts=None,
            agent_id=None,
            lite=True,
        )
    )

    assert payload["query_meta"]["source"] == "rollup_1s"
    assert response.headers["ETag"] == 'W/"1-overview"'
    assert response.headers["X-Cache-Outcome"] == "stale"
    assert metric_calls == [
        ("api_cache_outcome_total", {"route": "/overview", "outcome": "stale"})
    ]


def test_overview_snapshot_outdated_detects_resumed_traffic(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(overview_service, "read_overview_live_last_ts", lambda: now)
    frozen = {"meta": {"window_end": (now - timedelta(minutes=10)).isoformat()}}

    assert overview_service._overview_snapshot_outdated(frozen, {"agent_id": None}) is True
    assert overview_service._overview_snapshot_outdated(frozen, {"agent_id": "a1"}) is False

    recent = {"meta": {"window_end": (now - timedelta(seconds=20)).isoformat()}}
    assert overview_service._overview_snapshot_outdated(recent, {"agent_id": None}) is False


def test_overview_snapshot_outdated_defaults_to_serving_the_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(overview_service, "read_overview_live_last_ts", lambda: None)
    frozen = {"meta": {"window_end": "2026-01-01T00:00:00+00:00"}}
    assert overview_service._overview_snapshot_outdated(frozen, {"agent_id": None}) is False

    monkeypatch.setattr(
        overview_service, "read_overview_live_last_ts", lambda: datetime.now(timezone.utc)
    )
    assert overview_service._overview_snapshot_outdated({"meta": {}}, {"agent_id": None}) is False
    assert (
        overview_service._overview_snapshot_outdated({"meta": {"window_end": "junk"}}, {"agent_id": None})
        is False
    )


def test_overview_handler_returns_304_on_matching_etag(monkeypatch: pytest.MonkeyPatch) -> None:
    metric_calls: list[tuple[str, dict]] = []

    async def _get_overview_async(**_kwargs: Any) -> tuple[dict, str, str]:
        return _overview_payload(), 'W/"1-overview"', "fresh"

    monkeypatch.setattr(overview_api, "get_overview_async", _get_overview_async)
    monkeypatch.setattr(overview_api, "incr_counter", lambda name, **labels: metric_calls.append((name, labels)))
    response = Response()

    result = asyncio.run(
        overview_api.get_overview_endpoint(
            request=_get_request({"If-None-Match": 'W/"1-overview"'}),
            response=response,
            window_minutes=60,
            start_ts=None,
            end_ts=None,
            agent_id=None,
            lite=True,
        )
    )

    assert isinstance(result, Response)
    assert result.status_code == 304
    assert result.body == b""
    assert result.headers["ETag"] == 'W/"1-overview"'
    assert result.headers["X-Cache-Outcome"] == "fresh"
    assert ("api_304_total", {"route": "/overview"}) in metric_calls
