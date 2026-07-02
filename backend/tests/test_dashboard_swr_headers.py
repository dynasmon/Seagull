from __future__ import annotations

import asyncio
import os
from typing import Any

import pytest
from fastapi import Request, Response

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.core.api.conditional import matches_if_none_match, maybe_not_modified
from app.features.alerts import api as alerts_api
from app.features.exposure import api as exposure_api
from app.features.network_topology import api as topology_api
from app.features.vuln import api as vuln_api


def _get_request(headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": raw_headers})


def test_matches_if_none_match_variants() -> None:
    assert matches_if_none_match('W/"1-abc"', 'W/"1-abc"') is True
    assert matches_if_none_match('"1-abc"', 'W/"1-abc"') is True
    assert matches_if_none_match('W/"1-x", W/"1-abc"', 'W/"1-abc"') is True
    assert matches_if_none_match("*", 'W/"1-abc"') is True
    assert matches_if_none_match('W/"1-zzz"', 'W/"1-abc"') is False
    assert matches_if_none_match(None, 'W/"1-abc"') is False
    assert matches_if_none_match('W/"1-abc"', "") is False


def test_maybe_not_modified_sets_headers_and_returns_none_on_mismatch() -> None:
    response = Response()

    result = maybe_not_modified(response, 'W/"1-old"', 'W/"1-new"', outcome="fresh")

    assert result is None
    assert response.headers["ETag"] == 'W/"1-new"'
    assert response.headers["X-Cache-Outcome"] == "fresh"


def test_maybe_not_modified_skips_empty_etag() -> None:
    response = Response()

    result = maybe_not_modified(response, 'W/"1-any"', "", outcome="bypass")

    assert result is None
    assert "ETag" not in response.headers


def test_maybe_not_modified_returns_304_on_match() -> None:
    response = Response()

    result = maybe_not_modified(response, 'W/"1-same"', 'W/"1-same"', outcome="stale")

    assert result is not None
    assert result.status_code == 304
    assert result.body == b""
    assert result.headers["ETag"] == 'W/"1-same"'
    assert result.headers["X-Cache-Outcome"] == "stale"


def test_exposure_summary_sets_cache_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get_summary_async() -> tuple[dict, str, str]:
        return {}, 'W/"1-exposure-summary"', "fresh"

    monkeypatch.setattr(exposure_api.service, "get_exposure_summary_async", _get_summary_async)
    monkeypatch.setattr(exposure_api, "incr_counter", lambda *_args, **_kwargs: None)
    response = Response()

    asyncio.run(exposure_api.get_summary(request=_get_request(), response=response))

    assert response.headers["ETag"] == 'W/"1-exposure-summary"'
    assert response.headers["X-Cache-Outcome"] == "fresh"


def test_exposure_summary_returns_304_when_etag_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    metric_calls: list[tuple[str, dict]] = []

    async def _get_summary_async() -> tuple[dict, str, str]:
        return {}, 'W/"1-exposure-summary"', "fresh"

    monkeypatch.setattr(exposure_api.service, "get_exposure_summary_async", _get_summary_async)
    monkeypatch.setattr(exposure_api, "incr_counter", lambda name, **labels: metric_calls.append((name, labels)))
    response = Response()

    result = asyncio.run(
        exposure_api.get_summary(
            request=_get_request({"If-None-Match": 'W/"1-exposure-summary"'}),
            response=response,
        )
    )

    assert isinstance(result, Response)
    assert result.status_code == 304
    assert result.body == b""
    assert result.headers["ETag"] == 'W/"1-exposure-summary"'
    assert ("api_304_total", {"route": "/exposure/summary"}) in metric_calls
    assert ("api_cache_outcome_total", {"route": "/exposure/summary", "outcome": "fresh"}) in metric_calls


def test_exposure_summary_mismatched_etag_returns_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get_summary_async() -> tuple[dict, str, str]:
        return {"total_assets": 3}, 'W/"1-exposure-summary"', "fresh"

    monkeypatch.setattr(exposure_api.service, "get_exposure_summary_async", _get_summary_async)
    monkeypatch.setattr(exposure_api, "incr_counter", lambda *_args, **_kwargs: None)
    response = Response()

    result = asyncio.run(
        exposure_api.get_summary(
            request=_get_request({"If-None-Match": 'W/"1-stale"'}),
            response=response,
        )
    )

    assert result == {"total_assets": 3}
    assert response.headers["ETag"] == 'W/"1-exposure-summary"'


def test_exposure_paths_sets_cache_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _list_paths_async(*, params: Any) -> tuple[dict, str, str]:
        return {"items": [], "next_cursor": None, "has_more": False}, 'W/"1-exposure-paths"', "stale"

    monkeypatch.setattr(exposure_api.service, "list_paths_async", _list_paths_async)
    monkeypatch.setattr(exposure_api, "incr_counter", lambda *_args, **_kwargs: None)
    response = Response()

    asyncio.run(
        exposure_api.list_paths(
            request=_get_request(),
            response=response,
            page_size=25,
            cursor=None,
            severity=None,
            agent_id=None,
            min_score=None,
            reason_code=None,
        )
    )

    assert response.headers["ETag"] == 'W/"1-exposure-paths"'
    assert response.headers["X-Cache-Outcome"] == "stale"


def test_topology_summary_sets_cache_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get_summary_async() -> tuple[dict, str, str]:
        return {}, 'W/"1-topology-summary"', "miss"

    monkeypatch.setattr(topology_api.service, "get_summary_async", _get_summary_async)
    monkeypatch.setattr(topology_api, "incr_counter", lambda *_args, **_kwargs: None)
    response = Response()

    asyncio.run(topology_api.get_summary(request=_get_request(), response=response))

    assert response.headers["ETag"] == 'W/"1-topology-summary"'
    assert response.headers["X-Cache-Outcome"] == "miss"


def test_vuln_summary_sets_cache_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get_summary_async(**_kwargs: Any) -> tuple[dict, str, str]:
        return {}, 'W/"1-vuln-summary"', "fresh"

    monkeypatch.setattr(vuln_api, "get_vuln_summary_async", _get_summary_async)
    monkeypatch.setattr(vuln_api, "incr_counter", lambda *_args, **_kwargs: None)
    response = Response()

    asyncio.run(
        vuln_api.summary_endpoint(
            request=_get_request(),
            response=response,
            active_within_days=30,
            include_suppressed=False,
        )
    )

    assert response.headers["ETag"] == 'W/"1-vuln-summary"'
    assert response.headers["X-Cache-Outcome"] == "fresh"


def test_vuln_posture_sets_cache_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get_posture_async(**_kwargs: Any) -> tuple[dict, str, str]:
        return {}, 'W/"1-vuln-posture"', "stale"

    monkeypatch.setattr(vuln_api, "get_vuln_posture_async", _get_posture_async)
    monkeypatch.setattr(vuln_api, "incr_counter", lambda *_args, **_kwargs: None)
    response = Response()

    asyncio.run(
        vuln_api.posture_endpoint(
            request=_get_request(),
            response=response,
            active_within_days=30,
            include_suppressed=False,
            top_n=15,
        )
    )

    assert response.headers["ETag"] == 'W/"1-vuln-posture"'
    assert response.headers["X-Cache-Outcome"] == "stale"


def test_recent_alerts_sets_cache_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get_recent_alerts_async(*, limit: int) -> tuple[list[dict[str, Any]], str, str]:
        return [], 'W/"1-alerts-recent"', "fresh"

    monkeypatch.setattr(alerts_api, "get_recent_alerts_async", _get_recent_alerts_async)
    monkeypatch.setattr(alerts_api, "incr_counter", lambda *_args, **_kwargs: None)
    response = Response()

    asyncio.run(alerts_api.get_recent_alerts_endpoint(request=_get_request(), response=response, limit=50))

    assert response.headers["ETag"] == 'W/"1-alerts-recent"'
    assert response.headers["X-Cache-Outcome"] == "fresh"


def test_recent_alerts_returns_304_when_etag_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    metric_calls: list[tuple[str, dict]] = []

    async def _get_recent_alerts_async(*, limit: int) -> tuple[list[dict[str, Any]], str, str]:
        return [], 'W/"1-alerts-recent"', "stale"

    monkeypatch.setattr(alerts_api, "get_recent_alerts_async", _get_recent_alerts_async)
    monkeypatch.setattr(alerts_api, "incr_counter", lambda name, **labels: metric_calls.append((name, labels)))
    response = Response()

    result = asyncio.run(
        alerts_api.get_recent_alerts_endpoint(
            request=_get_request({"If-None-Match": 'W/"1-alerts-recent"'}),
            response=response,
            limit=50,
        )
    )

    assert isinstance(result, Response)
    assert result.status_code == 304
    assert ("api_304_total", {"route": "/alerts/recent"}) in metric_calls
