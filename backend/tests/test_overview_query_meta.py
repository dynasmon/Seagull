from __future__ import annotations

import os

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.features.overview import service as overview_service


def test_overview_cache_hit_marks_query_meta(monkeypatch) -> None:
    cached_payload = {
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
    monkeypatch.setattr(overview_service, "_overview_cache_get", lambda _k: cached_payload)
    monkeypatch.setattr(overview_service, "_overview_cache_set", lambda *_args, **_kwargs: None)

    out = overview_service.get_overview(db=object(), window_minutes=60, agent_id=None, lite=True)
    assert out["query_meta"]["cache_hit"] is True


def test_overview_recomputes_when_cached_payload_has_no_query_meta(monkeypatch) -> None:
    monkeypatch.setattr(overview_service, "_overview_cache_get", lambda _k: {"meta": {}, "kpis": {}})
    monkeypatch.setattr(overview_service, "_overview_cache_set", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        overview_service,
        "get_overview_payload",
        lambda *_args, **_kwargs: {
            "query_meta": {
                "source": "rollup_1s",
                "fallback_chain": ["rollup_1s"],
                "degraded_reason": None,
                "source_freshness_seconds": 2,
                "query_latency_ms": 9.0,
                "cache_hit": False,
                "approximate": False,
                "query_window_start": "2026-04-06T09:00:00+00:00",
                "query_window_end": "2026-04-06T10:00:00+00:00",
            },
            "meta": {"sources": {}},
            "kpis": {},
        },
    )

    out = overview_service.get_overview(db=object(), window_minutes=30, agent_id=None, lite=True)
    assert out["query_meta"]["source"] == "rollup_1s"
    assert out["query_meta"]["cache_hit"] is False
