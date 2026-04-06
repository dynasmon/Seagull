from __future__ import annotations

import os
from datetime import datetime, timezone

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.features.events import api as events_api
from app.features.events.schemas import EventHuntResponse, NetEventDB, QueryProvenanceMeta


def _sample_event() -> NetEventDB:
    return NetEventDB(
        id=11,
        agent_id="agent-a",
        event_type="ssh_auth",
        schema_version=1,
        timestamp=datetime.now(timezone.utc),
        src_ip="203.0.113.10",
        dst_ip="192.0.2.20",
        src_port=50111,
        dst_port=22,
        proto="tcp",
        bytes=10,
        extra={"action": "failed_password"},
    )


def test_recent_endpoint_routes_search_to_hunt(monkeypatch) -> None:
    captured: dict[str, object] = {}
    sample = _sample_event()

    def _fake_hunt(db, **kwargs):
        captured["db"] = db
        captured.update(kwargs)
        return EventHuntResponse(
            items=[sample],
            next_cursor=None,
            has_more=False,
            meta=QueryProvenanceMeta(
                source="elasticsearch",
                fallback_chain=["elasticsearch"],
                degraded_reason=None,
                source_freshness_seconds=1,
                query_latency_ms=4.2,
                cache_hit=False,
                approximate=False,
                query_window_start=datetime.now(timezone.utc),
                query_window_end=datetime.now(timezone.utc),
            ),
        )

    monkeypatch.setattr(events_api, "hunt_events", _fake_hunt)
    monkeypatch.setattr(events_api, "get_recent_events", lambda *_args, **_kwargs: [])

    out = events_api.get_recent_events_endpoint(
        limit=15,
        agent_id="agent-a",
        event_type="ssh_auth",
        search="failed_password",
        since_minutes=45,
        window_minutes=None,
        db=object(),
    )

    assert len(out) == 1
    assert out[0].id == 11
    assert captured["page_size"] == 15
    assert captured["since_minutes"] == 45
    assert captured["search"] == "failed_password"


def test_recent_endpoint_uses_window_minutes_alias_for_search(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_hunt(_db, **kwargs):
        captured.update(kwargs)
        return EventHuntResponse(
            items=[],
            next_cursor=None,
            has_more=False,
            meta=QueryProvenanceMeta(
                source="postgres",
                fallback_chain=["postgres"],
                degraded_reason=None,
                source_freshness_seconds=None,
                query_latency_ms=1.0,
                cache_hit=False,
                approximate=False,
                query_window_start=None,
                query_window_end=None,
            ),
        )

    monkeypatch.setattr(events_api, "hunt_events", _fake_hunt)
    monkeypatch.setattr(events_api, "get_recent_events", lambda *_args, **_kwargs: [])

    events_api.get_recent_events_endpoint(
        limit=20,
        agent_id=None,
        event_type=None,
        search="203.0.113.10",
        since_minutes=None,
        window_minutes=30,
        db=object(),
    )

    assert captured["since_minutes"] == 30

