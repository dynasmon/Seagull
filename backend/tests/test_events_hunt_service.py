from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.features.events import service
from app.features.events.schemas import NetEventDB


def _evt(event_id: int = 101) -> NetEventDB:
    return NetEventDB(
        id=int(event_id),
        agent_id="agent-a",
        event_type="ssh_auth",
        schema_version=1,
        timestamp=datetime.now(timezone.utc),
        src_ip="203.0.113.8",
        dst_ip="192.0.2.10",
        src_port=54000,
        dst_port=22,
        proto="tcp",
        bytes=100,
        extra={"action": "failed_password"},
    )


def test_select_hunt_chain_prefers_elasticsearch_for_search() -> None:
    assert service._select_hunt_chain(has_search=True, window_minutes=60) == ["elasticsearch", "postgres"]


def test_select_hunt_chain_prefers_clickhouse_for_wide_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service.settings, "NETWATCH_EVENTS_HUNT_CLICKHOUSE_MINUTES", 90, raising=False)
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    assert service._select_hunt_chain(has_search=False, window_minutes=120) == ["clickhouse", "postgres", "elasticsearch"]


def test_hunt_events_falls_back_to_postgres_when_es_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(501)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(service, "_pg_hunt_query", lambda *_args, **_kwargs: ([sample], None, False))

    out = service.hunt_events(
        db=object(),
        page_size=50,
        cursor=None,
        agent_id="agent-a",
        event_type="ssh_auth",
        since_minutes=120,
        search="failed_password",
    )

    assert out.items and out.items[0].id == 501
    assert out.meta.source == "postgres"
    assert out.meta.fallback_chain[:2] == ["elasticsearch", "postgres"]
    assert out.meta.degraded_reason is not None
    assert out.meta.query_window_start is not None
    assert out.meta.query_window_end is not None


def test_hunt_events_uses_elasticsearch_for_search_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(777)
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(
        service,
        "_es_hunt_query",
        lambda **_kwargs: ([sample], None, False),
    )
    monkeypatch.setattr(service, "_pg_has_newer_event", lambda *_args, **_kwargs: False)

    out = service.hunt_events(
        db=object(),
        page_size=25,
        cursor=None,
        agent_id=None,
        event_type=None,
        since_minutes=60,
        search="203.0.113.8",
    )

    assert out.meta.source == "elasticsearch"
    assert out.meta.fallback_chain == ["elasticsearch"]
    assert out.meta.degraded_reason is None


def test_hunt_events_falls_back_from_clickhouse_to_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(902)
    monkeypatch.setattr(service.settings, "NETWATCH_EVENTS_HUNT_CLICKHOUSE_MINUTES", 30, raising=False)
    monkeypatch.setattr(service, "_ch_client_or_none", lambda: None)
    monkeypatch.setattr(service, "_pg_hunt_query", lambda *_args, **_kwargs: ([sample], None, False))

    out = service.hunt_events(
        db=object(),
        page_size=30,
        cursor=None,
        agent_id=None,
        event_type=None,
        since_minutes=120,
    )

    assert out.meta.source == "postgres"
    assert out.meta.fallback_chain[:2] == ["clickhouse", "postgres"]
    assert out.meta.degraded_reason is not None


def test_hunt_events_falls_back_to_elasticsearch_after_pg_and_clickhouse_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _evt(903)
    monkeypatch.setattr(service.settings, "NETWATCH_EVENTS_HUNT_CLICKHOUSE_MINUTES", 30, raising=False)
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "_ch_client_or_none", lambda: object())
    monkeypatch.setattr(
        service,
        "_ch_hunt_query",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("ch_down")),
    )
    monkeypatch.setattr(
        service,
        "_pg_hunt_query",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("pg_down")),
    )
    monkeypatch.setattr(service, "_es_client_or_none", lambda: object())
    monkeypatch.setattr(service, "_es_hunt_query", lambda **_kwargs: ([sample], None, False))
    monkeypatch.setattr(service, "_pg_has_newer_event", lambda *_args, **_kwargs: False)

    out = service.hunt_events(
        db=object(),
        page_size=30,
        cursor=None,
        agent_id=None,
        event_type=None,
        since_minutes=120,
    )

    assert out.meta.source == "elasticsearch"
    assert out.meta.fallback_chain == ["clickhouse", "postgres", "elasticsearch"]
    assert out.meta.degraded_reason is not None


def test_hunt_events_rejects_invalid_time_range() -> None:
    with pytest.raises(HTTPException) as exc:
        service.hunt_events(
            db=object(),
            page_size=10,
            start_ts_iso="2026-04-06T10:00:00Z",
            end_ts_iso="2026-04-06T09:00:00Z",
        )
    assert exc.value.status_code == 422


def test_hunt_events_rejects_blank_search() -> None:
    with pytest.raises(HTTPException) as exc:
        service.hunt_events(
            db=object(),
            page_size=10,
            search="   ",
        )
    assert exc.value.status_code == 422


def test_hunt_events_returns_503_when_all_candidates_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "_es_client_or_none", lambda: None)
    monkeypatch.setattr(service, "_pg_hunt_query", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("pg_down")))

    with pytest.raises(HTTPException) as exc:
        service.hunt_events(
            db=object(),
            page_size=10,
            search="needle",
            since_minutes=30,
        )
    assert exc.value.status_code == 503
