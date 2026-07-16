from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.events import service as events_service
from app.features.events.schemas import SshSummaryResponse


def _empty(since_minutes: int) -> SshSummaryResponse:
    return SshSummaryResponse(
        generated_at=datetime.now(timezone.utc),
        since_minutes=since_minutes,
        total_accepted=0,
        total_failed_password=0,
        total_invalid_user=0,
        total_actions=0,
        unique_source_ips=0,
        enriched_source_ips=0,
        recent_auth_events=[],
        successful_logins=[],
        failed_attempts=[],
        invalid_user_attempts=[],
        most_active_ips=[],
        root_logins=[],
        users_attempted=[],
        sudo_recent=[],
    )


def _nonempty(since_minutes: int) -> SshSummaryResponse:
    payload = _empty(since_minutes)
    payload.total_accepted = 5
    payload.total_actions = 5
    return payload


def _params(**overrides):
    base = {"since_minutes": 1440, "limit": 50, "agent_id": None, "widen_if_empty": True}
    base.update(overrides)
    return base


def test_ssh_summary_widens_to_retention_horizon_when_empty(monkeypatch):
    def fake_resolve(*, since_minutes, limit, agent_id):
        if since_minutes >= events_service._SSH_SUMMARY_MAX_SINCE_MINUTES:
            return _nonempty(since_minutes)
        return _empty(since_minutes)

    monkeypatch.setattr(events_service, "_resolve_ssh_summary_blocking", fake_resolve)

    out = asyncio.run(events_service._compute_ssh_summary(_params()))

    assert out["effective_since_minutes"] == events_service._SSH_SUMMARY_MAX_SINCE_MINUTES
    assert out["total_actions"] == 5


def test_ssh_summary_does_not_widen_when_flag_off(monkeypatch):
    def fake_resolve(*, since_minutes, limit, agent_id):
        if since_minutes >= events_service._SSH_SUMMARY_MAX_SINCE_MINUTES:
            return _nonempty(since_minutes)
        return _empty(since_minutes)

    monkeypatch.setattr(events_service, "_resolve_ssh_summary_blocking", fake_resolve)

    out = asyncio.run(events_service._compute_ssh_summary(_params(widen_if_empty=False)))

    assert out["effective_since_minutes"] is None
    assert out["total_actions"] == 0


def test_ssh_summary_does_not_widen_when_window_has_data(monkeypatch):
    monkeypatch.setattr(
        events_service,
        "_resolve_ssh_summary_blocking",
        lambda *, since_minutes, limit, agent_id: _nonempty(since_minutes),
    )

    out = asyncio.run(events_service._compute_ssh_summary(_params()))

    assert out["effective_since_minutes"] is None
    assert out["since_minutes"] == 1440


def test_ssh_summary_stays_empty_when_retention_horizon_is_empty(monkeypatch):
    monkeypatch.setattr(
        events_service,
        "_resolve_ssh_summary_blocking",
        lambda *, since_minutes, limit, agent_id: _empty(since_minutes),
    )

    out = asyncio.run(events_service._compute_ssh_summary(_params()))

    assert out["effective_since_minutes"] is None
    assert out["total_actions"] == 0


def test_ssh_summary_cache_key_varies_by_widen_flag():
    off = events_service._ssh_summary_cache_key(_params(widen_if_empty=False))
    on = events_service._ssh_summary_cache_key(_params(widen_if_empty=True))

    assert off != on
    assert on.endswith(":w=1")
    assert off.endswith(":w=0")
