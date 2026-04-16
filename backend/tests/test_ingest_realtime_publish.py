from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.ingest import service


def test_build_overview_patch_payload_contract() -> None:
    payload = service._build_overview_patch_payload(
        received=37,
        backlog_events=1200,
        backlog_messages=14,
        protection_active=True,
        phase="storm",
        reason="batch_threshold",
    )

    assert payload == {
        "events_5m_delta": 37,
        "backlog_events": 1200,
        "backlog_messages": 14,
        "protection_active": True,
        "phase": "storm",
        "reason": "batch_threshold",
    }


def test_publish_overview_realtime_emits_patch_invalidate_and_storm(monkeypatch) -> None:
    emitted: list[tuple[str, dict]] = []

    monkeypatch.setattr(service, "_realtime_gate_once", lambda **kwargs: True)
    monkeypatch.setattr(service, "get_storm_status", lambda: {"active": True, "phase": "storm", "eps": 9000})
    monkeypatch.setattr(service, "publish_realtime", lambda event_type, payload: emitted.append((event_type, payload)))

    service._publish_overview_realtime(
        received=80,
        backlog_events=64000,
        backlog_messages=23,
        protection_active=True,
        phase="storm",
        reason="soft_backlog",
    )

    assert [t for t, _ in emitted] == ["ui.overview.kpi.patch", "ui.overview.invalidate", "ui.overview.storm.patch"]
    assert emitted[0][1]["events_5m_delta"] == 80
    assert emitted[1][1]["reason"] == "ingest_update"
    assert emitted[2][1]["phase"] == "storm"


def test_publish_overview_realtime_respects_gate(monkeypatch) -> None:
    emitted: list[tuple[str, dict]] = []
    gate_answers = iter([True, False, False])

    monkeypatch.setattr(service, "_realtime_gate_once", lambda **kwargs: next(gate_answers))
    monkeypatch.setattr(service, "get_storm_status", lambda: {"active": True})
    monkeypatch.setattr(service, "publish_realtime", lambda event_type, payload: emitted.append((event_type, payload)))

    service._publish_overview_realtime(
        received=5,
        backlog_events=0,
        backlog_messages=0,
        protection_active=False,
        phase="ok",
        reason="ok",
    )

    assert [t for t, _ in emitted] == ["ui.overview.kpi.patch"]
