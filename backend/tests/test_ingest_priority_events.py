from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.ingest import api as ingest_api


def test_hot_priority_event_matches_security_critical_events() -> None:
    assert ingest_api._is_hot_priority_event("dos_attack") is True
    assert ingest_api._is_hot_priority_event(" DOS_ATTACK ") is True
    assert ingest_api._is_hot_priority_event("ssh_auth") is True
    assert ingest_api._is_hot_priority_event(" SSH_AUTH ") is True


def test_hot_priority_event_ignores_other_event_types() -> None:
    assert ingest_api._is_hot_priority_event("flow") is False
    assert ingest_api._is_hot_priority_event(None) is False
