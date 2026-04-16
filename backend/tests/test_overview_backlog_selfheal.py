from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.overview import repository as ov


def test_best_effort_ingest_backlog_prefers_self_healed_source(monkeypatch) -> None:
    monkeypatch.setattr(ov, "ingest_get_backlog", lambda: (7, 123))
    assert ov._best_effort_ingest_backlog() == (123, 7)
