from __future__ import annotations

import os
from datetime import datetime, timedelta
from types import SimpleNamespace

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

from app.features.agents import service as agents_service


def test_revoke_active_credentials_does_not_extend_existing_overlap(monkeypatch) -> None:
    now = datetime.utcnow()
    existing_overlap = now + timedelta(seconds=30)
    new_overlap = now + timedelta(minutes=5)
    rows = [
        SimpleNamespace(revoked_at=existing_overlap, rotated_at=None, revoked_reason=None),
        SimpleNamespace(revoked_at=None, rotated_at=None, revoked_reason=None),
    ]
    saved = []

    monkeypatch.setattr(agents_service.repository, "list_active_credentials", lambda db, agent_id: rows)
    monkeypatch.setattr(agents_service.repository, "save_credential", lambda db, row: saved.append(row) or row)

    agents_service._revoke_active_credentials(
        object(),
        "agent-1",
        "rotated",
        rotated_at=now,
        overlap_until=new_overlap,
    )

    assert rows[0].revoked_at == existing_overlap
    assert rows[1].revoked_at == new_overlap
    assert rows[0].rotated_at == now
    assert rows[1].rotated_at == now
    assert rows[0].revoked_reason == "rotated"
    assert rows[1].revoked_reason == "rotated"
    assert saved == rows
