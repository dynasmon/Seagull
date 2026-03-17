from __future__ import annotations

import os

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core import ingest_control


class _FakeRedis:
    def __init__(self) -> None:
        self.data = {
            "netwatch:ingest:storm_active": "1",
            "netwatch:ingest:pressure_state": "x",
            "netwatch:overview:v2:a": "1",
            "netwatch:events:key": "1",
            "netwatch:inventory:overview:v2": "1",
            "other": "1",
        }

    def delete(self, *keys):
        n = 0
        for k in keys:
            if k in self.data:
                del self.data[k]
                n += 1
        return n

    def scan_iter(self, match: str, count: int = 256):
        # very small glob emulation for our prefix patterns
        if match.endswith("*"):
            pref = match[:-1]
            for k in list(self.data.keys()):
                if str(k).startswith(pref):
                    yield k


def test_recover_runtime_state_clears_pressure_and_cache_keys(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(ingest_control, "get_redis", lambda: fake)

    out = ingest_control.recover_runtime_state(clear_backlog_counters=False, clear_ui_caches=True)

    assert out["ok"] is True
    assert "netwatch:ingest:storm_active" not in fake.data
    assert "netwatch:ingest:pressure_state" not in fake.data
    assert "netwatch:overview:v2:a" not in fake.data
    assert "netwatch:events:key" not in fake.data
    assert "netwatch:inventory:overview:v2" not in fake.data
    assert "other" in fake.data
