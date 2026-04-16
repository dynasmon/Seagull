from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.admin import service


class _FakeRedis:
    def ping(self) -> bool:
        return True


class _FakeEs:
    def ping(self) -> bool:
        return True


class _FakeCh:
    class _Result:
        first_row = (1,)

    def query(self, _sql: str):
        return self._Result()


def _stub_repo(monkeypatch):
    monkeypatch.setattr(service.repository, "probe_database", lambda _db: None)
    monkeypatch.setattr(service.repository, "count_total_agents", lambda _db: 12)
    monkeypatch.setattr(service.repository, "count_online_agents", lambda _db, online_cutoff: 8)
    monkeypatch.setattr(service.repository, "count_revoked_agents", lambda _db: 1)
    monkeypatch.setattr(service.repository, "inventory_status_counts", lambda _db, inventory_stale_cutoff: (2, 3, 7))


def test_admin_system_status_includes_clickhouse_ok(monkeypatch) -> None:
    _stub_repo(monkeypatch)
    monkeypatch.setattr(service, "get_redis", lambda: _FakeRedis())
    monkeypatch.setattr(service, "get_es_client", lambda: _FakeEs())
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "get_storm_status", lambda: {"active": False, "phase": "ok", "reason": "ok"})
    monkeypatch.setattr(service, "snapshot_metrics", lambda: {"counters": [], "histograms": []})
    monkeypatch.setattr(service, "clickhouse_is_enabled", lambda: True)
    monkeypatch.setattr(service, "clickhouse_is_available", lambda: True)
    monkeypatch.setattr(service, "get_clickhouse_client", lambda: _FakeCh())

    out = service.admin_system_status(db=object())

    ch = out["components"]["clickhouse"]
    assert ch["enabled"] is True
    assert ch["available"] is True
    assert ch["status"] == "ok"
    assert ch["error"] is None


def test_admin_system_status_marks_clickhouse_degraded_when_disabled(monkeypatch) -> None:
    _stub_repo(monkeypatch)
    monkeypatch.setattr(service, "get_redis", lambda: _FakeRedis())
    monkeypatch.setattr(service, "get_es_client", lambda: _FakeEs())
    monkeypatch.setattr(service, "search_backend_mode", lambda: "auto")
    monkeypatch.setattr(service, "get_storm_status", lambda: {"active": False, "phase": "ok", "reason": "ok"})
    monkeypatch.setattr(service, "snapshot_metrics", lambda: {"counters": [], "histograms": []})
    monkeypatch.setattr(service, "clickhouse_is_enabled", lambda: False)

    out = service.admin_system_status(db=object())

    ch = out["components"]["clickhouse"]
    assert ch["enabled"] is False
    assert ch["available"] is False
    assert ch["status"] == "degraded"
