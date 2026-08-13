from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

import pytest

from app.core.config import settings
from app.core.security import rate_limit as rl


class _FakeRedis:
    def __init__(self, *, fail_after: int | None = None):
        self.values: dict[str, int] = {}
        self.ttls: dict[str, int] = {}
        self.calls = 0
        self.fail_after = fail_after

    def eval(self, script, numkeys, key, *args):
        self.calls += 1
        if self.fail_after is not None and self.calls > self.fail_after:
            raise RuntimeError("redis is down")
        hits = self.values.get(key, 0) + 1
        self.values[key] = hits
        ttl = self.ttls.get(key, -1)
        if ttl < 0:
            ttl = int(args[0])
            self.ttls[key] = ttl
        return [hits, ttl]


@pytest.fixture(autouse=True)
def isolated_limiter(monkeypatch: pytest.MonkeyPatch):
    rl._local_windows.clear()
    monkeypatch.setattr(settings, "SEAGULL_RATE_LIMIT_DEGRADED_POLICY", "local")
    monkeypatch.setattr(settings, "SEAGULL_RATE_LIMIT_LOCAL_PROCESSES", 1)
    monkeypatch.setattr(settings, "SEAGULL_RATE_LIMIT_LOCAL_MAX_KEYS", 10000)
    yield
    rl._local_windows.clear()


def _drain(scope: str, identity: str, *, limit: int, attempts: int, window_seconds: int = 60) -> list[bool]:
    return [
        rl.rate_limit(scope, "ip", identity, limit=limit, window_seconds=window_seconds).allowed
        for _ in range(attempts)
    ]


def test_the_window_is_counted_and_expired_in_one_round_trip(monkeypatch: pytest.MonkeyPatch):
    redis = _FakeRedis()
    monkeypatch.setattr(rl, "get_redis", lambda: redis)

    decisions = _drain("login", "203.0.113.7", limit=2, attempts=4)

    assert decisions == [True, True, False, False]
    assert redis.calls == 4
    assert redis.ttls == {"rl:login:ip:203.0.113.7": 60000}


def test_a_window_that_lost_its_expiry_gets_one_back(monkeypatch: pytest.MonkeyPatch):
    redis = _FakeRedis()
    key = "rl:login:ip:198.51.100.4"
    redis.values[key] = 5
    monkeypatch.setattr(rl, "get_redis", lambda: redis)

    result = rl.rate_limit("login", "ip", "198.51.100.4", limit=10, window_seconds=300)

    assert redis.ttls[key] == 300000
    assert result.reset_seconds == 300


def test_reset_seconds_reports_what_is_left_of_the_window(monkeypatch: pytest.MonkeyPatch):
    redis = _FakeRedis()
    key = "rl:otp:ip:192.0.2.9"
    redis.values[key] = 1
    redis.ttls[key] = 4200
    monkeypatch.setattr(rl, "get_redis", lambda: redis)

    result = rl.rate_limit("otp", "ip", "192.0.2.9", limit=10, window_seconds=300)

    assert result.reset_seconds == 5


def test_a_failing_redis_falls_back_and_opens_the_circuit(monkeypatch: pytest.MonkeyPatch):
    redis = _FakeRedis(fail_after=1)
    marked: list[bool] = []
    monkeypatch.setattr(rl, "get_redis", lambda: redis)
    monkeypatch.setattr(rl, "mark_redis_unavailable", lambda: marked.append(True))

    assert rl.rate_limit("login", "ip", "203.0.113.8", limit=5, window_seconds=60).allowed
    assert rl.rate_limit("login", "ip", "203.0.113.8", limit=5, window_seconds=60).allowed

    assert marked == [True]


def test_the_fallback_never_logs_the_identity(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    redis = _FakeRedis(fail_after=0)
    monkeypatch.setattr(rl, "get_redis", lambda: redis)
    monkeypatch.setattr(rl, "mark_redis_unavailable", lambda: None)

    with caplog.at_level("WARNING"):
        rl.rate_limit("login", "user", "admin@example.com", limit=5, window_seconds=60)

    records = [r for r in caplog.records if getattr(r, "event", "") == "rate_limit_shared_window_unavailable"]
    assert len(records) == 1
    fields = records[0].fields
    assert fields["scope"] == "login"
    assert fields["dimension"] == "user"
    assert "admin@example.com" not in str(fields)
    assert len(fields["identity_digest"]) == 12


def test_the_local_budget_is_split_across_the_declared_processes(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(rl, "get_redis", lambda: None)
    monkeypatch.setattr(settings, "SEAGULL_RATE_LIMIT_LOCAL_PROCESSES", 4)

    decisions = _drain("login", "203.0.113.9", limit=12, attempts=5)

    assert decisions == [True, True, True, False, False]


def test_the_processes_together_admit_no_more_than_the_configured_limit(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(rl, "get_redis", lambda: None)
    monkeypatch.setattr(settings, "SEAGULL_RATE_LIMIT_LOCAL_PROCESSES", 3)

    admitted = 0
    for _process in range(3):
        rl._local_windows.clear()
        admitted += sum(_drain("login", "203.0.113.20", limit=12, attempts=12))

    assert admitted == 12


def test_the_local_budget_never_falls_below_one_attempt(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(rl, "get_redis", lambda: None)
    monkeypatch.setattr(settings, "SEAGULL_RATE_LIMIT_LOCAL_PROCESSES", 100)

    decisions = _drain("login", "203.0.113.10", limit=12, attempts=3)

    assert decisions == [True, False, False]


def test_the_local_window_store_stays_within_its_ceiling(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(rl, "get_redis", lambda: None)
    monkeypatch.setattr(settings, "SEAGULL_RATE_LIMIT_LOCAL_MAX_KEYS", 32)

    for index in range(500):
        rl.rate_limit("login", "ip", f"198.51.100.{index}", limit=5, window_seconds=300)

    assert rl._local_windows.size() == 32


def test_an_expired_local_window_starts_over(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(rl, "get_redis", lambda: None)
    clock = {"now": 1000.0}
    monkeypatch.setattr(rl.time, "monotonic", lambda: clock["now"])

    assert _drain("login", "203.0.113.11", limit=2, attempts=3) == [True, True, False]
    clock["now"] += 61.0
    assert rl.rate_limit("login", "ip", "203.0.113.11", limit=2, window_seconds=60).allowed


def test_the_deny_policy_refuses_while_the_shared_window_is_gone(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(rl, "get_redis", lambda: None)
    monkeypatch.setattr(settings, "SEAGULL_RATE_LIMIT_DEGRADED_POLICY", "deny")

    result = rl.rate_limit("login", "ip", "203.0.113.12", limit=25, window_seconds=300)

    assert result.allowed is False
    assert result.remaining == 0
    assert result.reset_seconds == 300
    assert rl._local_windows.size() == 0


def test_every_decision_is_counted_by_scope_and_backend(monkeypatch: pytest.MonkeyPatch):
    recorded: list[dict] = []
    monkeypatch.setattr(rl, "get_redis", lambda: None)
    monkeypatch.setattr(rl, "incr_counter", lambda name, **labels: recorded.append({"name": name, **labels}))

    _drain("login", "203.0.113.13", limit=1, attempts=2)

    assert recorded == [
        {"name": "rate_limit_decisions_total", "scope": "login", "backend": "local", "outcome": "allowed"},
        {"name": "rate_limit_decisions_total", "scope": "login", "backend": "local", "outcome": "limited"},
    ]
