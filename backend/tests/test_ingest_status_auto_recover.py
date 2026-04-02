from __future__ import annotations

import os
import time

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core import ingest_control as ic


class _Pipeline:
    def __init__(self, redis: "_FakeRedis") -> None:
        self._r = redis
        self._ops = []

    def delete(self, *keys):
        self._ops.append(("delete", keys))
        return self

    def execute(self):
        out = []
        for op, args in self._ops:
            if op == "delete":
                out.append(self._r.delete(*args))
        self._ops.clear()
        return out


class _FakeRedis:
    def __init__(self) -> None:
        now_s = int(time.time())
        self.data = {
            ic.storm_active_key(): "1",
            "netwatch:ingest:storm_reason": "soft_backlog",
            "netwatch:ingest:storm_sample_hot": "5",
            "netwatch:ingest:storm_sample_warm": "2",
            "netwatch:overview:v2:w=60|a=*|lite=1": "cached",
            "netwatch:events:ssh_summary:v3:x": "cached",
            "netwatch:inventory:overview:v2:x": "cached",
            ic.backlog_events_key(): "999999",
            ic._worker_eps_key(now_s - 1): "0",  # noqa: SLF001
            ic._worker_msgs_key(now_s - 1): "0",  # noqa: SLF001
        }
        self.hashes = {
            ic._pressure_state_key(): {  # noqa: SLF001
                "phase": "draining",
                "reason": "recovery",
                "since_ts": str(now_s - 600),
                "prev_backlog_events": "50000",
                "last_progress_ts": str(now_s - 600),
            }
        }
        self.lens = {ic.queue_key(): 0, ic.processing_key(): 0}

    def get(self, key):
        return self.data.get(str(key))

    def set(self, key, value):
        self.data[str(key)] = str(value)
        return True

    def setex(self, key, ttl, value):
        self.data[str(key)] = str(value)
        return True

    def delete(self, *keys):
        n = 0
        for key in keys:
            k = str(key)
            if k in self.data:
                del self.data[k]
                n += 1
            if k in self.hashes:
                del self.hashes[k]
                n += 1
        return n

    def llen(self, key):
        return int(self.lens.get(str(key), 0))

    def hgetall(self, key):
        return dict(self.hashes.get(str(key), {}))

    def hset(self, key, mapping):
        self.hashes[str(key)] = {str(k): str(v) for k, v in dict(mapping or {}).items()}
        return True

    def expire(self, key, ttl):
        return True

    def scan_iter(self, match: str, count: int = 256):
        if not match.endswith("*"):
            return
        pref = match[:-1]
        for k in list(self.data.keys()):
            if str(k).startswith(pref):
                yield k

    def pipeline(self):
        return _Pipeline(self)


def test_get_storm_status_auto_recovers_and_clears_runtime_cache(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(ic, "get_redis", lambda: fake)
    monkeypatch.setattr(ic, "storm_maybe_close_alert", lambda: None)
    monkeypatch.setattr(ic, "count_active_workers", lambda: 0)
    monkeypatch.setattr(ic, "recent_feed_health", lambda **kwargs: {"events_last_second": 0, "dropped_last_second": 0, "last_event_ts": None, "freshness_seconds": None})
    monkeypatch.setattr(ic, "_read_ingest_quality_window", lambda **kwargs: [])

    out = ic.get_storm_status()

    assert out["phase"] == "ok"
    assert ic.storm_active_key() not in fake.data
    assert "netwatch:ingest:storm_reason" not in fake.data
    assert "netwatch:overview:v2:w=60|a=*|lite=1" not in fake.data
    assert "netwatch:events:ssh_summary:v3:x" not in fake.data
    assert "netwatch:inventory:overview:v2:x" not in fake.data
