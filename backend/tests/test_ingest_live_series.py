from __future__ import annotations

from datetime import datetime, timezone

from app.core import ingest_control as ic


class _Pipe:
    def __init__(self, redis: "_FakeRedis") -> None:
        self._r = redis
        self._ops: list[tuple[str, tuple, dict]] = []

    def hincrby(self, *args, **kwargs):
        self._ops.append(("hincrby", args, kwargs))
        return self

    def hset(self, *args, **kwargs):
        self._ops.append(("hset", args, kwargs))
        return self

    def expire(self, *args, **kwargs):
        self._ops.append(("expire", args, kwargs))
        return self

    def incrby(self, *args, **kwargs):
        self._ops.append(("incrby", args, kwargs))
        return self

    def hgetall(self, *args, **kwargs):
        self._ops.append(("hgetall", args, kwargs))
        return self

    def execute(self):
        out = []
        for name, args, kwargs in self._ops:
            out.append(getattr(self._r, name)(*args, **kwargs))
        self._ops.clear()
        return out


class _FakeRedis:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.hashes: dict[str, dict[str, str]] = {}

    def pipeline(self):
        return _Pipe(self)

    def get(self, key):
        return self.data.get(str(key))

    def setex(self, key, ttl, value):
        self.data[str(key)] = str(value)
        return True

    def expire(self, key, ttl):
        return True

    def incrby(self, key, value):
        k = str(key)
        cur = int(self.data.get(k, "0") or "0")
        cur += int(value)
        self.data[k] = str(cur)
        return cur

    def hincrby(self, key, field, value):
        hk = str(key)
        ff = str(field)
        cur = int((self.hashes.setdefault(hk, {})).get(ff, "0") or "0")
        cur += int(value)
        self.hashes[hk][ff] = str(cur)
        return cur

    def hset(self, key, field=None, value=None, mapping=None):
        hk = str(key)
        self.hashes.setdefault(hk, {})
        if mapping is not None:
            for mk, mv in dict(mapping).items():
                self.hashes[hk][str(mk)] = str(mv)
            return True
        self.hashes[hk][str(field)] = str(value)
        return True

    def hgetall(self, key):
        return dict(self.hashes.get(str(key), {}))


def test_record_and_read_live_overview_window(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(ic, "get_redis", lambda: fake)

    ts = datetime(2026, 4, 5, 12, 0, 5, tzinfo=timezone.utc)
    ok = ic.record_overview_live_telemetry(
        ingest_received=42,
        processed_events=31,
        bytes_sum=2048,
        event_type_counts={"flow": 30, "dns": 12},
        severity_counts={"high": 9, "medium": 7},
        ddos_packets_estimated=1000,
        ddos_samples=4,
        ddos_peak_pps=512.0,
        ddos_peak_bps=2048.0,
        bucket_ts=ts,
    )
    assert ok is True

    out = ic.read_overview_live_window(now_s=int(ts.timestamp()), seconds=10)
    assert out["last_data_ts"] is not None
    assert out["freshness_seconds"] == 0
    assert len(out["rows"]) == 1
    row = out["rows"][0]
    assert int(row["ingest_received"]) == 42
    assert int(row["processed_events"]) == 31
    assert int(row["bytes_sum"]) == 2048
    assert int(row["ddos_packets_estimated"]) == 1000
    assert int(row["event_types"]["flow"]) == 30
    assert int(row["severity"]["high"]) == 9


def test_live_overview_caps_event_type_cardinality(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(ic, "get_redis", lambda: fake)
    monkeypatch.setattr(ic.settings, "SEAGULL_OVERVIEW_LIVE_MAX_EVENT_TYPES_PER_SECOND", 2, raising=False)

    ts = datetime(2026, 4, 5, 12, 1, 0, tzinfo=timezone.utc)
    ic.record_overview_live_telemetry(
        ingest_received=20,
        event_type_counts={"a": 8, "b": 7, "c": 5},
        severity_counts={},
        bucket_ts=ts,
    )
    out = ic.read_overview_live_window(now_s=int(ts.timestamp()), seconds=5)
    row = out["rows"][0]
    assert len(row["event_types"]) == 2
    assert int(row["dropped_event_type_counts"]) == 5
