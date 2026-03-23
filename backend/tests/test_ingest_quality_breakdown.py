from __future__ import annotations

from app.core import ingest_control as ic


class _Pipe:
    def __init__(self, parent: "_FakeRedis") -> None:
        self.parent = parent
        self.ops = []

    def hincrby(self, key: str, field: str, amount: int):
        self.ops.append(("hincrby", key, field, int(amount)))
        return self

    def expire(self, key: str, ttl: int):
        self.ops.append(("expire", key, int(ttl)))
        return self

    def execute(self):
        out = []
        for op in self.ops:
            if op[0] == "hincrby":
                _, key, field, amount = op
                cur = int(self.parent.hashes.setdefault(key, {}).get(field, 0))
                nxt = cur + amount
                self.parent.hashes[key][field] = str(nxt)
                out.append(nxt)
            elif op[0] == "expire":
                out.append(True)
        return out


class _FakeRedis:
    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, str]] = {}

    def pipeline(self):
        return _Pipe(self)

    def hgetall(self, key: str):
        return dict(self.hashes.get(key, {}))


def test_ingest_quality_window_aggregates_percentages(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(ic, "get_redis", lambda: fake)
    monkeypatch.setattr(ic.time, "time", lambda: 200.0)

    ic.record_ingest_quality(
        breakdown={
            "dos_attack": {"received": 10, "hot": 10, "warm": 0, "analytics": 10},
            "flow": {"received": 10, "hot": 2, "warm": 1, "analytics": 3},
        }
    )
    rows = ic._read_ingest_quality_window(now_s=200, seconds=15)
    by_type = {str(r.get("event_type")): r for r in rows}

    assert by_type["dos_attack"]["kept_percent"] == 100
    assert by_type["dos_attack"]["drop_percent"] == 0
    assert by_type["flow"]["kept_percent"] == 30
    assert by_type["flow"]["drop_percent"] == 70

