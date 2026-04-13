from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core import recent_feed


class _FakePipeline:
    def __init__(self, redis_obj: "_FakeRedis") -> None:
        self.r = redis_obj
        self.ops = []

    def lpush(self, key: str, value: str):
        self.ops.append(("lpush", key, value))
        return self

    def ltrim(self, key: str, start: int, end: int):
        self.ops.append(("ltrim", key, start, end))
        return self

    def incrby(self, key: str, value: int):
        self.ops.append(("incrby", key, value))
        return self

    def expire(self, key: str, _ttl: int):
        self.ops.append(("expire", key))
        return self

    def setex(self, key: str, _ttl: int, value: str):
        self.ops.append(("setex", key, value))
        return self

    def execute(self):
        out = []
        for op in self.ops:
            kind = op[0]
            if kind == "lpush":
                _, key, value = op
                self.r.lists.setdefault(key, []).insert(0, value)
                out.append(1)
            elif kind == "ltrim":
                _, key, start, end = op
                self.r.lists[key] = self.r.lists.get(key, [])[int(start) : int(end) + 1]
                out.append(True)
            elif kind == "incrby":
                _, key, value = op
                cur = int(self.r.kv.get(key, "0") or 0)
                self.r.kv[key] = str(cur + int(value))
                out.append(cur + int(value))
            elif kind == "setex":
                _, key, value = op
                self.r.kv[key] = value
                out.append(True)
            elif kind == "expire":
                out.append(True)
        return out


class _FakeRedis:
    def __init__(self) -> None:
        self.kv: dict[str, str] = {}
        self.lists: dict[str, list[str]] = {}

    def pipeline(self) -> _FakePipeline:
        return _FakePipeline(self)

    def lrange(self, key: str, start: int, end: int):
        vals = self.lists.get(key, [])
        return vals[int(start) : int(end) + 1]

    def get(self, key: str):
        return self.kv.get(key)


def test_recent_feed_push_fetch_and_health(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(recent_feed, "get_redis", lambda: fake)

    now = datetime.now(timezone.utc)
    rows = [
        {
            "agent_id": "agent-a",
            "event_type": "dns",
            "timestamp": now.isoformat(),
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "extra": {"dns_qname": "example.local"},
        },
        {
            "agent_id": "agent-a",
            "event_type": "ssh_auth",
            "timestamp": (now - timedelta(seconds=1)).isoformat(),
            "src_ip": "10.0.0.9",
            "dst_ip": "10.0.0.2",
            "dst_port": 22,
            "extra": {"action": "failed_password"},
        },
    ]

    pushed = recent_feed.push_recent_events(rows)
    assert pushed == 2

    out = recent_feed.fetch_recent_events(limit=10, agent_id="agent-a")
    assert len(out) == 2
    assert out[0]["agent_id"] == "agent-a"
    assert out[0]["extra"]["action"] == "failed_password"


    health = recent_feed.recent_feed_health(agent_id="agent-a")
    assert health["last_event_ts"] is not None
    assert int(health["events_last_second"] or 0) >= 1
    assert int(health["freshness_seconds"] or 0) >= 0


def test_recent_feed_push_is_capped_per_call(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(recent_feed, "get_redis", lambda: fake)
    monkeypatch.setattr(recent_feed.settings, "NETWATCH_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL", 100, raising=False)
    monkeypatch.setattr(recent_feed.settings, "NETWATCH_INGEST_RECENT_FEED_MAX_EVENTS", 5000, raising=False)
    monkeypatch.setattr(recent_feed.settings, "NETWATCH_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS", 2000, raising=False)

    now = datetime.now(timezone.utc)
    rows = []
    for i in range(2000):
        rows.append(
            {
                "agent_id": "agent-load",
                "event_type": "flow",
                "timestamp": (now - timedelta(milliseconds=i)).isoformat(),
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dst_port": 443,
            }
        )

    pushed = recent_feed.push_recent_events(rows)
    assert pushed == 100

    global_key = "netwatch:recent_feed:v1:global"
    agent_key = "netwatch:recent_feed:v1:agent:agent-load"
    assert len(fake.lists.get(global_key, [])) == 100
    assert len(fake.lists.get(agent_key, [])) == 100
