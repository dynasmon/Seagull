from __future__ import annotations

from app.features.ingest.control import backpressure as ic
from app.features.ingest.control import recovery as recovery_ic
from app.core.config import settings


def _set_thresholds() -> None:
    settings.SEAGULL_INGEST_STORM_EVENTS_PER_SECOND = 1000
    settings.SEAGULL_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS = 5000
    settings.SEAGULL_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS = 20000


def test_pressure_state_progression_burst_to_recovery() -> None:
    _set_thresholds()

    prev = "ok"
    prev_backlog = 0

    # 1) pressure ramps up
    phase, _ = recovery_ic.decide_pressure_phase(
        prev_phase=prev,
        eps=1500,
        processed_eps=300,
        backlog_events=8000,
        prev_backlog_events=prev_backlog,
        rejected=0,
        stalled_seconds=0,
    )
    assert phase == "storm"
    prev = phase
    prev_backlog = 8000

    # 2) hard pressure causes shedding
    phase, _ = recovery_ic.decide_pressure_phase(
        prev_phase=prev,
        eps=2200,
        processed_eps=400,
        backlog_events=30000,
        prev_backlog_events=prev_backlog,
        rejected=900,
        stalled_seconds=10,
    )
    assert phase == "shedding"
    prev = phase
    prev_backlog = 30000

    # 3) load drops, still draining backlog
    phase, _ = recovery_ic.decide_pressure_phase(
        prev_phase=prev,
        eps=350,
        processed_eps=1200,
        backlog_events=9000,
        prev_backlog_events=prev_backlog,
        rejected=0,
        stalled_seconds=20,
    )
    assert phase == "draining"
    prev = phase
    prev_backlog = 9000

    # 4) backlog converges
    phase, _ = recovery_ic.decide_pressure_phase(
        prev_phase=prev,
        eps=200,
        processed_eps=700,
        backlog_events=2000,
        prev_backlog_events=prev_backlog,
        rejected=0,
        stalled_seconds=40,
    )
    assert phase == "ok"


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.lens: dict[str, int] = {}

    def llen(self, key: str) -> int:
        return int(self.lens.get(key, 0))

    def get(self, key: str):
        return self.store.get(key)

    def set(self, key: str, value):
        self.store[key] = str(value)
        return True


def test_backlog_counter_self_heals_when_stale(monkeypatch) -> None:
    _set_thresholds()
    fake = _FakeRedis()
    fake.lens[ic.queue_key()] = 0
    fake.lens[ic.processing_key()] = 0
    fake.store[ic.backlog_events_key()] = "1008581"
    fake.store["seagull:ingest:events_per_msg_avg"] = "12.0"
    monkeypatch.setattr(ic, "get_redis", lambda: fake)

    msgs, ev = ic.get_backlog()
    assert msgs == 0
    assert ev == 0
    assert fake.store[ic.backlog_events_key()] == "0"


def test_backpressure_recovers_when_queue_is_small(monkeypatch) -> None:
    _set_thresholds()

    class _SmallQueueRedis(_FakeRedis):
        pass

    fake = _SmallQueueRedis()
    fake.lens[ic.queue_key()] = 2
    fake.lens[ic.processing_key()] = 0
    fake.store[ic.backlog_events_key()] = "3200"
    fake.store["seagull:ingest:bp_mode"] = "rollup_only"
    fake.store["seagull:ingest:events_per_msg_avg"] = "8.0"
    monkeypatch.setattr(ic, "get_redis", lambda: fake)

    d = ic.evaluate_backpressure(received=5)
    assert d.mode == "normal"
