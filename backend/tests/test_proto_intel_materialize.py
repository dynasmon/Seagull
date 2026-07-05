from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from datetime import datetime, timezone

import pytest

from app.core.observability.registry import METRIC_SPECS
from app.workers.analytics import proto_intel_backfill as pib
from app.workers.manager import GROUPS


class FakeCH:
    def __init__(self, *, raw_min, overview_min, fail_on_insert: int | None = None):
        self.raw_min = raw_min
        self.overview_min = overview_min
        self.fail_on_insert = fail_on_insert
        self.commands: list[tuple[str, dict]] = []
        self._insert_count = 0

    def query(self, sql):
        row = [0]
        if "minOrNull(timestamp)" in sql:
            row = [self.raw_min]
        elif "minOrNull(bucket_ts)" in sql:
            row = [self.overview_min]

        class _R:
            first_row = row

        return _R()

    def command(self, sql, settings=None):
        if sql.startswith("INSERT"):
            self._insert_count += 1
            if self.fail_on_insert is not None and self._insert_count >= self.fail_on_insert:
                raise RuntimeError("simulated_insert_failure")
        self.commands.append((sql, settings or {}))

    def inserts(self):
        return [(s, st) for s, st in self.commands if s.startswith("INSERT")]

    def truncates(self):
        return [s for s, _ in self.commands if s.startswith("TRUNCATE")]


class FakeState:
    """In-memory stand-in for the Redis-backed watermark state."""

    def __init__(self):
        self.floor = None
        self.range = None
        self.floor_writes: list[datetime] = []
        self._pins = 0

    def read_floor(self):
        return self.floor

    def write_floor(self, *, floor_ts):
        self.floor = floor_ts
        self.floor_writes.append(floor_ts)

    def read_range(self):
        return dict(self.range) if self.range else None

    def pin(self, *, start_ts, boundary_ts, chunk_hours=None):
        if self.range is None:
            self._pins += 1
            self.range = {
                "start": start_ts,
                "boundary": boundary_ts,
                "gen": f"g{self._pins}",
                "chunk_hours": int(chunk_hours) if chunk_hours else None,
            }
        return dict(self.range)

    def clear(self):
        self.floor = None
        self.range = None

    def install(self, monkeypatch):
        monkeypatch.setattr(pib, "read_proto_intel_materialization_floor", self.read_floor)
        monkeypatch.setattr(pib, "write_proto_intel_materialization_floor", self.write_floor)
        monkeypatch.setattr(pib, "read_proto_intel_materialization_range", self.read_range)
        monkeypatch.setattr(pib, "pin_proto_intel_materialization_range", self.pin)
        monkeypatch.setattr(pib, "clear_proto_intel_materialization_state", self.clear)
        return self


RAW_MIN = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)
OVERVIEW_MIN = datetime(2026, 6, 5, 0, 0, tzinfo=timezone.utc)


def test_materialize_worker_registered_and_metric_declared():
    names = [c.name for c in GROUPS["intelligence"]]
    assert "proto-materialize" in names
    assert "analytics_materialize_total" in METRIC_SPECS


def test_run_materialization_skips_when_floor_covers_raw_min(monkeypatch):
    state = FakeState().install(monkeypatch)
    state.floor = RAW_MIN
    state.range = {"start": RAW_MIN, "boundary": OVERVIEW_MIN, "gen": "g1", "chunk_hours": 24}
    ch = FakeCH(raw_min=RAW_MIN, overview_min=OVERVIEW_MIN)

    out = pib.run_materialization(ch)

    assert out == RAW_MIN
    assert ch.inserts() == []
    assert ch.truncates() == []


def test_run_materialization_returns_floor_when_raw_empty(monkeypatch):
    state = FakeState().install(monkeypatch)
    state.floor = RAW_MIN
    ch = FakeCH(raw_min=None, overview_min=None)

    assert pib.run_materialization(ch) == RAW_MIN
    assert ch.inserts() == []


def test_fresh_fill_descends_and_persists_floor_per_chunk(monkeypatch):
    state = FakeState().install(monkeypatch)
    ch = FakeCH(raw_min=datetime(2026, 6, 1, 0, 0, 30, tzinfo=timezone.utc), overview_min=OVERVIEW_MIN)

    out = pib.run_materialization(ch, chunk_hours=24)

    assert out == RAW_MIN
    assert state.floor == RAW_MIN
    # Dirty/fresh state is rebuilt: targets truncated before the fill.
    assert len(ch.truncates()) == 2
    # 4 daily chunks x (facet + overview).
    inserts = ch.inserts()
    assert len(inserts) == 8
    tokens = [st["insert_deduplication_token"] for _, st in inserts]
    # Token shape: pim:<kind>:<gen>:<lo>:<hi>
    assert all(t.split(":")[2] == "g1" for t in tokens)
    # Descending: first chunk ends at the boundary, floors shrink monotonically.
    first_hi = int(tokens[0].rsplit(":", 1)[-1])
    assert first_hi == int(OVERVIEW_MIN.timestamp())
    assert state.floor_writes[:4] == sorted(state.floor_writes[:4], reverse=True)
    assert state.floor_writes[0] == datetime(2026, 6, 4, 0, 0, tzinfo=timezone.utc)


def test_failure_keeps_progress_and_resume_completes_without_rework(monkeypatch):
    state = FakeState().install(monkeypatch)
    # Fail while inserting the 3rd chunk (insert #5): 2 chunks completed.
    ch = FakeCH(raw_min=RAW_MIN, overview_min=OVERVIEW_MIN, fail_on_insert=5)

    with pytest.raises(RuntimeError):
        pib.run_materialization(ch, chunk_hours=24)

    assert state.floor == datetime(2026, 6, 3, 0, 0, tzinfo=timezone.utc)
    completed_tokens = {st["insert_deduplication_token"] for _, st in ch.inserts()}

    ch2 = FakeCH(raw_min=RAW_MIN, overview_min=OVERVIEW_MIN)
    out = pib.run_materialization(ch2, chunk_hours=24)

    assert out == RAW_MIN
    assert state.floor == RAW_MIN
    # Resume: no truncate, and only the two chunks below the floor are filled.
    assert ch2.truncates() == []
    resumed_tokens = {st["insert_deduplication_token"] for _, st in ch2.inserts()}
    assert len(resumed_tokens) == 4
    assert not (resumed_tokens & completed_tokens)


def test_retry_reuses_identical_dedup_tokens(monkeypatch):
    state = FakeState().install(monkeypatch)
    # Fail on the very first INSERT of the 2nd chunk twice in a row.
    for _ in range(2):
        ch = FakeCH(raw_min=RAW_MIN, overview_min=OVERVIEW_MIN, fail_on_insert=3)
        with pytest.raises(RuntimeError):
            pib.run_materialization(ch, chunk_hours=24)

    ch3 = FakeCH(raw_min=RAW_MIN, overview_min=OVERVIEW_MIN)
    pib.run_materialization(ch3, chunk_hours=24)
    # The failed chunk is retried under the same generation so ClickHouse
    # dedups any partially inserted blocks from the crashed attempts.
    all_tokens = [st["insert_deduplication_token"] for _, st in ch3.inserts()]
    assert all(t.split(":")[2] == "g1" for t in all_tokens)
    assert state.floor == RAW_MIN


def test_pinned_chunk_grid_wins_over_setting_changes(monkeypatch):
    FakeState().install(monkeypatch)
    ch = FakeCH(raw_min=RAW_MIN, overview_min=OVERVIEW_MIN, fail_on_insert=5)
    with pytest.raises(RuntimeError):
        pib.run_materialization(ch, chunk_hours=24)

    # Operator flips the chunk size mid-flight: the pinned 24h grid must win,
    # otherwise retries would insert overlapping ranges under new tokens.
    ch2 = FakeCH(raw_min=RAW_MIN, overview_min=OVERVIEW_MIN)
    pib.run_materialization(ch2, chunk_hours=6)
    assert len(ch2.inserts()) == 4  # two 24h chunks, not eight 6h chunks


def test_floor_without_pinned_range_triggers_rebuild(monkeypatch):
    state = FakeState().install(monkeypatch)
    state.floor = datetime(2026, 6, 3, 0, 0, tzinfo=timezone.utc)
    state.range = None  # progress marker survived but the grid/gen is gone
    ch = FakeCH(raw_min=RAW_MIN, overview_min=OVERVIEW_MIN)

    out = pib.run_materialization(ch, chunk_hours=24)

    assert out == RAW_MIN
    assert len(ch.truncates()) == 2
    assert len(ch.inserts()) == 8


def test_live_boundary_equal_to_start_means_nothing_to_backfill(monkeypatch):
    state = FakeState().install(monkeypatch)
    # Fresh install where the MVs existed before the first raw insert: the
    # live MV already covers everything, a backfill would double count.
    ch = FakeCH(raw_min=RAW_MIN, overview_min=RAW_MIN)

    out = pib.run_materialization(ch, chunk_hours=24)

    assert out == RAW_MIN
    assert ch.inserts() == []
    assert state.floor == RAW_MIN


def test_tokens_are_stable_across_runs(monkeypatch):
    def _tokens():
        state = FakeState().install(monkeypatch)
        ch = FakeCH(raw_min=RAW_MIN, overview_min=OVERVIEW_MIN)
        pib.run_materialization(ch, chunk_hours=24)
        assert state.floor == RAW_MIN
        return [st["insert_deduplication_token"] for _, st in ch.inserts()]

    assert _tokens() == _tokens()
