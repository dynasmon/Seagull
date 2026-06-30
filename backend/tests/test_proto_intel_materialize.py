from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from datetime import datetime, timezone

from app.core.observability.registry import METRIC_SPECS
from app.workers.analytics import proto_intel_backfill as pib
from app.workers.manager import GROUPS


class FakeCH:
    def __init__(self, *, raw_min, overview_min):
        self.raw_min = raw_min
        self.overview_min = overview_min
        self.commands: list[tuple[str, dict]] = []

    def query(self, sql):
        row = [0]
        if "min(timestamp)" in sql:
            row = [self.raw_min]
        elif "min(bucket_ts)" in sql:
            row = [self.overview_min]

        class _R:
            first_row = row

        return _R()

    def command(self, sql, settings=None):
        self.commands.append((sql, settings or {}))

    def inserts(self):
        return [(s, st) for s, st in self.commands if s.startswith("INSERT")]


def _pin_passthrough(*, start_ts, boundary_ts):
    return (start_ts, boundary_ts)


def test_materialize_worker_registered_and_metric_declared():
    names = [c.name for c in GROUPS["intelligence"]]
    assert "proto-materialize" in names
    assert "analytics_materialize_total" in METRIC_SPECS


def test_run_materialization_skips_when_floor_set(monkeypatch):
    monkeypatch.setattr(pib, "read_proto_intel_materialization_floor", lambda: datetime(2026, 6, 1, tzinfo=timezone.utc))
    ch = FakeCH(raw_min=datetime(2026, 6, 1, tzinfo=timezone.utc), overview_min=datetime(2026, 6, 30, tzinfo=timezone.utc))

    out = pib.run_materialization(ch)

    assert out == datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert ch.inserts() == []


def test_run_materialization_fills_and_sets_floor(monkeypatch):
    state: dict = {"floor": None}
    monkeypatch.setattr(pib, "read_proto_intel_materialization_floor", lambda: state["floor"])
    monkeypatch.setattr(pib, "write_proto_intel_materialization_floor", lambda *, floor_ts: state.update(floor=floor_ts))
    monkeypatch.setattr(pib, "pin_proto_intel_materialization_range", _pin_passthrough)

    raw_min = datetime(2026, 6, 1, 0, 0, 30, tzinfo=timezone.utc)
    ch = FakeCH(raw_min=raw_min, overview_min=datetime(2026, 6, 30, 0, 0, tzinfo=timezone.utc))

    out = pib.run_materialization(ch, chunk_hours=24 * 40)

    floored = raw_min.replace(second=0, microsecond=0)
    assert out == floored
    assert state["floor"] == floored
    inserts = ch.inserts()
    assert len(inserts) == 2
    assert all("insert_deduplication_token" in st for _, st in inserts)


def test_run_materialization_tokens_are_stable_across_runs(monkeypatch):
    monkeypatch.setattr(pib, "read_proto_intel_materialization_floor", lambda: None)
    monkeypatch.setattr(pib, "write_proto_intel_materialization_floor", lambda *, floor_ts: None)
    monkeypatch.setattr(pib, "pin_proto_intel_materialization_range", _pin_passthrough)

    raw_min = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)
    overview_min = datetime(2026, 6, 5, 0, 0, tzinfo=timezone.utc)

    def _tokens():
        ch = FakeCH(raw_min=raw_min, overview_min=overview_min)
        pib.run_materialization(ch, chunk_hours=24)
        return [st["insert_deduplication_token"] for _, st in ch.inserts()]

    assert _tokens() == _tokens()
