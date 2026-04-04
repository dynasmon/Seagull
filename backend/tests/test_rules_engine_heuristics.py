from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core.config import settings
from app.workers.rules_engine import _build_beacon_candidates, _build_egress_anomaly_candidates, _build_exfil_candidates


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeDB:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, _stmt):
        return _Rows(self._rows)


class _FakeDBSeq:
    def __init__(self, responses):
        self._responses = list(responses)
        self._idx = 0

    def execute(self, _stmt):
        if self._idx >= len(self._responses):
            return _Rows([])
        rows = self._responses[self._idx]
        self._idx += 1
        return _Rows(rows)


def _row(ts: datetime, *, bytes_sent: int, host: str = "c2.example.test") -> SimpleNamespace:
    return SimpleNamespace(
        agent_id="agent-1",
        timestamp=ts,
        src_ip="10.0.0.8",
        dst_ip="203.0.113.25",
        dst_port=443,
        proto="tcp",
        bytes=bytes_sent,
        app_proto="tls",
        extra={"flow_direction": "outbound_from_local", "http_host": host},
    )


def test_build_beacon_candidates_detects_periodic_low_jitter() -> None:
    now = datetime.now(timezone.utc)
    rows = [_row(now - timedelta(seconds=(7 - i) * 60), bytes_sent=640) for i in range(8)]

    old_max_rows = settings.NETWATCH_HEUR_MAX_ROWS
    try:
        settings.NETWATCH_HEUR_MAX_ROWS = 1000
        out = _build_beacon_candidates(_FakeDB(rows), now)
    finally:
        settings.NETWATCH_HEUR_MAX_ROWS = old_max_rows

    assert out
    cand = out[0]
    assert cand["dst_ip"] == "203.0.113.25"
    assert cand["sample_count"] >= 7
    assert float(cand["interval_mean_s"]) >= 59.0
    assert float(cand["interval_jitter_cv"]) <= 0.22


def test_build_exfil_candidates_detects_burst_to_rare_destination() -> None:
    now = datetime.now(timezone.utc)
    baseline = [
        _row(now - timedelta(seconds=1800), bytes_sent=200),
        _row(now - timedelta(seconds=1500), bytes_sent=200),
        _row(now - timedelta(seconds=1200), bytes_sent=200),
    ]
    recent = [
        _row(now - timedelta(seconds=240), bytes_sent=3200),
        _row(now - timedelta(seconds=180), bytes_sent=3200),
        _row(now - timedelta(seconds=120), bytes_sent=3200),
        _row(now - timedelta(seconds=60), bytes_sent=3200),
        _row(now - timedelta(seconds=20), bytes_sent=3200),
    ]
    rows = baseline + recent

    old_vals = (
        settings.NETWATCH_HEUR_MAX_ROWS,
        settings.NETWATCH_HEUR_EXFIL_BASELINE_SECONDS,
        settings.NETWATCH_HEUR_EXFIL_WINDOW_SECONDS,
        settings.NETWATCH_HEUR_EXFIL_MIN_EVENTS,
        settings.NETWATCH_HEUR_EXFIL_MIN_BYTES,
        settings.NETWATCH_HEUR_EXFIL_SPIKE_FACTOR,
        settings.NETWATCH_HEUR_EXFIL_RARE_BASELINE_EVENTS,
    )
    try:
        settings.NETWATCH_HEUR_MAX_ROWS = 1000
        settings.NETWATCH_HEUR_EXFIL_BASELINE_SECONDS = 7200
        settings.NETWATCH_HEUR_EXFIL_WINDOW_SECONDS = 300
        settings.NETWATCH_HEUR_EXFIL_MIN_EVENTS = 4
        settings.NETWATCH_HEUR_EXFIL_MIN_BYTES = 1024
        settings.NETWATCH_HEUR_EXFIL_SPIKE_FACTOR = 2.0
        settings.NETWATCH_HEUR_EXFIL_RARE_BASELINE_EVENTS = 5
        out = _build_exfil_candidates(_FakeDB(rows), now)
    finally:
        (
            settings.NETWATCH_HEUR_MAX_ROWS,
            settings.NETWATCH_HEUR_EXFIL_BASELINE_SECONDS,
            settings.NETWATCH_HEUR_EXFIL_WINDOW_SECONDS,
            settings.NETWATCH_HEUR_EXFIL_MIN_EVENTS,
            settings.NETWATCH_HEUR_EXFIL_MIN_BYTES,
            settings.NETWATCH_HEUR_EXFIL_SPIKE_FACTOR,
            settings.NETWATCH_HEUR_EXFIL_RARE_BASELINE_EVENTS,
        ) = old_vals

    assert out
    cand = out[0]
    assert cand["recent_events"] >= 4
    assert int(cand["recent_bytes"]) > int(cand["baseline_bytes"])
    assert int(cand["confidence"]) >= 62


def test_build_egress_anomaly_candidates_with_exec_correlation() -> None:
    now = datetime.now(timezone.utc)
    flow_rows = [
        SimpleNamespace(
            agent_id="agent-1",
            timestamp=now - timedelta(seconds=4200),
            src_ip="10.0.0.8",
            dst_ip="198.51.100.44",
            dst_port=4444,
            proto="tcp",
            bytes=4000,
            app_proto="dns",
            extra={"flow_direction": "outbound_from_local", "http_host": "x1.bad.evil.test"},
        ),
        *[
            SimpleNamespace(
                agent_id="agent-1",
                timestamp=now - timedelta(seconds=s),
                src_ip="10.0.0.8",
                dst_ip="198.51.100.44",
                dst_port=4444,
                proto="tcp",
                bytes=900000,
                app_proto="dns",
                extra={"flow_direction": "outbound_from_local", "http_host": "x1.bad.evil.test"},
            )
            for s in [240, 180, 120, 60, 20]
        ],
    ]
    suspicious_rows = [
        SimpleNamespace(
            agent_id="agent-1",
            event_type="proc_exec",
            extra={"exec_pattern": "remote_fetch_exec"},
        )
    ]

    old_vals = (
        settings.NETWATCH_HEUR_MAX_ROWS,
        settings.NETWATCH_HEUR_EGRESS_BASELINE_SECONDS,
        settings.NETWATCH_HEUR_EGRESS_WINDOW_SECONDS,
        settings.NETWATCH_HEUR_EGRESS_MIN_EVENTS,
        settings.NETWATCH_HEUR_EGRESS_MIN_BYTES,
        settings.NETWATCH_HEUR_EGRESS_SPIKE_FACTOR,
        settings.NETWATCH_HEUR_EGRESS_RARE_BASELINE_EVENTS,
        settings.NETWATCH_HEUR_EGRESS_CORRELATION_SECONDS,
    )
    try:
        settings.NETWATCH_HEUR_MAX_ROWS = 1000
        settings.NETWATCH_HEUR_EGRESS_BASELINE_SECONDS = 7200
        settings.NETWATCH_HEUR_EGRESS_WINDOW_SECONDS = 300
        settings.NETWATCH_HEUR_EGRESS_MIN_EVENTS = 4
        settings.NETWATCH_HEUR_EGRESS_MIN_BYTES = 1024
        settings.NETWATCH_HEUR_EGRESS_SPIKE_FACTOR = 1.5
        settings.NETWATCH_HEUR_EGRESS_RARE_BASELINE_EVENTS = 2
        settings.NETWATCH_HEUR_EGRESS_CORRELATION_SECONDS = 1200
        out = _build_egress_anomaly_candidates(_FakeDBSeq([flow_rows, suspicious_rows]), now)
    finally:
        (
            settings.NETWATCH_HEUR_MAX_ROWS,
            settings.NETWATCH_HEUR_EGRESS_BASELINE_SECONDS,
            settings.NETWATCH_HEUR_EGRESS_WINDOW_SECONDS,
            settings.NETWATCH_HEUR_EGRESS_MIN_EVENTS,
            settings.NETWATCH_HEUR_EGRESS_MIN_BYTES,
            settings.NETWATCH_HEUR_EGRESS_SPIKE_FACTOR,
            settings.NETWATCH_HEUR_EGRESS_RARE_BASELINE_EVENTS,
            settings.NETWATCH_HEUR_EGRESS_CORRELATION_SECONDS,
        ) = old_vals

    assert out
    cand = out[0]
    assert cand["dst_ip"] == "198.51.100.44"
    assert int(cand["suspicious_exec_hits"]) >= 1
    assert str(cand["reason_kind"]) in {
        "rare_destination_after_suspicious_exec",
        "rare_destination_unusual_protocol",
    }
