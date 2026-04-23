from __future__ import annotations

import os
from datetime import datetime, timezone

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.ingest import service as ingest_service
from app.features.events.schemas import NetEvent
from app.features.overview import repository as overview_repository


def test_build_live_overview_summary_only_counts_ddos_events() -> None:
    rows = [
        NetEvent(
            agent_id="agent-1",
            event_type="ssh_auth",
            schema_version=1,
            timestamp=datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc),
            src_ip="203.0.113.10",
            dst_ip="192.168.200.128",
            dst_port=22,
            proto="tcp",
            bytes=128,
            extra={"pps": 999, "bps": 12345},
        ),
        NetEvent(
            agent_id="agent-1",
            event_type="dos_attack",
            schema_version=1,
            timestamp=datetime(2026, 4, 23, 10, 0, 1, tzinfo=timezone.utc),
            dst_ip="192.168.200.128",
            dst_port=80,
            proto="tcp",
            bytes=4096,
            extra={
                "packets": 379,
                "pps": 11,
                "bps": 2048,
                "tcp_syn_ratio": 0.8,
                "http_rps": 7,
            },
        ),
    ]

    summary = ingest_service._build_live_overview_summary(rows)

    assert summary["event_type_counts"]["ssh_auth"] == 1
    assert summary["event_type_counts"]["dos_attack"] == 1
    assert summary["ddos_packets_estimated"] == 379
    assert summary["ddos_samples"] == 1
    assert summary["ddos_peak_pps"] == 11.0
    assert summary["ddos_peak_bps"] == 2048.0
    assert summary["ddos_peak_syn_ratio"] == 0.8
    assert summary["ddos_peak_flow_rps"] == 7.0


def test_overlay_live_ddos_volume_map_preserves_history_and_ignores_zero_live_rows() -> None:
    historical_bucket = datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    live_bucket = datetime(2026, 4, 23, 10, 1, 0, tzinfo=timezone.utc)
    base_map = {
        historical_bucket: {"packets": 120.0, "peak_pps": 15.0, "peak_bps": 2048.0},
        live_bucket: {"packets": 5.0, "peak_pps": 1.0, "peak_bps": 128.0},
    }

    live_rows = [
        {
            "ts": datetime(2026, 4, 23, 10, 0, 10, tzinfo=timezone.utc),
            "ddos_packets_estimated": 0,
            "ddos_samples": 0,
            "ddos_peak_pps": 0.0,
            "ddos_peak_bps": 0.0,
            "ingest_received": 999,
        },
        {
            "ts": datetime(2026, 4, 23, 10, 1, 5, tzinfo=timezone.utc),
            "ddos_packets_estimated": 379,
            "ddos_samples": 1,
            "ddos_peak_pps": 11.0,
            "ddos_peak_bps": 1024.0,
        },
    ]

    merged = overview_repository._overlay_live_ddos_volume_map(base_map, live_rows)

    assert merged[historical_bucket]["packets"] == 120.0
    assert merged[live_bucket]["packets"] == 379.0
    assert merged[live_bucket]["peak_pps"] == 11.0
    assert merged[live_bucket]["peak_bps"] == 1024.0
