from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.features.ingest import service


def test_elevated_sampling_keeps_hot_telemetry_outside_active_protection() -> None:
    hot_pct, analytics_pct, warm_pct, recent_min_batch = service._target_sample_policy(  # noqa: SLF001
        level="elevated",
        storm_active=False,
    )

    assert hot_pct == 100
    assert analytics_pct >= 1
    assert warm_pct >= 0
    assert recent_min_batch >= 8
