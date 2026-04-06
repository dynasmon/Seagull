from __future__ import annotations

from app.features.overview import repository as ov


def test_choose_series_source_prefers_rollup_when_fresh() -> None:
    source, reason = ov._choose_series_source(
        rollups_fresh=True,
        rollup_stuck=False,
        live_fresh=True,
        fallback="rollup_1m",
    )
    assert source == "rollup_1s"
    assert reason is None


def test_choose_series_source_falls_back_to_live_when_rollup_stale() -> None:
    source, reason = ov._choose_series_source(
        rollups_fresh=False,
        rollup_stuck=False,
        live_fresh=True,
        fallback="rollup_1m",
    )
    assert source == "live_1s"
    assert reason == "rollup_stale_fallback_live"


def test_choose_series_source_falls_back_cleanly_when_both_stale() -> None:
    source, reason = ov._choose_series_source(
        rollups_fresh=False,
        rollup_stuck=True,
        live_fresh=False,
        fallback="historical",
    )
    assert source == "historical"
    assert reason == "rollup_stuck_live_stale"


def test_overview_query_source_maps_historical_rollups_to_postgres() -> None:
    assert ov._overview_query_source("rollup_1m") == "postgres"
    assert ov._overview_query_source("historical") == "postgres"


def test_overview_fallback_chain_marks_degraded_progression() -> None:
    assert ov._overview_fallback_chain(selected_source="rollup_1s", degraded_reason=None) == ["rollup_1s"]
    assert ov._overview_fallback_chain(selected_source="postgres", degraded_reason="rollup_stale_fallback") == [
        "rollup_1s",
        "live_1s",
        "postgres",
    ]
