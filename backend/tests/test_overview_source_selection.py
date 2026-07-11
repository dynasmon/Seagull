from __future__ import annotations

from datetime import datetime, timezone

from app.features.overview import repository as ov


def _ts(minute: int) -> datetime:
    return datetime(2026, 7, 11, 12, minute, tzinfo=timezone.utc)


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


def test_choose_series_source_idle_prefers_covering_rollups() -> None:
    source, reason = ov._choose_series_source(
        rollups_fresh=False,
        rollup_stuck=False,
        live_fresh=False,
        stream_idle=True,
        rollups_cover_idle=True,
        fallback="rollup_1m",
    )
    assert source == "rollup_1s"
    assert reason is None


def test_choose_series_source_idle_without_coverage_falls_back_undegraded() -> None:
    source, reason = ov._choose_series_source(
        rollups_fresh=False,
        rollup_stuck=False,
        live_fresh=False,
        stream_idle=True,
        rollups_cover_idle=False,
        fallback="historical",
    )
    assert source == "historical"
    assert reason is None


def test_choose_series_source_fresh_rollups_win_over_idle() -> None:
    source, reason = ov._choose_series_source(
        rollups_fresh=True,
        rollup_stuck=False,
        live_fresh=False,
        stream_idle=True,
        rollups_cover_idle=True,
        fallback="rollup_1m",
    )
    assert source == "rollup_1s"
    assert reason is None


def test_resolve_data_end_freezes_idle_window_at_last_activity() -> None:
    end = ov._resolve_data_end_ts(
        requested_end_ts=_ts(59),
        fixed_range=False,
        stream_idle=True,
        last_activity_ts=_ts(30),
        use_ingest_rollups=True,
        last_roll_ts=_ts(28),
    )
    assert end == _ts(30)


def test_resolve_data_end_anchors_flowing_rollups_to_last_bucket() -> None:
    end = ov._resolve_data_end_ts(
        requested_end_ts=_ts(59),
        fixed_range=False,
        stream_idle=False,
        last_activity_ts=_ts(59),
        use_ingest_rollups=True,
        last_roll_ts=_ts(58),
    )
    assert end == _ts(58)


def test_resolve_data_end_keeps_requested_end_for_fixed_range_or_no_data() -> None:
    fixed = ov._resolve_data_end_ts(
        requested_end_ts=_ts(59),
        fixed_range=True,
        stream_idle=True,
        last_activity_ts=_ts(30),
        use_ingest_rollups=False,
        last_roll_ts=None,
    )
    assert fixed == _ts(59)

    empty = ov._resolve_data_end_ts(
        requested_end_ts=_ts(59),
        fixed_range=False,
        stream_idle=True,
        last_activity_ts=None,
        use_ingest_rollups=False,
        last_roll_ts=None,
    )
    assert empty == _ts(59)


def test_max_ts_ignores_missing_candidates() -> None:
    assert ov._max_ts(None, None) is None
    assert ov._max_ts(_ts(10), None, _ts(20)) == _ts(20)


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
