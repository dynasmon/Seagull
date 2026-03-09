from app.core.observability import incr_counter, normalize_trace_id, observe_hist, snapshot_metrics


def test_normalize_trace_id_generates_when_missing() -> None:
    tid = normalize_trace_id("")
    assert isinstance(tid, str)
    assert len(tid) >= 16


def test_metrics_snapshot_collects_values() -> None:
    incr_counter("unit_counter", 1, scope="test")
    observe_hist("unit_hist", 12.5, scope="test")
    snap = snapshot_metrics()

    assert "counters" in snap
    assert "histograms" in snap
    assert any(x["name"] == "unit_counter" for x in snap["counters"])
    assert any(x["name"] == "unit_hist" for x in snap["histograms"])
