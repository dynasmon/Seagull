from app.core.observability import (
    incr_counter,
    normalize_trace_id,
    observe_hist,
    render_exposition,
    snapshot_metrics,
)


def test_normalize_trace_id_generates_when_missing() -> None:
    tid = normalize_trace_id("")
    assert isinstance(tid, str)
    assert len(tid) >= 16


def test_metrics_snapshot_collects_declared_values() -> None:
    incr_counter("http_requests_total", method="GET", route="/unit/{id}", status_class="2xx")
    observe_hist("http_request_duration_ms", 12.5, method="GET", route="/unit/{id}", status_class="2xx")
    snap = snapshot_metrics()

    assert "counters" in snap
    assert "histograms" in snap
    assert any(x["name"] == "http_requests_total" for x in snap["counters"])
    assert any(x["name"] == "http_request_duration_ms" for x in snap["histograms"])


def test_heterogeneous_labels_are_reconciled() -> None:
    # Same metric, different call-site label sets — declared as the union; the
    # omitted label is filled with "none" rather than raising.
    incr_counter("agent_auth_requests_total", outcome="failure", reason="expired")
    incr_counter("agent_auth_requests_total", outcome="success", method="credential")

    body, content_type = render_exposition()
    text = body.decode()
    assert "text/plain" in content_type
    assert 'agent_auth_requests_total{method="none",outcome="failure",reason="expired"}' in text
    assert 'agent_auth_requests_total{method="credential",outcome="success",reason="none"}' in text


def test_undeclared_metric_is_ignored() -> None:
    # Undeclared names are a no-op (warn-once) to keep cardinality bounded.
    incr_counter("totally_undeclared_metric_total", foo="bar")
    snap = snapshot_metrics()
    assert not any(x["name"].startswith("totally_undeclared_metric") for x in snap["counters"])
