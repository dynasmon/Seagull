
from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")

from datetime import datetime
from types import SimpleNamespace

from app.workers.intelligence.rules.health import (
    RuleExecResult,
    _build_record,
    _content_hash,
    build_health_records,
)


def _existing(consecutive_failures: int = 0, last_success_at=None, last_error_at=None):
    return SimpleNamespace(
        consecutive_failures=consecutive_failures,
        last_success_at=last_success_at,
        last_error_at=last_error_at,
    )


NOW = datetime(2026, 5, 6, 12, 0, 0)

_BASE_RESULT = dict(
    rule_id="test_rule_v1",
    rule_version=1,
    content_hash="abc123",
    duration_ms=12,
)


def test_healthy_status_on_success():
    result = RuleExecResult(**_BASE_RESULT, alerts_created=2)
    record = _build_record(result, None, NOW)

    assert record["status"] == "healthy"
    assert record["consecutive_failures"] == 0
    assert record["last_success_at"] == NOW
    assert record["last_error_at"] is None
    assert record["alerts_created"] == 2
    assert record["error_type"] is None
    assert record["error_message"] is None


def test_healthy_resets_consecutive_failures():
    result = RuleExecResult(**_BASE_RESULT)
    record = _build_record(result, _existing(consecutive_failures=5), NOW)

    assert record["status"] == "healthy"
    assert record["consecutive_failures"] == 0


def test_healthy_preserves_last_error_at():
    past = datetime(2026, 5, 5, 0, 0, 0)
    result = RuleExecResult(**_BASE_RESULT)
    record = _build_record(result, _existing(last_error_at=past), NOW)

    assert record["last_error_at"] == past
    assert record["last_success_at"] == NOW


def test_first_failure_is_degraded():
    exc = ValueError("bad filter")
    result = RuleExecResult(**_BASE_RESULT, error=exc)
    record = _build_record(result, None, NOW)

    assert record["status"] == "degraded"
    assert record["consecutive_failures"] == 1
    assert record["last_error_at"] == NOW
    assert record["last_success_at"] is None
    assert record["error_type"] == "ValueError"
    assert "bad filter" in record["error_message"]


def test_second_failure_is_still_degraded():
    exc = RuntimeError("crash")
    result = RuleExecResult(**_BASE_RESULT, error=exc)
    record = _build_record(result, _existing(consecutive_failures=1), NOW)

    assert record["status"] == "degraded"
    assert record["consecutive_failures"] == 2


def test_third_failure_transitions_to_failing():
    exc = RuntimeError("crash")
    result = RuleExecResult(**_BASE_RESULT, error=exc)
    record = _build_record(result, _existing(consecutive_failures=2), NOW)

    assert record["status"] == "failing"
    assert record["consecutive_failures"] == 3


def test_failure_preserves_last_success_at():
    past = datetime(2026, 5, 1, 0, 0, 0)
    exc = Exception("oops")
    result = RuleExecResult(**_BASE_RESULT, error=exc)
    record = _build_record(result, _existing(last_success_at=past), NOW)

    assert record["last_success_at"] == past


def test_disabled_status():
    result = RuleExecResult(**_BASE_RESULT, disabled=True)
    record = _build_record(result, None, NOW)

    assert record["status"] == "disabled"
    assert record["consecutive_failures"] == 0
    assert record["error_type"] is None


def test_build_health_records_batch():
    results = [
        RuleExecResult(**{**_BASE_RESULT, "rule_id": "rule_a_v1"}, alerts_created=1),
        RuleExecResult(**{**_BASE_RESULT, "rule_id": "rule_b_v1"}, error=ValueError("x")),
    ]
    records = build_health_records(results, {}, NOW)

    assert len(records) == 2
    by_id = {r["rule_id"]: r for r in records}
    assert by_id["rule_a_v1"]["status"] == "healthy"
    assert by_id["rule_b_v1"]["status"] == "degraded"


def test_content_hash_is_stable():
    rule = {"id": "x_v1", "type": "aggregate_count", "window": "5m"}
    h1 = _content_hash(rule)
    h2 = _content_hash(rule)
    assert h1 == h2
    assert len(h1) == 16


def test_content_hash_differs_for_different_rules():
    r1 = {"id": "x_v1", "window": "5m"}
    r2 = {"id": "x_v1", "window": "10m"}
    assert _content_hash(r1) != _content_hash(r2)


def test_error_message_is_truncated_at_512():
    long_msg = "x" * 1000
    exc = Exception(long_msg)
    result = RuleExecResult(**_BASE_RESULT, error=exc)
    record = _build_record(result, None, NOW)
    assert len(record["error_message"]) == 512
