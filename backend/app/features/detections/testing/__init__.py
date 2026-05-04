from __future__ import annotations

from app.features.detections.testing.backtest import (
    DEFAULT_SAMPLE_LIMIT,
    backtest_detection_rule,
    run_detection_backtest,
)
from app.features.detections.testing.fixtures import (
    netevent_row_to_document,
    normalize_event_document,
)
from app.features.detections.testing.quality import (
    collect_quality_warnings,
    validate_detection_content,
)
from app.features.detections.testing.yaml_tests import (
    build_rule_execution_spec,
    evaluate_detection_rule,
    run_rule_yaml_tests,
    run_yaml_rule_suite,
)

__all__ = [
    "DEFAULT_SAMPLE_LIMIT",
    "backtest_detection_rule",
    "build_rule_execution_spec",
    "collect_quality_warnings",
    "evaluate_detection_rule",
    "netevent_row_to_document",
    "normalize_event_document",
    "run_detection_backtest",
    "run_rule_yaml_tests",
    "run_yaml_rule_suite",
    "validate_detection_content",
]
