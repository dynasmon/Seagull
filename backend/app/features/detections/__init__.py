from __future__ import annotations

from app.features.detections.rules.loader import load_and_validate_rules, load_rules


def run_detection_backtest(*args, **kwargs):
    from app.features.detections.testing import run_detection_backtest as _run_detection_backtest

    return _run_detection_backtest(*args, **kwargs)


def validate_detection_content(*args, **kwargs):
    from app.features.detections.testing import validate_detection_content as _validate_detection_content

    return _validate_detection_content(*args, **kwargs)

__all__ = ["load_and_validate_rules", "load_rules", "run_detection_backtest", "validate_detection_content"]
