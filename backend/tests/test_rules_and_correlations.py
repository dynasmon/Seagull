from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.features.correlations.api import _segment_by_window, _stage_requirements_met
from app.workers.rules_engine import _evaluate_condition, _normalize_dedup_key


@dataclass
class _Alert:
    created_at: datetime
    rule_id: str = "r1"


def test_evaluate_condition_variants() -> None:
    assert _evaluate_condition(10, {"operator": ">=", "value": 5})
    assert _evaluate_condition(10, {"operator": ">", "value": 5})
    assert _evaluate_condition(10, {"operator": "<=", "value": 10})
    assert _evaluate_condition(10, {"operator": "==", "value": 10})
    assert _evaluate_condition(10, {"operator": "!=", "value": 9})


def test_normalize_dedup_key_rule_specific_behavior() -> None:
    assert _normalize_dedup_key("ddos_x", "1.1.1.1", "2.2.2.2", 80) == ("ddos_x", None, "2.2.2.2", 80)
    assert _normalize_dedup_key("ssh_bruteforce_x", "1.1.1.1", "2.2.2.2", 22) == (
        "ssh_bruteforce_x",
        "1.1.1.1",
        None,
        22,
    )


def test_segment_by_window_splits_on_window_limit() -> None:
    t0 = datetime(2026, 1, 1, 0, 0, 0)
    rows = [_Alert(t0), _Alert(t0 + timedelta(seconds=10)), _Alert(t0 + timedelta(seconds=70))]
    segs = _segment_by_window(rows, window_seconds=60)
    assert len(segs) == 2
    assert len(segs[0]) == 2
    assert len(segs[1]) == 1


def test_stage_requirements_met() -> None:
    hits = {"Recon": 2, "Credential": 1}
    stages = [{"name": "Recon", "min_count": 1}, {"name": "Credential", "min_count": 1}]
    assert _stage_requirements_met(hits, stages)
