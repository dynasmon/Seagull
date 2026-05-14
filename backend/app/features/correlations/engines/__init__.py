from __future__ import annotations

from typing import Any

from app.features.correlations.engines.base import (
    CorrelationDataset,
    compute_stage_hits,
    group_value,
    match_any,
    norm_patterns,
    passes_filter,
    segment_by_window,
    stage_requirements_met,
)
from app.features.correlations.engines.cardinality import CardinalityEngine
from app.features.correlations.engines.entity_state import NewEntityEngine, RareEntityEngine
from app.features.correlations.engines.risk_aggregation import RiskAggregationEngine
from app.features.correlations.engines.sequence import SequenceEngine
from app.features.correlations.engines.temporal_join import TemporalJoinEngine
from app.features.correlations.engines.threshold import ThresholdEngine

_ENGINE_BY_STRATEGY = {
    "threshold": ThresholdEngine(),
    "burst": ThresholdEngine(compatibility_mode=True),
    "cardinality": CardinalityEngine(),
    "sequence": SequenceEngine(),
    "chain": SequenceEngine(compatibility_mode=True),
    "temporal_join": TemporalJoinEngine(),
    "risk_aggregation": RiskAggregationEngine(),
    "new_entity": NewEntityEngine(),
    "rare_entity": RareEntityEngine(),
}


def get_engine(strategy: str | None):
    key = str(strategy or "burst").strip().lower()
    return _ENGINE_BY_STRATEGY.get(key) or _ENGINE_BY_STRATEGY["threshold"]


def build_incidents(
    rules: list[Any],
    alerts: list[Any],
    sample_limit: int,
    dataset: CorrelationDataset | None = None,
):
    runtime_dataset = dataset or CorrelationDataset(alerts=list(alerts or []))
    if not runtime_dataset.alerts:
        runtime_dataset.alerts = list(alerts or [])

    incidents = []
    for rule in rules:
        engine = get_engine(getattr(rule, "strategy", None))
        for match in engine.build(rule=rule, dataset=runtime_dataset, sample_limit=sample_limit):
            incidents.append(match.to_out())

    incidents.sort(key=lambda item: item.started_at, reverse=True)
    return incidents


__all__ = [
    "CorrelationDataset",
    "build_incidents",
    "compute_stage_hits",
    "group_value",
    "match_any",
    "norm_patterns",
    "passes_filter",
    "segment_by_window",
    "stage_requirements_met",
]
