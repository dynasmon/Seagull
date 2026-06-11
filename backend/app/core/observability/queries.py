from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from app.core.integrations import prometheus as prom
from app.core.integrations.prometheus import QueryResponse

RATE_WINDOWS: Tuple[str, ...] = ("1m", "5m", "15m", "1h")
DEFAULT_WINDOW = "5m"

MIN_STEP_SECONDS = 15
MIN_RANGE_SECONDS = 60
MAX_RANGE_SECONDS = 7 * 24 * 60 * 60
MAX_POINTS = 1500


class QueryValidationError(ValueError):
    pass


@dataclass(frozen=True)
class QuerySpec:

    key: str
    title: str
    description: str
    unit: str
    builder: Callable[[str], str]
    requires_window: bool = True
    allow_instant: bool = True
    allow_range: bool = True


def _quantile_builder(metric_base: str, quantile: float) -> Callable[[str], str]:

    def build(window: str) -> str:
        return f"histogram_quantile({quantile}, sum(rate({metric_base}_bucket[{window}])) by (le))"

    return build


def _gauge(expr: str) -> Callable[[str], str]:

    def build(_window: str) -> str:
        return expr

    return build


_SPECS: Tuple[QuerySpec, ...] = (
    QuerySpec(
        "http_request_rate", "HTTP request rate", "Requests served per second across the backend.",
        "ops", lambda w: f"sum(rate(http_requests_total[{w}]))",
    ),
    QuerySpec(
        "http_error_ratio", "HTTP 5xx ratio", "Fraction of requests returning a 5xx status.",
        "ratio",
        lambda w: f"(sum(rate(http_requests_total{{status_class=\"5xx\"}}[{w}])) or vector(0)) / sum(rate(http_requests_total[{w}]))",
    ),
    QuerySpec(
        "http_latency_p95_ms", "HTTP latency p95", "95th percentile request latency.",
        "ms", _quantile_builder("http_request_duration_ms", 0.95),
    ),
    QuerySpec(
        "http_latency_p99_ms", "HTTP latency p99", "99th percentile request latency.",
        "ms", _quantile_builder("http_request_duration_ms", 0.99),
    ),
    QuerySpec(
        "ingest_events_received_rate", "Events received/s", "Events accepted for ingestion per second.",
        "ops", lambda w: f"sum(rate(ingest_events_received_total[{w}]))",
    ),
    QuerySpec(
        "ingest_events_processed_rate", "Events processed/s", "Events processed (acked) by ingest workers per second.",
        "ops", lambda w: f"sum(rate(ingest_events_processed_total[{w}]))",
    ),
    QuerySpec(
        "ingest_events_sampled_rate", "Events shed/s", "Events shed from the hot path by sampling under load.",
        "ops", lambda w: f"sum(rate(ingest_events_sampled_total[{w}]))",
    ),
    QuerySpec(
        "ingest_hot_path_p95_seconds", "Ingest hot-path p95", "95th percentile ingest hot-path latency.",
        "seconds", _quantile_builder("ingest_hot_path_latency_seconds", 0.95),
    ),
    QuerySpec(
        "ingest_queue_depth", "Ingest queue depth", "Current total ingest queue depth (messages).",
        "count", _gauge("sum(ingest_queue_depth)"), requires_window=False,
    ),
    QuerySpec(
        "ingest_backpressure_active", "Backpressure active", "Whether ingest backpressure is currently engaged.",
        "bool", _gauge("max(ingest_backpressure_active)"), requires_window=False,
    ),
    QuerySpec(
        "ingest_storm_active", "Storm active", "Whether an ingest storm is currently active.",
        "bool", _gauge("max(ingest_storm_active)"), requires_window=False,
    ),
    QuerySpec(
        "detection_cycle_rate", "Detection cycles/s", "Detection rule cycles executed per second.",
        "ops", lambda w: f"sum(rate(detection_cycles_total[{w}]))",
    ),
    QuerySpec(
        "detection_cycle_p95_seconds", "Detection cycle p95", "95th percentile full detection cycle duration.",
        "seconds", _quantile_builder("detection_cycle_duration_seconds", 0.95),
    ),
    QuerySpec(
        "detection_rule_eval_rate", "Rule evaluations/s", "Rule evaluations across cycles per second.",
        "ops", lambda w: f"sum(rate(detection_rule_evaluations_total[{w}]))",
    ),
    QuerySpec(
        "detection_rule_match_rate", "Rule matches/s", "Rule evaluations producing at least one alert per second.",
        "ops", lambda w: f"sum(rate(detection_rule_matches_total[{w}]))",
    ),
    QuerySpec(
        "detection_rule_error_rate", "Rule errors/s", "Rule evaluation errors per second.",
        "ops", lambda w: f"sum(rate(detection_rule_errors_total[{w}]))",
    ),
    QuerySpec(
        "alert_created_rate", "Alerts created/s", "Alerts created per second across all detectors.",
        "ops", lambda w: f"sum(rate(alert_created_total[{w}]))",
    ),
    QuerySpec(
        "alert_created_rate_by_severity", "Alerts created/s by severity",
        "Alerts created per second, split by severity.",
        "ops", lambda w: f"sum by (severity) (rate(alert_created_total[{w}]))",
    ),
    QuerySpec(
        "workers_up", "Workers up", "Total worker child processes currently running.",
        "count", _gauge("sum(worker_up)"), requires_window=False,
    ),
    QuerySpec(
        "workers_up_by_group", "Workers up by group", "Running worker child processes, split by group.",
        "count", _gauge("sum by (worker_group) (worker_up)"), requires_window=False,
    ),
    QuerySpec(
        "worker_start_rate", "Worker starts/s", "Worker child process starts (incl. restarts) per second.",
        "ops", lambda w: f"sum(rate(worker_starts_total[{w}]))",
    ),
    QuerySpec(
        "worker_exit_rate_by_outcome", "Worker exits/s by outcome", "Worker child exits per second, split by outcome.",
        "ops", lambda w: f"sum by (outcome) (rate(worker_exits_total[{w}]))",
    ),
)

CATALOGUE: Dict[str, QuerySpec] = {s.key: s for s in _SPECS}


def get_spec(key: str) -> Optional[QuerySpec]:
    return CATALOGUE.get(key)


def _spec_kinds(spec: QuerySpec) -> List[str]:
    kinds: List[str] = []
    if spec.allow_instant:
        kinds.append("instant")
    if spec.allow_range:
        kinds.append("range")
    return kinds


def list_query_catalogue() -> List[dict]:
    out: List[dict] = []
    for key in sorted(CATALOGUE):
        spec = CATALOGUE[key]
        out.append(
            {
                "key": spec.key,
                "title": spec.title,
                "description": spec.description,
                "unit": spec.unit,
                "kinds": _spec_kinds(spec),
                "requires_window": bool(spec.requires_window),
            }
        )
    return out


def validate_window(window: Optional[str]) -> str:
    w = (window or "").strip() or DEFAULT_WINDOW
    if w not in RATE_WINDOWS:
        allowed = ", ".join(RATE_WINDOWS)
        raise QueryValidationError(f"invalid window '{w}' (allowed: {allowed})")
    return w


def _format_duration(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def rate_window_for_step(step_seconds: float) -> str:
    window = max(MIN_RANGE_SECONDS, int(math.ceil(step_seconds)) * 4)
    window = min(window, 3600)
    return _format_duration(window)


def resolve_range(start: float, end: float, step: Optional[float] = None) -> Tuple[float, float, float]:
    try:
        s = float(start)
        e = float(end)
    except (TypeError, ValueError) as exc:
        raise QueryValidationError("start and end must be numeric epoch seconds") from exc

    if not math.isfinite(s) or not math.isfinite(e):
        raise QueryValidationError("start and end must be finite")
    if e <= s:
        raise QueryValidationError("end must be after start")

    span = e - s
    if span > MAX_RANGE_SECONDS:
        raise QueryValidationError(f"range too large ({int(span)}s > max {MAX_RANGE_SECONDS}s)")

    if step is None:
        derived = max(MIN_STEP_SECONDS, math.ceil(span / MAX_POINTS))
        st = float(math.ceil(derived / MIN_STEP_SECONDS) * MIN_STEP_SECONDS)
    else:
        try:
            st = float(step)
        except (TypeError, ValueError) as exc:
            raise QueryValidationError("step must be numeric seconds") from exc
        if not math.isfinite(st) or st < MIN_STEP_SECONDS:
            raise QueryValidationError(f"step too small (min {MIN_STEP_SECONDS}s)")
        if span / st > MAX_POINTS:
            raise QueryValidationError(f"too many points (max {MAX_POINTS}); increase step or shorten range")

    return s, e, st


def _finite(value: float):
    return value if isinstance(value, (int, float)) and math.isfinite(value) else None


@dataclass(frozen=True)
class QueryResult:
    key: str
    title: str
    unit: str
    kind: str
    response: QueryResponse

    def to_dict(self) -> dict:
        out: dict = {
            "key": self.key,
            "title": self.title,
            "unit": self.unit,
            "kind": self.kind,
            "result_type": self.response.result_type,
        }
        if self.kind == "range":
            out["series"] = [
                {"metric": s.metric, "points": [[ts, _finite(v)] for ts, v in s.points]}
                for s in self.response.series
            ]
        else:
            out["samples"] = [
                {"metric": s.metric, "value": _finite(s.value), "timestamp": s.timestamp}
                for s in self.response.samples
            ]
        return out


def _require_spec(key: str) -> QuerySpec:
    spec = CATALOGUE.get(key)
    if spec is None:
        raise QueryValidationError(f"unknown query '{key}'")
    return spec


def run_instant(key: str, *, window: Optional[str] = None) -> QueryResult:
    spec = _require_spec(key)
    if not spec.allow_instant:
        raise QueryValidationError(f"query '{key}' does not support instant evaluation")
    w = validate_window(window) if spec.requires_window else DEFAULT_WINDOW
    promql = spec.builder(w)
    response = prom.instant_query(promql)
    return QueryResult(key=spec.key, title=spec.title, unit=spec.unit, kind="instant", response=response)


def run_range(
    key: str,
    *,
    start: float,
    end: float,
    step: Optional[float] = None,
    window: Optional[str] = None,
) -> QueryResult:
    spec = _require_spec(key)
    if not spec.allow_range:
        raise QueryValidationError(f"query '{key}' does not support range evaluation")
    s, e, st = resolve_range(start, end, step)
    if not spec.requires_window:
        w = DEFAULT_WINDOW
    elif window:
        w = validate_window(window)
    else:
        w = rate_window_for_step(st)
    promql = spec.builder(w)
    response = prom.range_query(promql, start=s, end=e, step=st)
    return QueryResult(key=spec.key, title=spec.title, unit=spec.unit, kind="range", response=response)
