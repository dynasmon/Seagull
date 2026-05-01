from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any, Dict, Tuple

from .context import service_name


_METRIC_LOCK = threading.Lock()
_COUNTERS: dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = defaultdict(float)
_HIST: dict[Tuple[str, Tuple[Tuple[str, str], ...]], dict[str, float]] = defaultdict(
    lambda: {"count": 0.0, "sum": 0.0, "min": 0.0, "max": 0.0}
)


def _labels_tuple(labels: Dict[str, Any]) -> Tuple[Tuple[str, str], ...]:
    return tuple((str(key), str(labels[key])) for key in sorted(labels.keys()))


def incr_counter(name: str, value: float = 1.0, **labels: Any) -> None:
    key = (name, _labels_tuple(labels))
    with _METRIC_LOCK:
        _COUNTERS[key] += float(value)


def observe_hist(name: str, value: float, **labels: Any) -> None:
    key = (name, _labels_tuple(labels))
    v = float(value)
    with _METRIC_LOCK:
        cur = _HIST[key]
        cur["count"] += 1.0
        cur["sum"] += v
        if cur["count"] == 1.0:
            cur["min"] = v
            cur["max"] = v
        else:
            cur["min"] = min(cur["min"], v)
            cur["max"] = max(cur["max"], v)


def snapshot_metrics() -> dict[str, Any]:
    counters = []
    histograms = []

    with _METRIC_LOCK:
        for (name, labels), value in sorted(_COUNTERS.items(), key=lambda item: item[0][0]):
            counters.append(
                {
                    "name": name,
                    "labels": {k: v for k, v in labels},
                    "value": value,
                }
            )

        for (name, labels), stats in sorted(_HIST.items(), key=lambda item: item[0][0]):
            avg = (stats["sum"] / stats["count"]) if stats["count"] > 0 else 0.0
            histograms.append(
                {
                    "name": name,
                    "labels": {k: v for k, v in labels},
                    "count": stats["count"],
                    "sum": stats["sum"],
                    "min": stats["min"],
                    "max": stats["max"],
                    "avg": avg,
                }
            )

    return {
        "service": service_name(),
        "counters": counters,
        "histograms": histograms,
    }
