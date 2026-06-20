
from __future__ import annotations

from typing import Any, Dict, Tuple

from prometheus_client import CONTENT_TYPE_LATEST, generate_latest, start_http_server

from .context import service_name
from .registry import exposition_registry, get_instrument

# Re-exported so callers can set the response content type for the scrape route.
METRICS_CONTENT_TYPE = CONTENT_TYPE_LATEST


def _label_values(labelnames: Tuple[str, ...], labels: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name in labelnames:
        value = labels.get(name, None)
        if value is None or value == "":
            out[name] = "none"
        else:
            out[name] = str(value)[:128]
    return out


def _bound(instrument: object, spec_labelnames: Tuple[str, ...], labels: Dict[str, Any]):
    if not spec_labelnames:
        return instrument
    return instrument.labels(**_label_values(spec_labelnames, labels))  # type: ignore[attr-defined]


def incr_counter(name: str, value: float = 1.0, **labels: Any) -> None:
    spec, instrument = get_instrument(name)
    if spec is None or instrument is None:
        return
    try:
        _bound(instrument, spec.labelnames, labels).inc(float(value))  # type: ignore[union-attr]
    except Exception:
        # Metrics must never break a request/worker path.
        pass


def init_counter(name: str, **labels: Any) -> None:
    incr_counter(name, 0.0, **labels)


def observe_hist(name: str, value: float, **labels: Any) -> None:
    spec, instrument = get_instrument(name)
    if spec is None or instrument is None:
        return
    try:
        _bound(instrument, spec.labelnames, labels).observe(float(value))  # type: ignore[union-attr]
    except Exception:
        pass


def set_gauge(name: str, value: float, **labels: Any) -> None:
    spec, instrument = get_instrument(name)
    if spec is None or instrument is None:
        return
    try:
        _bound(instrument, spec.labelnames, labels).set(float(value))  # type: ignore[union-attr]
    except Exception:
        pass


def render_exposition() -> Tuple[bytes, str]:
    return generate_latest(exposition_registry()), METRICS_CONTENT_TYPE


def start_metrics_server(port: int, addr: str = "0.0.0.0") -> None:
    start_http_server(port, addr=addr, registry=exposition_registry())


def snapshot_metrics() -> dict[str, Any]:
    counters: list[dict[str, Any]] = []
    gauges: list[dict[str, Any]] = []
    hist_acc: dict[tuple[str, tuple[tuple[str, str], ...]], dict[str, float]] = {}

    for family in exposition_registry().collect():
        ftype = getattr(family, "type", "")
        if ftype == "counter":
            for sample in family.samples:
                if sample.name.endswith("_total"):
                    counters.append(
                        {"name": sample.name, "labels": dict(sample.labels), "value": float(sample.value)}
                    )
        elif ftype == "gauge":
            for sample in family.samples:
                gauges.append(
                    {"name": sample.name, "labels": dict(sample.labels), "value": float(sample.value)}
                )
        elif ftype == "histogram":
            for sample in family.samples:
                if sample.name.endswith("_bucket"):
                    continue
                key_labels = tuple(sorted((k, v) for k, v in sample.labels.items() if k != "le"))
                acc = hist_acc.setdefault((family.name, key_labels), {"count": 0.0, "sum": 0.0})
                if sample.name.endswith("_count"):
                    acc["count"] = float(sample.value)
                elif sample.name.endswith("_sum"):
                    acc["sum"] = float(sample.value)

    histograms: list[dict[str, Any]] = []
    for (name, key_labels), acc in hist_acc.items():
        count = acc["count"]
        total = acc["sum"]
        histograms.append(
            {
                "name": name,
                "labels": {k: v for k, v in key_labels},
                "count": count,
                "sum": total,
                "min": 0.0,
                "max": 0.0,
                "avg": (total / count) if count > 0 else 0.0,
            }
        )

    counters.sort(key=lambda r: r["name"])
    histograms.sort(key=lambda r: r["name"])
    gauges.sort(key=lambda r: r["name"])

    return {
        "service": service_name(),
        "counters": counters,
        "histograms": histograms,
        "gauges": gauges,
    }
