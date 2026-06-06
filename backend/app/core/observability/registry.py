"""Prometheus metric catalogue and object lifecycle for Seagull.

This module is the single source of truth for *which* metrics exist and *how*
they are backed by ``prometheus_client`` primitives. The public emit/read API
lives in :mod:`app.core.observability.metrics`; that facade delegates here so
the rest of the codebase keeps calling ``incr_counter`` / ``observe_hist``
without knowing about Prometheus at all.

Design notes
------------
* Every metric is *declared* once with a fixed, bounded label set. The legacy
  in-memory metrics accepted arbitrary ``**labels`` per call-site, which is
  incompatible with Prometheus (a metric has a fixed label dimensionality).
  We reconcile this by declaring the *union* of label names a metric is ever
  called with and filling any label a given call-site omits with ``"none"``.
* Undeclared metric names are rejected (warn-once + no-op) on purpose: it keeps
  cardinality under control and forces new metrics to be declared here.
* Multiprocess safe. The API backend runs multiple uvicorn workers and the
  worker groups fan out into child processes, so ``PROMETHEUS_MULTIPROC_DIR``
  is used to aggregate series across processes at scrape time.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, multiprocess
from prometheus_client.registry import REGISTRY

logger = logging.getLogger("seagull.observability.metrics")

# --- Histogram bucket presets -------------------------------------------------
# Latency distributions for sub-second-to-multi-second backend/worker work.
SECONDS_BUCKETS: Tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)
# HTTP request latency is historically recorded in milliseconds.
MS_BUCKETS: Tuple[float, ...] = (
    5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000,
)
# Depth-style distributions (queue depth, batch sizes).
DEPTH_BUCKETS: Tuple[float, ...] = (
    1, 10, 50, 100, 500, 1000, 5000, 10000, 50000,
)


@dataclass(frozen=True)
class MetricSpec:
    """Declarative description of a single metric.

    ``name`` is the name as used by call-sites (e.g. ``http_requests_total``).
    For counters the trailing ``_total`` is stripped before handing the name to
    ``prometheus_client`` (which re-adds it), so the exposed series name matches
    the declared name exactly.
    """

    name: str
    kind: str  # "counter" | "gauge" | "histogram"
    documentation: str
    labelnames: Tuple[str, ...] = ()
    buckets: Optional[Tuple[float, ...]] = None
    multiproc_mode: str = "livesum"  # gauges only


def _spec(name: str, kind: str, doc: str, labels: Tuple[str, ...] = (), **kw) -> MetricSpec:
    return MetricSpec(name=name, kind=kind, documentation=doc, labelnames=labels, **kw)


# --- Metric catalogue ---------------------------------------------------------
# Grouped by domain. Labels are intentionally bounded; raw IPs, IDs, hostnames,
# paths, command lines, user identifiers etc. are never used as label values.
_SPECS: Tuple[MetricSpec, ...] = (
    # HTTP layer (emitted by app.main middleware). ``route`` is the matched
    # route template (e.g. /alerts/{alert_id}), never the raw path, and
    # ``status_class`` is the status family (2xx/3xx/4xx/5xx), not the raw code.
    _spec("http_requests_total", "counter", "HTTP requests served by the backend.",
          ("method", "route", "status_class")),
    _spec("http_request_duration_ms", "histogram", "HTTP request latency in milliseconds.",
          ("method", "route", "status_class"), buckets=MS_BUCKETS),

    # Generic API cache / route latency (events, overview, inventory features).
    _spec("api_cache_hit_total", "counter", "Cache hits served by product API routes.", ("route",)),
    _spec("api_route_latency_seconds", "histogram", "Product API route latency in seconds.",
          ("route",), buckets=SECONDS_BUCKETS),

    # Agent identity / auth lifecycle.
    _spec("agent_auth_requests_total", "counter", "Agent authentication attempts.",
          ("outcome", "reason", "method")),
    _spec("agent_bootstrap_token_consumed_total", "counter", "Agent bootstrap tokens consumed.",
          ("token_type", "outcome")),
    _spec("agent_bootstrap_token_issued_total", "counter", "Agent bootstrap tokens issued.", ("token_type",)),
    _spec("agent_bootstrap_token_admin_issue_total", "counter", "Admin-issued agent bootstrap tokens.", ("outcome",)),
    _spec("agent_identity_enroll_total", "counter", "Agent identity enrollments.", ("outcome", "token_type")),
    _spec("agent_credential_rotate_total", "counter", "Agent credential rotations.", ("outcome",)),
    _spec("agent_identity_reissue_total", "counter", "Agent identity re-issues.", ("outcome",)),
    _spec("agent_disable_total", "counter", "Agents disabled.", ("outcome",)),
    _spec("agent_enable_total", "counter", "Agents enabled.", ("outcome",)),

    # Realtime portal stream.
    _spec("realtime_publish_topic_total", "counter", "Realtime messages published per topic.", ("topic",)),
    _spec("realtime_publish_dropped_total", "counter", "Realtime publishes dropped.", ("reason",)),
    _spec("realtime_stream_connections_total", "counter", "Realtime stream connection events.",
          ("transport", "outcome")),
    _spec("realtime_stream_reconnect_total", "counter", "Realtime stream reconnects.", ("transport",)),
    _spec("realtime_stream_disconnect_total", "counter", "Realtime stream disconnects.", ("transport", "reason")),
    _spec("realtime_cursor_gap_total", "counter", "Realtime cursor gaps detected.", ("reason",)),
    _spec("realtime_unauthorized_topic_total", "counter", "Realtime unauthorized topic subscriptions.", ("transport",)),
    _spec("realtime_delivery_coalesced_total", "counter", "Realtime deliveries coalesced.", ("kind",)),

    # Ingest pipeline (worker side).
    _spec("ingest_hot_path_latency_seconds", "histogram", "Ingest hot-path processing latency in seconds.",
          buckets=SECONDS_BUCKETS),
    _spec("ingest_optional_sink_latency_seconds", "histogram", "Optional sink write latency in seconds.",
          ("sink", "outcome"), buckets=SECONDS_BUCKETS),
    _spec("ingest_optional_sink_queue_depth", "histogram", "Optional sink queue depth at enqueue time.",
          ("sink",), buckets=DEPTH_BUCKETS),
    _spec("ingest_optional_sink_dropped_total", "counter", "Events dropped from optional sinks.", ("sink", "reason")),

    # Overview live writer.
    _spec("overview_live_write_failed_total", "counter", "Overview live snapshot write failures.", ("reason",)),

    # --- Phase 2: pipeline & worker instrumentation ---

    # Ingest receive side (backend): batch/event intake and load shedding.
    _spec("ingest_batches_received_total", "counter", "Ingest batches accepted by the backend.", ("outcome",)),
    _spec("ingest_events_received_total", "counter", "Events received for ingestion."),
    _spec("ingest_events_sampled_total", "counter", "Events shed from the hot path by sampling under load."),

    # Ingest worker (processing side).
    _spec("ingest_batches_processed_total", "counter", "Ingest batches processed by the worker."),
    _spec("ingest_events_processed_total", "counter", "Events processed (acked) by the ingest worker."),
    _spec("ingest_loop_errors_total", "counter", "Ingest worker loop errors."),
    _spec("ingest_queue_depth", "gauge", "Ingest queue depth in messages.", ("queue",), multiproc_mode="mostrecent"),
    _spec("ingest_backpressure_active", "gauge", "Ingest backpressure active (1) or not (0).",
          multiproc_mode="mostrecent"),
    _spec("ingest_storm_active", "gauge", "Ingest storm active (1) or not (0).", multiproc_mode="mostrecent"),

    # Detection engine (aggregate; per-rule health is owned by the detections
    # feature's DB-backed rule health, intentionally not duplicated as labels).
    _spec("detection_cycles_total", "counter", "Detection rule cycles executed."),
    _spec("detection_cycle_duration_seconds", "histogram", "Full detection cycle duration in seconds.",
          buckets=SECONDS_BUCKETS),
    _spec("detection_rule_evaluations_total", "counter", "Rule evaluations across cycles."),
    _spec("detection_rule_matches_total", "counter", "Rule evaluations that produced at least one alert."),
    _spec("detection_rule_errors_total", "counter", "Rule evaluation errors."),
    _spec("detection_rule_eval_latency_seconds", "histogram", "Per-rule evaluation latency in seconds.",
          buckets=SECONDS_BUCKETS),

    # Alert lifecycle (universal create hook).
    _spec("alert_created_total", "counter", "Alerts created.", ("severity", "detector_type")),

    # Worker supervisor (group managers).
    _spec("worker_up", "gauge", "Worker child running (1) or not (0).",
          ("worker_group", "worker"), multiproc_mode="mostrecent"),
    _spec("worker_starts_total", "counter", "Worker child process starts (including restarts).",
          ("worker_group", "worker")),
    _spec("worker_exits_total", "counter", "Worker child process exits.", ("worker_group", "worker", "outcome")),
    _spec("worker_child_runtime_seconds", "histogram", "Worker child runtime before exit, in seconds.",
          ("worker_group", "worker"), buckets=(1, 5, 15, 30, 60, 300, 900, 1800, 3600, 86400)),
)

METRIC_SPECS: Dict[str, MetricSpec] = {s.name: s for s in _SPECS}

# --- Process / registry setup -------------------------------------------------
_LOCK = threading.Lock()
_INSTRUMENTS: Dict[str, object] = {}
_WARNED_UNKNOWN: set[str] = set()


def multiproc_dir() -> Optional[str]:
    """Return the configured Prometheus multiprocess directory, if any."""
    raw = (os.environ.get("PROMETHEUS_MULTIPROC_DIR") or "").strip()
    return raw or None


def _ensure_multiproc_dir() -> None:
    d = multiproc_dir()
    if d:
        try:
            os.makedirs(d, exist_ok=True)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("metrics_multiproc_dir_create_failed dir=%s error=%s", d, exc)


_ensure_multiproc_dir()


def _create(spec: MetricSpec):
    if spec.kind == "counter":
        # prometheus_client appends `_total`; strip it from the declared name.
        base = spec.name[:-6] if spec.name.endswith("_total") else spec.name
        return Counter(base, spec.documentation, spec.labelnames)
    if spec.kind == "histogram":
        return Histogram(spec.name, spec.documentation, spec.labelnames, buckets=spec.buckets or SECONDS_BUCKETS)
    if spec.kind == "gauge":
        return Gauge(spec.name, spec.documentation, spec.labelnames, multiprocess_mode=spec.multiproc_mode)
    raise ValueError(f"unknown metric kind: {spec.kind}")


def get_instrument(name: str) -> Tuple[Optional[MetricSpec], Optional[object]]:
    """Resolve a declared metric, creating its prometheus_client object lazily.

    Returns ``(spec, instrument)`` or ``(None, None)`` for undeclared names
    (logged once so it surfaces without spamming).
    """
    spec = METRIC_SPECS.get(name)
    if spec is None:
        if name not in _WARNED_UNKNOWN:
            _WARNED_UNKNOWN.add(name)
            logger.warning("metrics_undeclared_metric name=%s (declare it in observability/registry.py)", name)
        return None, None

    inst = _INSTRUMENTS.get(name)
    if inst is not None:
        return spec, inst

    with _LOCK:
        inst = _INSTRUMENTS.get(name)
        if inst is None:
            try:
                inst = _create(spec)
            except ValueError:
                # Already registered on the default registry (e.g. re-import in tests).
                inst = _find_existing(spec)
            _INSTRUMENTS[name] = inst
    return spec, inst


def _find_existing(spec: MetricSpec):  # pragma: no cover - defensive fallback
    base = spec.name[:-6] if (spec.kind == "counter" and spec.name.endswith("_total")) else spec.name
    collector = REGISTRY._names_to_collectors.get(base)  # type: ignore[attr-defined]
    if collector is None:
        raise RuntimeError(f"metric {spec.name} reported as duplicate but not found in registry")
    return collector


def exposition_registry() -> CollectorRegistry:
    """Return the registry to render at scrape time.

    In multiprocess mode a fresh registry is built per scrape and populated by
    the :class:`MultiProcessCollector`, aggregating every process that shares
    ``PROMETHEUS_MULTIPROC_DIR``. Otherwise the default global registry is used.
    """
    if multiproc_dir():
        reg = CollectorRegistry()
        multiprocess.MultiProcessCollector(reg)
        return reg
    return REGISTRY


def mark_process_dead(pid: int) -> None:
    """Clean up multiprocess gauge files for an exited process (no-op otherwise)."""
    if multiproc_dir():
        try:
            multiprocess.mark_process_dead(pid)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("metrics_mark_process_dead_failed pid=%s error=%s", pid, exc)
