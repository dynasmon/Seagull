from __future__ import annotations

import contextvars
import json
import logging
import os
import threading
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, Tuple

from app.core.config import settings
from app.core.env_secrets import getenv_compat

_REQUEST_ID = contextvars.ContextVar("seagull_request_id", default="")
_TRACE_ID = contextvars.ContextVar("seagull_trace_id", default="")
_SERVICE = contextvars.ContextVar("seagull_service", default="seagull")

_METRIC_LOCK = threading.Lock()
_COUNTERS: dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = defaultdict(float)
_HIST: dict[Tuple[str, Tuple[Tuple[str, str], ...]], dict[str, float]] = defaultdict(
    lambda: {"count": 0.0, "sum": 0.0, "min": 0.0, "max": 0.0}
)


def _labels_tuple(labels: Dict[str, Any]) -> Tuple[Tuple[str, str], ...]:
    out = []
    for k in sorted(labels.keys()):
        out.append((str(k), str(labels[k])))
    return tuple(out)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "logger": record.name,
            "service": _SERVICE.get(),
            "message": record.getMessage(),
        }

        rid = _REQUEST_ID.get()
        tid = _TRACE_ID.get()
        if rid:
            payload["request_id"] = rid
        if tid:
            payload["trace_id"] = tid

        event = getattr(record, "event", None)
        if event:
            payload["event"] = event

        worker_process = (getenv_compat("SEAGULL_WORKER_PROCESS", "") or "").strip()
        if worker_process:
            payload["worker_process"] = worker_process

        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=True, default=str)


_LOGGING_READY = False


def setup_logging(service: str) -> None:
    global _LOGGING_READY
    _SERVICE.set(service)
    if _LOGGING_READY:
        return

    level_name = (settings.SEAGULL_LOG_LEVEL or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)

    _LOGGING_READY = True


def set_request_context(request_id: str, trace_id: str) -> None:
    _REQUEST_ID.set(request_id)
    _TRACE_ID.set(trace_id)


def clear_request_context() -> None:
    _REQUEST_ID.set("")
    _TRACE_ID.set("")


def request_id() -> str:
    return _REQUEST_ID.get()


def new_request_id() -> str:
    return str(uuid.uuid4())


def normalize_trace_id(v: str | None) -> str:
    raw = (v or "").strip()
    if not raw:
        return uuid.uuid4().hex
    return raw[:128]


def log_event(logger: logging.Logger, level: str, event: str, **fields: Any) -> None:
    extra = {"event": event, "fields": fields}
    lvl = (level or "info").lower()
    if lvl == "debug":
        logger.debug(event, extra=extra)
    elif lvl == "warning" or lvl == "warn":
        logger.warning(event, extra=extra)
    elif lvl == "error":
        logger.error(event, extra=extra)
    else:
        logger.info(event, extra=extra)


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
        for (name, labels), value in sorted(_COUNTERS.items(), key=lambda x: x[0][0]):
            counters.append(
                {
                    "name": name,
                    "labels": {k: v for k, v in labels},
                    "value": value,
                }
            )

        for (name, labels), stats in sorted(_HIST.items(), key=lambda x: x[0][0]):
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
        "service": _SERVICE.get(),
        "counters": counters,
        "histograms": histograms,
    }
