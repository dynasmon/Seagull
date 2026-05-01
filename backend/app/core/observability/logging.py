from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict

from app.core.config import settings
from app.core.config.env_secrets import getenv_compat

from .context import request_id, service_name, set_service_name, trace_id


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "logger": record.name,
            "service": service_name(),
            "message": record.getMessage(),
        }

        rid = request_id()
        tid = trace_id()
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

    set_service_name(service)
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


def log_event(logger: logging.Logger, level: str, event: str, **fields: Any) -> None:
    extra = {"event": event, "fields": fields}
    lvl = (level or "info").lower()
    if lvl == "debug":
        logger.debug(event, extra=extra)
    elif lvl in {"warning", "warn"}:
        logger.warning(event, extra=extra)
    elif lvl == "error":
        logger.error(event, extra=extra)
    else:
        logger.info(event, extra=extra)
