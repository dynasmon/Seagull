from __future__ import annotations

import contextvars
import uuid

_REQUEST_ID = contextvars.ContextVar("seagull_request_id", default="")
_TRACE_ID = contextvars.ContextVar("seagull_trace_id", default="")
_SERVICE = contextvars.ContextVar("seagull_service", default="seagull")


def set_request_context(request_id: str, trace_id: str) -> None:
    _REQUEST_ID.set(request_id)
    _TRACE_ID.set(trace_id)


def clear_request_context() -> None:
    _REQUEST_ID.set("")
    _TRACE_ID.set("")


def request_id() -> str:
    return _REQUEST_ID.get()


def trace_id() -> str:
    return _TRACE_ID.get()


def service_name() -> str:
    return _SERVICE.get()


def set_service_name(service: str) -> None:
    _SERVICE.set(service)


def new_request_id() -> str:
    return str(uuid.uuid4())


def normalize_trace_id(v: str | None) -> str:
    raw = (v or "").strip()
    if not raw:
        return uuid.uuid4().hex
    return raw[:128]
