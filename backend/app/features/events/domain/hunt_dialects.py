from __future__ import annotations

import re
from typing import Any, Dict, Literal, Mapping, Optional, Tuple, cast

HuntDialect = Literal["simple", "kql", "eql"]

HUNT_DIALECTS: Tuple[str, ...] = ("simple", "kql", "eql")

EQL_ENDPOINT_HINT = "EQL queries are served by POST /api/events/hunt/eql"

_DIALECT_PREFIX_PATTERN = re.compile(r"^\s*(simple|kql|eql)\s*:\s*", re.IGNORECASE)
_LINE_COLUMN_PATTERN = re.compile(r"line\s+(\d+):(\d+):?\s*(.*)", re.DOTALL)
_UNKNOWN_COLUMN_PATTERN = re.compile(r"Unknown column \[([^\]]+)\]")
_TIMEOUT_MARKERS: Tuple[str, ...] = ("timeout", "timed out", "timed_out")
_SYNTAX_ERROR_TYPES: Tuple[str, ...] = ("parsing_exception", "eql_illegal_argument_exception")


class HuntQueryError(ValueError):
    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def resolve_hunt_dialect(
    *,
    search: Optional[str],
    search_dialect: Optional[str],
) -> Tuple[HuntDialect, Optional[str]]:
    requested = (search_dialect or "").strip().lower() or None
    if requested is not None and requested not in HUNT_DIALECTS:
        raise HuntQueryError(
            f"Unknown search dialect '{requested}'. Supported dialects: {', '.join(HUNT_DIALECTS)}",
            reason="unknown_dialect",
        )
    text: Optional[str] = None if search is None else str(search)
    match = _DIALECT_PREFIX_PATTERN.match(text) if text else None
    prefixed = match.group(1).lower() if match else None
    dialect = requested if requested is not None else (prefixed or "simple")
    if match is not None and text is not None and prefixed == dialect:
        text = text[match.end():]
    return cast(HuntDialect, dialect), text


def _es_error_body(exc: Exception) -> Dict[str, Any]:
    for attr in ("body", "info"):
        value = getattr(exc, attr, None)
        if isinstance(value, dict):
            return value
    return {}


def _es_root_cause(body: Mapping[str, Any]) -> Tuple[str, str]:
    error = body.get("error")
    if not isinstance(error, Mapping):
        return "", ""
    causes = error.get("root_cause")
    first: Mapping[str, Any] = error
    if isinstance(causes, list) and causes and isinstance(causes[0], Mapping):
        first = causes[0]
    return str(first.get("type") or ""), str(first.get("reason") or "")


def translate_es_query_error(exc: Exception, *, dialect: str) -> HuntQueryError:
    if isinstance(exc, HuntQueryError):
        return exc
    label = dialect.upper()
    error_type, error_reason = _es_root_cause(_es_error_body(exc))

    if error_type in _SYNTAX_ERROR_TYPES:
        located = _LINE_COLUMN_PATTERN.search(error_reason)
        if located:
            return HuntQueryError(
                f"{label} syntax error at line {located.group(1)}, column {located.group(2)}: "
                f"{located.group(3).strip() or error_reason}",
                reason="syntax",
            )
        return HuntQueryError(
            f"{label} syntax error: {error_reason or 'malformed query'}",
            reason="syntax",
        )

    if error_type == "verification_exception":
        unknown = _UNKNOWN_COLUMN_PATTERN.search(error_reason)
        if unknown:
            return HuntQueryError(
                f"Unknown field '{unknown.group(1)}' in {label} query",
                reason="unknown_field",
            )
        return HuntQueryError(
            f"{label} query failed validation: {error_reason or 'invalid query'}",
            reason="syntax",
        )

    haystack = f"{type(exc).__name__}: {exc}".lower()
    if any(marker in haystack for marker in _TIMEOUT_MARKERS):
        return HuntQueryError(f"{label} query timed out against Elasticsearch", reason="timeout")

    status = getattr(exc, "status_code", None)
    if isinstance(status, int) and 400 <= status < 500:
        return HuntQueryError(
            f"Elasticsearch rejected the {label} query: {error_reason or error_type or 'bad request'}",
            reason="rejected",
        )
    return HuntQueryError("Elasticsearch is unavailable for this query", reason="es_unavailable")
