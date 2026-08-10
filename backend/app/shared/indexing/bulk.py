from __future__ import annotations

from typing import Any, Dict, List, Tuple

RETRYABLE_CLIENT_STATUS = 429


def run_bulk(es: Any, actions: List[Dict[str, Any]], *, request_timeout: int) -> Tuple[int, List[Any]]:
    from elasticsearch import helpers

    return helpers.bulk(
        es,
        actions,
        request_timeout=request_timeout,
        raise_on_error=False,
        raise_on_exception=False,
    )


def is_permanent_status(status: int) -> bool:
    return 400 <= status < 500 and status != RETRYABLE_CLIENT_STATUS


def parse_bulk_errors(errors: List[Any]) -> Dict[str, Tuple[int, str]]:
    failures: Dict[str, Tuple[int, str]] = {}
    for error in errors or []:
        if not isinstance(error, dict):
            continue
        for operation, info in error.items():
            if not isinstance(info, dict):
                continue
            doc_id = info.get("_id")
            if doc_id is None:
                continue
            try:
                status = int(info.get("status") or 0)
            except (TypeError, ValueError):
                status = 0
            detail = info.get("error")
            if isinstance(detail, dict):
                reason = str(detail.get("type") or detail.get("reason") or "")[:80]
            elif detail:
                reason = str(detail)[:80]
            else:
                reason = ""
            failures[str(doc_id)] = (status, reason or str(operation))
    return failures
