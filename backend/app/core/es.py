"""Elasticsearch client helpers.

We keep Postgres as source-of-truth. Elasticsearch is used as a scalable read
backend for event hunting and aggregations.

The API can be configured via NETWATCH_SEARCH_BACKEND:
- auto: use ES if available, otherwise fallback to Postgres
- elasticsearch: require ES (return 503 if unavailable)
- postgres: always use Postgres
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from app.core.config import settings


_es_client = None
_last_ping_at: float = 0.0
_last_ping_ok: bool = False


def _build_es_client():
    from elasticsearch import Elasticsearch

    kwargs: Dict[str, Any] = {
        "request_timeout": int(getattr(settings, "NETWATCH_ES_REQUEST_TIMEOUT_SECONDS", 30) or 30),
    }

    username = getattr(settings, "NETWATCH_ES_USERNAME", None)
    password = getattr(settings, "NETWATCH_ES_PASSWORD", None)
    if username and password:
        kwargs["basic_auth"] = (username, password)

    kwargs["verify_certs"] = bool(getattr(settings, "NETWATCH_ES_VERIFY_CERTS", True))
    ca_certs = getattr(settings, "NETWATCH_ES_CA_CERTS", None)
    if ca_certs:
        kwargs["ca_certs"] = ca_certs

    return Elasticsearch(getattr(settings, "NETWATCH_ES_URL", "http://elasticsearch:9200"), **kwargs)


def get_es_client():
    global _es_client
    if _es_client is None:
        _es_client = _build_es_client()
    return _es_client


def es_is_available() -> bool:
    """Ping ES with a small in-process cache to avoid a ping per request."""

    global _last_ping_at, _last_ping_ok

    ttl = int(getattr(settings, "NETWATCH_ES_PING_TTL_SECONDS", 2) or 2)
    now = time.time()

    if (now - _last_ping_at) < max(1, ttl):
        return _last_ping_ok

    _last_ping_at = now

    try:
        _last_ping_ok = bool(get_es_client().ping())
    except Exception:
        _last_ping_ok = False

    return _last_ping_ok


def search_backend_mode() -> str:
    return (getattr(settings, "NETWATCH_SEARCH_BACKEND", "auto") or "auto").strip().lower()
