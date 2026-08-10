from __future__ import annotations

from typing import Any, Dict, Optional

from app.shared.es_hosts import es_hosts


def build_es_client(
    *,
    url: str,
    request_timeout_seconds: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
    verify_certs: bool = True,
    ca_certs: Optional[str] = None,
) -> Any:
    from elasticsearch import Elasticsearch

    kwargs: Dict[str, Any] = {
        "request_timeout": request_timeout_seconds,
        "verify_certs": bool(verify_certs),
    }
    if username and password:
        kwargs["basic_auth"] = (username, password)
    if ca_certs:
        kwargs["ca_certs"] = ca_certs
    return Elasticsearch(es_hosts(url), **kwargs)
