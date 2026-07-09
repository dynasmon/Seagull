
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

from app.core.config import settings
from app.core.observability import log_event, set_gauge
from app.shared.es_hosts import es_hosts

logger = logging.getLogger("seagull.integrations.es")

_es_client = None
_last_ping_at: float = 0.0
_last_ping_ok: bool = False

_STATUS_RANK: Dict[str, int] = {"green": 0, "yellow": 1, "red": 2}

_cluster_health_at: float = 0.0
_cluster_health: Optional[Dict[str, Any]] = None
_below_expected_since: Optional[float] = None
_last_alert_log_at: float = 0.0


def _build_es_client():
    from elasticsearch import Elasticsearch

    kwargs: Dict[str, Any] = {
        "request_timeout": int(getattr(settings, "SEAGULL_ES_REQUEST_TIMEOUT_SECONDS", 30) or 30),
    }

    username = getattr(settings, "SEAGULL_ES_USERNAME", None)
    password = getattr(settings, "SEAGULL_ES_PASSWORD", None)
    if username and password:
        kwargs["basic_auth"] = (username, password)

    kwargs["verify_certs"] = bool(getattr(settings, "SEAGULL_ES_VERIFY_CERTS", True))
    ca_certs = getattr(settings, "SEAGULL_ES_CA_CERTS", None)
    if ca_certs:
        kwargs["ca_certs"] = ca_certs

    return Elasticsearch(es_hosts(getattr(settings, "SEAGULL_ES_URL", None)), **kwargs)


def get_es_client():
    global _es_client
    if _es_client is None:
        _es_client = _build_es_client()
    return _es_client


def es_is_available() -> bool:

    global _last_ping_at, _last_ping_ok

    ttl = int(getattr(settings, "SEAGULL_ES_PING_TTL_SECONDS", 2) or 2)
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
    return (getattr(settings, "SEAGULL_SEARCH_BACKEND", "auto") or "auto").strip().lower()


def es_cluster_health() -> Optional[Dict[str, Any]]:
    global _cluster_health_at, _cluster_health

    ttl = int(getattr(settings, "SEAGULL_ES_PING_TTL_SECONDS", 2) or 2)
    now = time.time()
    if _cluster_health_at and (now - _cluster_health_at) < max(1, ttl):
        return _cluster_health

    _cluster_health_at = now
    try:
        timeout = max(1, int(getattr(settings, "SEAGULL_ES_HEALTH_TIMEOUT_SECONDS", 2) or 2))
        resp = get_es_client().options(request_timeout=timeout).cluster.health()
        _cluster_health = dict(resp)
    except Exception:
        _cluster_health = None
    return _cluster_health


def _resolve_expected_status(configured: str, number_of_nodes: Optional[int]) -> str:
    value = (configured or "auto").strip().lower()
    if value in ("green", "yellow"):
        return value
    return "green" if (number_of_nodes or 0) > 1 else "yellow"


def _evaluate_cluster_state(
    health: Optional[Dict[str, Any]],
    *,
    expected_configured: str,
    alert_after_seconds: float,
    below_since: Optional[float],
    now: float,
) -> Tuple[Dict[str, Any], Optional[float]]:
    status: Optional[str] = None
    if health:
        raw = str(health.get("status") or "").strip().lower()
        if raw in _STATUS_RANK:
            status = raw

    nodes: Optional[int] = None
    if health is not None:
        try:
            nodes = int(health.get("number_of_nodes") or 0)
        except (TypeError, ValueError):
            nodes = None

    expected = _resolve_expected_status(expected_configured, nodes)
    below = status is None or _STATUS_RANK[status] > _STATUS_RANK[expected]
    if not below:
        below_since = None
    elif below_since is None:
        below_since = now
    below_seconds = (now - below_since) if below_since is not None else 0.0
    alert = below and (status == "red" or below_seconds >= max(60.0, alert_after_seconds))

    report: Dict[str, Any] = {
        "status": status,
        "expected": expected,
        "below_expected": below,
        "below_expected_seconds": int(below_seconds),
        "alert": alert,
    }
    if health is not None:
        report.update(
            {
                "number_of_nodes": health.get("number_of_nodes"),
                "number_of_data_nodes": health.get("number_of_data_nodes"),
                "active_shards_percent": health.get("active_shards_percent_as_number"),
                "unassigned_shards": health.get("unassigned_shards"),
                "relocating_shards": health.get("relocating_shards"),
                "initializing_shards": health.get("initializing_shards"),
            }
        )
    return report, below_since


def es_cluster_status_report() -> Dict[str, Any]:
    global _below_expected_since, _last_alert_log_at

    health = es_cluster_health()
    now = time.monotonic()
    minutes = float(getattr(settings, "SEAGULL_ES_YELLOW_ALERT_MINUTES", 15.0) or 15.0)
    report, _below_expected_since = _evaluate_cluster_state(
        health,
        expected_configured=str(getattr(settings, "SEAGULL_ES_EXPECTED_STATUS", "auto") or "auto"),
        alert_after_seconds=minutes * 60.0,
        below_since=_below_expected_since,
        now=now,
    )

    set_gauge("es_cluster_status", float(_STATUS_RANK.get(report["status"] or "", -1)))
    set_gauge("es_cluster_below_expected", 1.0 if report["below_expected"] else 0.0)
    unassigned = report.get("unassigned_shards")
    if unassigned is not None:
        set_gauge("es_cluster_unassigned_shards", float(unassigned))

    if report["alert"] and (now - _last_alert_log_at) >= 60.0:
        _last_alert_log_at = now
        log_event(
            logger,
            "warning",
            "es_cluster_status_below_expected",
            status=report["status"],
            expected=report["expected"],
            below_expected_seconds=report["below_expected_seconds"],
            unassigned_shards=report.get("unassigned_shards"),
        )
    return report
