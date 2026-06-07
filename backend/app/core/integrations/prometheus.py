from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from app.core.config import settings

logger = logging.getLogger("seagull.observability.prometheus")

_PING_TTL_SECONDS = 5.0
_last_ping_at: float = 0.0
_last_ping_ok: bool = False


class PrometheusError(Exception):
    pass


class PrometheusUnavailable(PrometheusError):
    pass


class PrometheusQueryError(PrometheusError):
    def __init__(self, message: str, *, error_type: str | None = None) -> None:
        super().__init__(message)
        self.error_type = error_type or "execution"


@dataclass(frozen=True)
class InstantSample:
    metric: Dict[str, str]
    value: float
    timestamp: float


@dataclass(frozen=True)
class RangeSeries:
    metric: Dict[str, str]
    points: List[Tuple[float, float]]


@dataclass(frozen=True)
class QueryResponse:
    result_type: str
    samples: List[InstantSample] = field(default_factory=list)
    series: List[RangeSeries] = field(default_factory=list)


def prometheus_is_enabled() -> bool:
    return bool(getattr(settings, "SEAGULL_PROMETHEUS_ENABLED", False))


def _base_url() -> str:
    raw = (getattr(settings, "SEAGULL_PROMETHEUS_URL", "") or "http://prometheus:9090").strip()
    return raw.rstrip("/")


def _timeout() -> float:
    try:
        return float(getattr(settings, "SEAGULL_PROMETHEUS_TIMEOUT_SECONDS", 5.0) or 5.0)
    except (TypeError, ValueError):
        return 5.0


def _to_float(raw: Any) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return float("nan")


def _parse_value_pair(pair: Any) -> Tuple[float, float]:
    if not isinstance(pair, (list, tuple)) or len(pair) < 2:
        return 0.0, float("nan")
    return float(_to_float(pair[0])), _to_float(pair[1])


def _http_get_json(path: str, params: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
    url = f"{_base_url()}{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            raw = resp.read()
            status = int(getattr(resp, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        raw = exc.read() or b""
        status = int(exc.code or 0)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PrometheusUnavailable(f"prometheus request failed: {exc}") from exc

    try:
        data = json.loads(raw.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError) as exc:
        if status >= 500 or status == 0:
            raise PrometheusUnavailable(f"prometheus returned non-JSON (status={status})") from exc
        raise PrometheusQueryError(f"prometheus returned non-JSON (status={status})") from exc

    if not isinstance(data, dict):
        raise PrometheusQueryError("prometheus returned an unexpected payload")
    return status, data


def _envelope_to_response(data: Dict[str, Any]) -> QueryResponse:
    status = str(data.get("status") or "")
    if status == "error":
        raise PrometheusQueryError(
            str(data.get("error") or "prometheus query error"),
            error_type=str(data.get("errorType") or "execution"),
        )
    if status != "success":
        raise PrometheusQueryError(f"unexpected prometheus status: {status or 'missing'}")

    payload = data.get("data") or {}
    result_type = str(payload.get("resultType") or "")
    result = payload.get("result")

    if result_type == "vector":
        samples: List[InstantSample] = []
        for item in result or []:
            metric = {str(k): str(v) for k, v in (item.get("metric") or {}).items()}
            ts, val = _parse_value_pair(item.get("value"))
            samples.append(InstantSample(metric=metric, value=val, timestamp=ts))
        return QueryResponse(result_type=result_type, samples=samples)

    if result_type == "matrix":
        series: List[RangeSeries] = []
        for item in result or []:
            metric = {str(k): str(v) for k, v in (item.get("metric") or {}).items()}
            points = [_parse_value_pair(p) for p in (item.get("values") or [])]
            series.append(RangeSeries(metric=metric, points=points))
        return QueryResponse(result_type=result_type, series=series)

    if result_type in ("scalar", "string"):
        ts, val = _parse_value_pair(result)
        return QueryResponse(result_type=result_type, samples=[InstantSample(metric={}, value=val, timestamp=ts)])

    raise PrometheusQueryError(f"unsupported prometheus result type: {result_type or 'missing'}")


def _query(path: str, params: Dict[str, str]) -> QueryResponse:
    if not prometheus_is_enabled():
        raise PrometheusUnavailable("prometheus query layer is disabled")
    status, data = _http_get_json(path, params)
    if status >= 500:
        raise PrometheusUnavailable(str(data.get("error") or f"prometheus status {status}"))
    return _envelope_to_response(data)


def instant_query(promql: str, *, time_unix: float | None = None) -> QueryResponse:
    params: Dict[str, str] = {"query": promql}
    if time_unix is not None:
        params["time"] = repr(float(time_unix))
    return _query("/api/v1/query", params)


def range_query(promql: str, *, start: float, end: float, step: float) -> QueryResponse:
    params = {
        "query": promql,
        "start": repr(float(start)),
        "end": repr(float(end)),
        "step": repr(float(step)),
    }
    return _query("/api/v1/query_range", params)


def is_available() -> bool:
    global _last_ping_at, _last_ping_ok

    if not prometheus_is_enabled():
        return False

    now = time.time()
    if (now - _last_ping_at) < _PING_TTL_SECONDS:
        return _last_ping_ok

    _last_ping_at = now
    try:
        req = urllib.request.Request(f"{_base_url()}/-/healthy", method="GET")
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            _last_ping_ok = 200 <= int(getattr(resp, "status", 200) or 200) < 300
    except Exception:
        _last_ping_ok = False
    return _last_ping_ok


def reset_state() -> None:
    global _last_ping_at, _last_ping_ok
    _last_ping_at = 0.0
    _last_ping_ok = False
