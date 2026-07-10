from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Literal, Set, Tuple

from app.core.config import settings

RouteBackend = Literal["elasticsearch", "clickhouse", "postgres"]

ROUTE_BACKENDS: Tuple[RouteBackend, ...] = ("elasticsearch", "clickhouse", "postgres")

CircuitStateName = Literal["closed", "open", "half_open"]


@dataclass(frozen=True)
class QuerySignals:
    has_search: bool = False
    has_wildcard: bool = False
    filter_clauses: int = 0
    window_minutes: int | None = None
    aggregate: bool = False
    transactional_join: bool = False


@dataclass(frozen=True)
class RouteDecision:
    chain: Tuple[RouteBackend, ...]
    reason: str


@dataclass(frozen=True)
class CircuitState:
    state: CircuitStateName
    recent_failures: int
    open_remaining_seconds: float
    probe_in_flight: bool


def route_trusts_es() -> bool:
    return bool(getattr(settings, "SEAGULL_ROUTE_TRUST_ES", False))


def is_wide_window(signals: QuerySignals, *, wide_window_minutes: int) -> bool:
    return (
        signals.window_minutes is not None
        and int(signals.window_minutes) >= max(15, int(wide_window_minutes))
    )


def decide_backend_chain(
    signals: QuerySignals,
    *,
    es_enabled: bool,
    wide_window_minutes: int,
    many_clauses_threshold: int,
) -> RouteDecision:
    wide = is_wide_window(signals, wide_window_minutes=wide_window_minutes)
    search_tail: Tuple[RouteBackend, ...] = (
        ("clickhouse", "postgres") if wide else ("postgres", "clickhouse")
    )

    if signals.transactional_join:
        decision = RouteDecision(("postgres", "clickhouse", "elasticsearch"), "transactional")
    elif es_enabled and (signals.has_search or signals.has_wildcard):
        decision = RouteDecision(("elasticsearch", *search_tail), "fulltext")
    elif es_enabled and signals.filter_clauses >= max(1, int(many_clauses_threshold)):
        decision = RouteDecision(("elasticsearch", *search_tail), "filters")
    elif signals.aggregate:
        decision = RouteDecision(("clickhouse", "postgres", "elasticsearch"), "aggregate")
    elif wide:
        decision = RouteDecision(("clickhouse", "postgres", "elasticsearch"), "wide_window")
    else:
        decision = RouteDecision(("postgres", "clickhouse", "elasticsearch"), "default")

    if not es_enabled:
        decision = RouteDecision(
            tuple(backend for backend in decision.chain if backend != "elasticsearch"),
            decision.reason,
        )
    return decision


_TIMEOUT_MARKERS: Tuple[str, ...] = (
    "timeout",
    "timed out",
    "timeout_exceeded",
    "code: 159",
    "canceling statement",
    "statement timeout",
    "querycanceled",
)


def classify_backend_failure(exc: Exception) -> str:
    if isinstance(exc, LookupError):
        return str(exc).strip() or "lookup_error"
    haystack = f"{type(exc).__name__}: {exc}".lower()
    if any(marker in haystack for marker in _TIMEOUT_MARKERS):
        return "timeout"
    return type(exc).__name__


def failure_counts_toward_breaker(reason: str) -> bool:
    return not reason.endswith("_stale")


class BackendCircuitBreaker:
    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        window_seconds: float = 30.0,
        cooldown_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._failure_threshold = max(1, int(failure_threshold))
        self._window_seconds = max(1.0, float(window_seconds))
        self._cooldown_seconds = max(1.0, float(cooldown_seconds))
        self._clock = clock
        self._lock = threading.Lock()
        self._failures: Dict[str, Deque[float]] = {}
        self._opened_until: Dict[str, float] = {}
        self._probing: Set[str] = set()

    def allow(self, backend: str) -> bool:
        now = self._clock()
        with self._lock:
            opened_until = self._opened_until.get(backend)
            if opened_until is None:
                return True
            if now < opened_until:
                return False
            if backend in self._probing:
                return False
            self._probing.add(backend)
            return True

    def record_success(self, backend: str) -> None:
        with self._lock:
            self._failures.pop(backend, None)
            self._opened_until.pop(backend, None)
            self._probing.discard(backend)

    def record_failure(self, backend: str) -> bool:
        now = self._clock()
        with self._lock:
            if backend in self._probing:
                self._probing.discard(backend)
                self._opened_until[backend] = now + self._cooldown_seconds
                return True

            failures = self._failures.setdefault(backend, deque())
            failures.append(now)
            cutoff = now - self._window_seconds
            while failures and failures[0] < cutoff:
                failures.popleft()
            if len(failures) < self._failure_threshold:
                return False

            already_open = self._opened_until.get(backend, float("-inf")) > now
            self._opened_until[backend] = now + self._cooldown_seconds
            failures.clear()
            return not already_open

    def state(self, backend: str) -> CircuitState:
        now = self._clock()
        with self._lock:
            cutoff = now - self._window_seconds
            recent = sum(1 for ts in self._failures.get(backend, ()) if ts >= cutoff)
            opened_until = self._opened_until.get(backend)
            probing = backend in self._probing
            if opened_until is None:
                return CircuitState("closed", recent, 0.0, probing)
            if now < opened_until:
                return CircuitState("open", recent, round(opened_until - now, 3), probing)
            return CircuitState("half_open", recent, 0.0, probing)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._opened_until.clear()
            self._probing.clear()
