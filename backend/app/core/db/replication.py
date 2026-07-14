from __future__ import annotations

import itertools
import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Sequence

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from app.core.observability import incr_counter, log_event, set_gauge

logger = logging.getLogger("seagull.db.replication")

PRIMARY_LSN_SQL = text("SELECT pg_current_wal_lsn()::text")
REPLICA_LSN_SQL = text("SELECT pg_is_in_recovery(), COALESCE(pg_last_wal_replay_lsn()::text, '0/0')")


def parse_wal_lsn(value: str) -> int:
    hi, _, lo = value.strip().partition("/")
    return (int(hi, 16) << 32) | int(lo, 16)


@dataclass(frozen=True)
class ReplicaHandle:
    name: str
    engine: Engine
    factory: sessionmaker


@dataclass
class ReplicaStatus:
    lag_bytes: int | None = None
    degraded: bool = True
    error: str | None = None
    lag_over_since: float | None = None
    last_probe_at: float | None = None


class ReadRouter:
    def __init__(
        self,
        primary: Engine,
        replicas: Sequence[ReplicaHandle],
        lag_threshold_bytes: int,
        degrade_seconds: float,
        probe_interval_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._primary = primary
        self._replicas = tuple(replicas)
        self._lag_threshold_bytes = max(1, int(lag_threshold_bytes))
        self._degrade_seconds = max(0.0, float(degrade_seconds))
        self._probe_interval = max(0.5, float(probe_interval_seconds))
        self._clock = clock
        self._status = {handle.name: ReplicaStatus() for handle in self._replicas}
        self._rr = itertools.count()
        self._lock = threading.Lock()
        self._probe_lock = threading.Lock()
        self._monitor: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def replicas(self) -> tuple[ReplicaHandle, ...]:
        return self._replicas

    @property
    def enabled(self) -> bool:
        return bool(self._replicas)

    def acquire(self) -> ReplicaHandle | None:
        if not self._replicas:
            return None
        now = self._clock()
        max_age = self._probe_interval * 3
        healthy: list[ReplicaHandle] = []
        with self._lock:
            for handle in self._replicas:
                status = self._status[handle.name]
                if status.degraded or status.last_probe_at is None:
                    continue
                if now - status.last_probe_at > max_age:
                    continue
                healthy.append(handle)
        if not healthy:
            return None
        return healthy[next(self._rr) % len(healthy)]

    def probe(self) -> None:
        if not self._replicas:
            return
        with self._probe_lock:
            now = self._clock()
            replayed: dict[str, tuple[int | None, str | None]] = {}
            for handle in self._replicas:
                try:
                    with handle.engine.connect() as conn:
                        row = conn.execute(REPLICA_LSN_SQL).one()
                    if bool(row[0]):
                        replayed[handle.name] = (parse_wal_lsn(str(row[1])), None)
                    else:
                        replayed[handle.name] = (None, "not in recovery")
                except Exception as exc:
                    replayed[handle.name] = (None, str(exc).splitlines()[0][:200])

            primary_lsn: int | None = None
            try:
                with self._primary.connect() as conn:
                    primary_lsn = parse_wal_lsn(str(conn.execute(PRIMARY_LSN_SQL).scalar_one()))
            except Exception as exc:
                log_event(
                    logger,
                    "warning",
                    "postgres_primary_probe_error",
                    error=str(exc).splitlines()[0][:200],
                )

            for handle in self._replicas:
                replay_lsn, error = replayed[handle.name]
                lag_bytes: int | None = None
                if error is None and primary_lsn is not None and replay_lsn is not None:
                    lag_bytes = max(0, primary_lsn - replay_lsn)
                self.record_probe(handle.name, lag_bytes, error, now=now)

    def probe_if_stale(self, max_age_seconds: float | None = None) -> None:
        if not self._replicas:
            return
        max_age = self._probe_interval if max_age_seconds is None else max(0.0, float(max_age_seconds))
        now = self._clock()
        with self._lock:
            probed = [status.last_probe_at for status in self._status.values()]
            fresh = all(at is not None and now - at <= max_age for at in probed)
        if not fresh:
            self.probe()

    def record_probe(self, name: str, lag_bytes: int | None, error: str | None, now: float | None = None) -> None:
        at = self._clock() if now is None else now
        with self._lock:
            status = self._status[name]
            status.last_probe_at = at
            status.lag_bytes = lag_bytes
            status.error = error
            if error is not None:
                status.lag_over_since = None
                self._transition(name, status, True)
            elif lag_bytes is not None and lag_bytes > self._lag_threshold_bytes:
                if status.lag_over_since is None:
                    status.lag_over_since = at
                if at - status.lag_over_since >= self._degrade_seconds:
                    self._transition(name, status, True)
            else:
                status.lag_over_since = None
                self._transition(name, status, False)
        if lag_bytes is not None:
            set_gauge("postgres_replica_lag_bytes", float(lag_bytes), replica=name)

    def _transition(self, name: str, status: ReplicaStatus, degraded: bool) -> None:
        if degraded and not status.degraded:
            incr_counter("postgres_replica_degraded_total", replica=name)
            log_event(
                logger,
                "warning",
                "postgres_replica_degraded",
                replica=name,
                lag_bytes=status.lag_bytes,
                error=status.error,
            )
        elif not degraded and status.degraded:
            log_event(logger, "info", "postgres_replica_recovered", replica=name, lag_bytes=status.lag_bytes)
        status.degraded = degraded

    def status_report(self) -> dict[str, object]:
        now = self._clock()
        replicas: list[dict[str, object]] = []
        healthy = 0
        with self._lock:
            for handle in self._replicas:
                status = self._status[handle.name]
                if not status.degraded and status.last_probe_at is not None:
                    healthy += 1
                replicas.append(
                    {
                        "name": handle.name,
                        "lag_bytes": status.lag_bytes,
                        "degraded": status.degraded,
                        "error": status.error,
                        "probe_age_seconds": (
                            None if status.last_probe_at is None else round(now - status.last_probe_at, 2)
                        ),
                    }
                )
        return {
            "enabled": bool(self._replicas),
            "healthy": healthy,
            "total": len(self._replicas),
            "lag_threshold_bytes": self._lag_threshold_bytes,
            "replicas": replicas,
        }

    def start_monitor(self) -> None:
        if not self._replicas:
            return
        with self._lock:
            if self._monitor is not None and self._monitor.is_alive():
                return
            self._stop.clear()
            self._monitor = threading.Thread(target=self._monitor_loop, name="pg-replica-monitor", daemon=True)
            self._monitor.start()

    def stop_monitor(self) -> None:
        self._stop.set()
        monitor = self._monitor
        if monitor is not None and monitor.is_alive():
            monitor.join(timeout=2.0)
        self._monitor = None

    def _monitor_loop(self) -> None:
        log_event(logger, "info", "postgres_replica_monitor_started", replicas=len(self._replicas))
        while not self._stop.is_set():
            try:
                self.probe()
            except Exception as exc:
                log_event(logger, "warning", "postgres_replica_probe_error", error=str(exc)[:200])
            self._stop.wait(self._probe_interval)
