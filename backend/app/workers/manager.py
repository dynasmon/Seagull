from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Sequence

from app.core.config.env_secrets import getenv_compat
from app.core.observability import (
    incr_counter,
    log_event,
    mark_process_dead,
    observe_hist,
    set_gauge,
    setup_logging,
    start_metrics_server,
)


def _env_bool(name: str, default: bool) -> bool:
    raw = getenv_compat(name)
    if raw is None:
        return default
    s = raw.strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _env_float(name: str, default: float) -> float:
    raw = getenv_compat(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except Exception:
        return default


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _state_file_for_group(group: str) -> Path:
    root = (getenv_compat("SEAGULL_WORKER_GROUP_STATE_DIR", "/tmp/seagull-worker-groups") or "/tmp/seagull-worker-groups").strip()
    safe_group = "".join(ch for ch in group.lower() if ch.isalnum() or ch in {"-", "_"}).strip("._-")
    if not safe_group:
        safe_group = "unknown"
    return Path(root) / f"{safe_group}.json"


@dataclass(frozen=True)
class ChildSpec:
    name: str
    module: str | None = None
    argv: tuple[str, ...] | None = None
    enabled_env: str | None = None
    enabled_default: bool = False
    required_paths: tuple[str, ...] = ()

    def is_enabled(self) -> bool:
        if not self.enabled_env:
            return True
        return _env_bool(self.enabled_env, self.enabled_default)

    def command(self) -> list[str]:
        if self.argv:
            return list(self.argv)
        if self.module:
            return [sys.executable, "-m", self.module]
        raise RuntimeError(f"invalid child spec for {self.name}: missing module/argv")


@dataclass
class ChildRuntime:
    spec: ChildSpec
    process: subprocess.Popen[bytes] | None = None
    starts: int = 0
    consecutive_failures: int = 0
    last_start_monotonic: float = 0.0
    last_exit_monotonic: float = 0.0
    last_exit_wall_time: float = 0.0
    last_exit_code: int | None = None
    next_start_monotonic: float = 0.0
    recent_quick_failures: Deque[float] = field(default_factory=deque)

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None


GROUPS: dict[str, tuple[ChildSpec, ...]] = {
    "ingest": (
        ChildSpec(name="ingest-worker", module="app.workers.ingest.main"),
        ChildSpec(name="es-indexer", module="app.workers.indexing.elasticsearch"),
        ChildSpec(name="rollup-1m", module="app.workers.analytics.rollup_1m"),
    ),
    "intelligence": (
        ChildSpec(name="rules-runner", module="app.workers.intelligence.rules.runner"),
        ChildSpec(name="ip-intel", module="app.workers.intelligence.ip_intel.main"),
        ChildSpec(name="proto-intel", module="app.workers.intelligence.protocol.main"),
        ChildSpec(name="attack-chain", module="app.workers.intelligence.attack_chain.main"),
        ChildSpec(
            name="exposure-graph",
            module="app.workers.intelligence.exposure.main",
            enabled_env="SEAGULL_EXPOSURE_ENABLED",
            enabled_default=True,
        ),
        ChildSpec(
            name="network-topology",
            module="app.workers.intelligence.network_topology.main",
            enabled_env="SEAGULL_NETWORK_TOPOLOGY_ENABLED",
            enabled_default=True,
        ),
        ChildSpec(
            name="correlations",
            module="app.workers.intelligence.correlations.main",
            enabled_env="SEAGULL_CORRELATIONS_WORKER_ENABLED",
            enabled_default=True,
        ),
        ChildSpec(
            name="ueba",
            module="app.workers.intelligence.ueba.main",
            enabled_env="SEAGULL_UEBA_ENABLED",
            enabled_default=True,
        ),
    ),
    "maintenance": (
        ChildSpec(name="audit-retention", module="app.workers.maintenance.audit_retention"),
        ChildSpec(
            name="bootstrap-rotator",
            argv=(sys.executable, "/scripts/agent_bootstrap_token_rotator.py"),
            enabled_env="SEAGULL_MAINTENANCE_ENABLE_BOOTSTRAP_ROTATOR",
            required_paths=("/scripts/agent_bootstrap_token_rotator.py",),
        ),
    ),
}


class WorkerGroupManager:
    def __init__(self, group: str) -> None:
        if group not in GROUPS:
            raise RuntimeError(f"unknown worker group: {group}")
        self.group = group
        self.logger = logging.getLogger("seagull.worker.manager")
        self.state_file = _state_file_for_group(group)
        self.stop_requested = False
        self.exit_code = 0

        self.restart_window_seconds = max(10.0, _env_float("SEAGULL_WORKER_GROUP_RESTART_WINDOW_SECONDS", 300.0))
        self.quick_fail_seconds = max(1.0, _env_float("SEAGULL_WORKER_GROUP_QUICK_FAIL_SECONDS", 15.0))
        self.max_quick_failures = max(1, int(_env_float("SEAGULL_WORKER_GROUP_MAX_QUICK_FAILURES", 5)))
        self.restart_backoff_initial = max(0.5, _env_float("SEAGULL_WORKER_GROUP_RESTART_BACKOFF_INITIAL_SECONDS", 1.0))
        self.restart_backoff_max = max(2.0, _env_float("SEAGULL_WORKER_GROUP_RESTART_BACKOFF_MAX_SECONDS", 30.0))
        self.state_flush_seconds = max(0.5, _env_float("SEAGULL_WORKER_GROUP_STATE_FLUSH_SECONDS", 2.0))
        self.stop_timeout_seconds = max(1.0, _env_float("SEAGULL_WORKER_GROUP_STOP_TIMEOUT_SECONDS", 20.0))

        self.children: Dict[str, ChildRuntime] = {}
        for spec in GROUPS[group]:
            self.children[spec.name] = ChildRuntime(spec=spec)

    def _start_metrics_server(self) -> None:
        """Expose this group's aggregated child metrics on an internal port.

        Child workers inherit ``PROMETHEUS_MULTIPROC_DIR`` and write per-process
        metrics there; this manager serves the multiprocess aggregate so a single
        Prometheus target covers the whole group. Best-effort — a bind failure is
        logged but never takes the group down.
        """
        if not _env_bool("SEAGULL_METRICS_ENABLED", True):
            return
        try:
            port = int(_env_float("SEAGULL_WORKER_METRICS_PORT", 9100.0))
        except Exception:
            port = 9100
        if port <= 0:
            return
        try:
            start_metrics_server(port)
            log_event(self.logger, "info", "worker_metrics_server_started", group=self.group, port=port)
        except Exception as exc:
            log_event(self.logger, "warning", "worker_metrics_server_failed", group=self.group, port=port, error=repr(exc))

    def run(self) -> int:
        self._install_signal_handlers()
        self._start_metrics_server()
        self._write_state()

        enabled = [child for child in self.children.values() if child.spec.is_enabled()]
        if not enabled:
            log_event(self.logger, "error", "worker_group_no_enabled_children", group=self.group)
            self._write_state()
            return 2

        log_event(
            self.logger,
            "info",
            "worker_group_starting",
            group=self.group,
            enabled_children=[child.spec.name for child in enabled],
        )

        for child in enabled:
            if not self._start_child(child):
                self._fail_group(f"failed to start child {child.spec.name}")
                break

        last_state_flush = 0.0

        while not self.stop_requested:
            now = time.monotonic()
            group_failed = False

            for child in self.children.values():
                if not child.spec.is_enabled():
                    continue

                if child.running:
                    continue

                if child.process is not None:
                    if self._handle_child_exit(child, now):
                        group_failed = True
                        break

                if now >= child.next_start_monotonic:
                    if not self._start_child(child):
                        group_failed = True
                        break

            if group_failed:
                break

            if (now - last_state_flush) >= self.state_flush_seconds:
                self._write_state()
                last_state_flush = now

            time.sleep(0.5)

        self._shutdown_children()
        self._write_state()
        return self.exit_code

    def _start_child(self, child: ChildRuntime) -> bool:
        for required_path in child.spec.required_paths:
            if not Path(required_path).exists():
                log_event(
                    self.logger,
                    "error",
                    "worker_child_missing_dependency",
                    group=self.group,
                    child=child.spec.name,
                    required_path=required_path,
                )
                self._fail_group(f"missing dependency for child {child.spec.name}")
                return False

        cmd = child.spec.command()
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["SEAGULL_WORKER_PROCESS"] = child.spec.name

        try:
            proc = subprocess.Popen(cmd, env=env)
        except Exception as exc:
            log_event(
                self.logger,
                "error",
                "worker_child_spawn_failed",
                group=self.group,
                child=child.spec.name,
                error=repr(exc),
                command=cmd,
            )
            self._fail_group(f"unable to spawn child {child.spec.name}")
            return False

        child.process = proc
        child.starts += 1
        child.last_start_monotonic = time.monotonic()
        child.last_exit_code = None
        child.next_start_monotonic = 0.0

        incr_counter("worker_starts_total", worker_group=self.group, worker=child.spec.name)
        set_gauge("worker_up", 1, worker_group=self.group, worker=child.spec.name)

        log_event(
            self.logger,
            "info",
            "worker_child_started",
            group=self.group,
            child=child.spec.name,
            pid=proc.pid,
            starts=child.starts,
            command=cmd,
        )
        return True

    def _handle_child_exit(self, child: ChildRuntime, now: float) -> bool:
        proc = child.process
        if proc is None:
            return False

        rc = proc.poll()
        if rc is None:
            return False

        dead_pid = proc.pid
        child.process = None
        child.last_exit_code = int(rc)
        child.last_exit_monotonic = now
        child.last_exit_wall_time = time.time()
        runtime = max(0.0, now - child.last_start_monotonic)

        set_gauge("worker_up", 0, worker_group=self.group, worker=child.spec.name)
        incr_counter("worker_exits_total", worker_group=self.group, worker=child.spec.name,
                     outcome="ok" if rc == 0 else "error")
        observe_hist("worker_child_runtime_seconds", runtime, worker_group=self.group, worker=child.spec.name)
        # Reclaim the exited process's multiprocess metric files (gauge cleanup).
        mark_process_dead(dead_pid)

        quick_failure = runtime < self.quick_fail_seconds
        if quick_failure:
            child.recent_quick_failures.append(now)
            cutoff = now - self.restart_window_seconds
            while child.recent_quick_failures and child.recent_quick_failures[0] < cutoff:
                child.recent_quick_failures.popleft()
        else:
            child.recent_quick_failures.clear()
            child.consecutive_failures = 0

        if rc == 0 and not self.stop_requested:
            # A long-running worker exiting 0 unexpectedly is still a failure mode.
            child.consecutive_failures += 1
        elif rc != 0:
            child.consecutive_failures += 1
        else:
            child.consecutive_failures = 0

        log_event(
            self.logger,
            "warning" if rc != 0 else "info",
            "worker_child_exited",
            group=self.group,
            child=child.spec.name,
            exit_code=int(rc),
            runtime_seconds=round(runtime, 3),
            consecutive_failures=child.consecutive_failures,
            quick_failures_in_window=len(child.recent_quick_failures),
        )

        if len(child.recent_quick_failures) >= self.max_quick_failures:
            self._fail_group(
                f"child {child.spec.name} exceeded quick-failure threshold "
                f"({len(child.recent_quick_failures)}/{self.max_quick_failures})"
            )
            return True

        backoff = min(
            self.restart_backoff_initial * (2 ** max(0, child.consecutive_failures - 1)),
            self.restart_backoff_max,
        )
        child.next_start_monotonic = now + backoff
        log_event(
            self.logger,
            "warning",
            "worker_child_restart_scheduled",
            group=self.group,
            child=child.spec.name,
            restart_in_seconds=round(backoff, 3),
        )
        return False

    def _install_signal_handlers(self) -> None:
        def _handler(signum: int, _frame: object) -> None:
            if self.stop_requested:
                return
            self.stop_requested = True
            self.exit_code = 0
            log_event(
                self.logger,
                "info",
                "worker_group_signal_received",
                group=self.group,
                signal=signal.Signals(signum).name,
            )

        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)

    def _fail_group(self, reason: str) -> None:
        if self.stop_requested and self.exit_code != 0:
            return
        self.stop_requested = True
        self.exit_code = 1
        log_event(self.logger, "error", "worker_group_non_viable", group=self.group, reason=reason)

    def _shutdown_children(self) -> None:
        running = [child for child in self.children.values() if child.running]
        if not running:
            return

        for child in running:
            assert child.process is not None
            try:
                child.process.terminate()
            except Exception:
                pass

        deadline = time.monotonic() + self.stop_timeout_seconds
        while time.monotonic() < deadline:
            if all(not child.running for child in running):
                break
            time.sleep(0.25)

        for child in running:
            if child.running and child.process is not None:
                try:
                    child.process.kill()
                except Exception:
                    pass

        for child in running:
            if child.process is not None:
                try:
                    child.process.wait(timeout=1.0)
                except Exception:
                    pass
                child.process = None

        log_event(
            self.logger,
            "info",
            "worker_group_stopped",
            group=self.group,
            exit_code=self.exit_code,
        )

    def _write_state(self) -> None:
        statuses: List[dict] = []
        enabled_count = 0
        running_count = 0
        permanent_failure = False

        for child in self.children.values():
            enabled = child.spec.is_enabled()
            status = "disabled"
            pid: int | None = None

            if enabled:
                enabled_count += 1
                if child.running:
                    status = "running"
                    running_count += 1
                    assert child.process is not None
                    pid = child.process.pid
                elif self.stop_requested and self.exit_code == 0:
                    status = "stopping"
                elif self.stop_requested and self.exit_code != 0:
                    status = "failed"
                    permanent_failure = True
                elif child.next_start_monotonic > time.monotonic():
                    status = "backoff"
                elif child.last_exit_code is not None:
                    status = "restarting"
                else:
                    status = "starting"

            set_gauge("worker_up", 1 if (enabled and child.running) else 0,
                      worker_group=self.group, worker=child.spec.name)
            statuses.append(
                {
                    "name": child.spec.name,
                    "enabled": enabled,
                    "status": status,
                    "pid": pid,
                    "starts": child.starts,
                    "consecutive_failures": child.consecutive_failures,
                    "last_exit_code": child.last_exit_code,
                    "last_exit_at": (
                        datetime.fromtimestamp(child.last_exit_wall_time, tz=timezone.utc).isoformat().replace("+00:00", "Z")
                        if child.last_exit_code is not None and child.last_exit_wall_time > 0
                        else None
                    ),
                }
            )

        healthy = enabled_count > 0 and not permanent_failure
        if self.exit_code != 0:
            healthy = False
        if self.stop_requested and self.exit_code == 0:
            healthy = False

        payload = {
            "group": self.group,
            "pid": os.getpid(),
            "healthy": healthy,
            "stopping": self.stop_requested,
            "updated_at": _utc_now_iso(),
            "enabled_children": enabled_count,
            "running_children": running_count,
            "children": statuses,
        }

        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.state_file.with_suffix(self.state_file.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n", encoding="utf-8")
        tmp_path.replace(self.state_file)


def _run_healthcheck(group: str) -> int:
    state_file = _state_file_for_group(group)
    stale_after = max(5.0, _env_float("SEAGULL_WORKER_GROUP_HEALTH_STALE_SECONDS", 30.0))

    try:
        payload = json.loads(state_file.read_text(encoding="utf-8"))
    except Exception:
        return 1

    updated_at = str(payload.get("updated_at") or "")
    if not updated_at:
        return 1

    try:
        ts = datetime.fromisoformat(updated_at.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 1

    now = time.time()
    if (now - ts) > stale_after:
        return 1

    if bool(payload.get("stopping")):
        return 1
    if not bool(payload.get("healthy")):
        return 1

    return 0


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m app.workers.manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run a worker group manager")
    run_parser.add_argument("group", choices=sorted(GROUPS.keys()))

    health_parser = subparsers.add_parser("health", help="healthcheck for a worker group")
    health_parser.add_argument("group", choices=sorted(GROUPS.keys()))

    for group in sorted(GROUPS.keys()):
        subparsers.add_parser(group, help=f"shortcut for 'run {group}'")

    return parser.parse_args(list(argv))


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    if args.command == "health":
        return _run_healthcheck(args.group)

    group = args.group if args.command == "run" else args.command
    setup_logging(f"worker-group-{group}")

    manager = WorkerGroupManager(group=group)
    return manager.run()


if __name__ == "__main__":
    raise SystemExit(main())
