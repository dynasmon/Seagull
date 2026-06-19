import logging
import signal
import threading

from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.db import engine
from app.core.observability import init_counter, log_event, setup_logging
from app.features.alerts.rule_runtime import run_all_rules
from app.workers.intelligence.rules.leader import release_leader_lock, try_acquire_leader_lock

setup_logging("worker-rules")
logger = logging.getLogger("seagull.worker.rules")

_stop_event = threading.Event()


def _get_interval_seconds() -> float:
    v = float(settings.SEAGULL_RULES_EVERY_SECONDS or 5.0)
    if v < 0.25:
        return 0.25
    return v


def _install_signal_handlers() -> None:
    def _handler(signum: int, _frame: object) -> None:
        _stop_event.set()

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


def _open_lock_connection():
    return engine.connect().execution_options(isolation_level="AUTOCOMMIT")


def _close_lock_connection(connection) -> None:
    if connection is None:
        return
    try:
        connection.close()
    except Exception:
        pass


def main() -> None:
    settings.validate_for_service("worker-rules")
    init_counter("detection_rule_matches_total")
    init_counter("detection_rule_errors_total")
    every = _get_interval_seconds()
    backoff = 1.0

    _install_signal_handlers()
    lock_connection = None
    is_leader = False
    try:
        while not _stop_event.is_set():
            try:
                if lock_connection is None:
                    lock_connection = _open_lock_connection()
                    is_leader = False
                if not is_leader:
                    is_leader = try_acquire_leader_lock(lock_connection)
                    if not is_leader:
                        log_event(logger, "info", "rules_standby_not_leader", every=every)
                        _stop_event.wait(every)
                        continue
                    log_event(logger, "info", "rules_leader_acquired")
                alerts = run_all_rules()
                log_event(logger, "info", "rules_cycle_ok", created_alerts=len(alerts))
                backoff = 1.0
                _stop_event.wait(every)
            except OperationalError as e:
                # DB not ready yet (startup / recovery). Keep the worker alive.
                is_leader = False
                _close_lock_connection(lock_connection)
                lock_connection = None
                wait_s = min(backoff, 15.0)
                log_event(logger, "warning", "rules_db_not_ready", wait_s=wait_s, error=str(e).splitlines()[0])
                _stop_event.wait(wait_s)
                backoff = min(backoff * 2.0, 15.0)
            except Exception as e:
                wait_s = min(backoff, 15.0)
                log_event(logger, "error", "rules_loop_error", wait_s=wait_s, error=repr(e))
                _stop_event.wait(wait_s)
                backoff = min(backoff * 2.0, 15.0)
    finally:
        if is_leader and lock_connection is not None:
            try:
                release_leader_lock(lock_connection)
            except Exception as exc:
                log_event(logger, "warning", "rules_leader_release_failed", error=repr(exc))
        _close_lock_connection(lock_connection)
        log_event(logger, "info", "rules_worker_stopped")


if __name__ == "__main__":
    main()
