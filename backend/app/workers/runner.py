import logging
import time

from sqlalchemy.exc import OperationalError

from app.core.observability import log_event, setup_logging
from app.core.config import settings
from app.features.alerts.rule_runtime import run_all_rules


setup_logging("worker-rules")
logger = logging.getLogger("seagull.worker.rules")


def _get_interval_seconds() -> float:
    v = float(settings.SEAGULL_RULES_EVERY_SECONDS or 5.0)
    if v < 0.25:
        return 0.25
    return v


def main() -> None:
    settings.validate_for_service("worker-rules")
    every = _get_interval_seconds()
    backoff = 1.0
    while True:
        try:
            alerts = run_all_rules()
            log_event(logger, "info", "rules_cycle_ok", created_alerts=len(alerts))
            backoff = 1.0
            time.sleep(every)
        except OperationalError as e:
            # DB not ready yet (startup / recovery). Keep the worker alive.
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "rules_db_not_ready", wait_s=wait_s, error=str(e).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 15.0)
            log_event(logger, "error", "rules_loop_error", wait_s=wait_s, error=repr(e))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)


if __name__ == "__main__":
    main()
