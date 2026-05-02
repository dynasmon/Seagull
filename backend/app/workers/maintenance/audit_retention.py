from __future__ import annotations

import logging
import time

from sqlalchemy.exc import OperationalError

from app.core.audit.retention import purge_admin_evidence
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.observability import log_event, setup_logging


setup_logging("worker-audit-retention")
logger = logging.getLogger("seagull.worker.audit_retention")


def _interval_seconds() -> float:
    v = float(settings.SEAGULL_AUDIT_RETENTION_EVERY_SECONDS or 3600.0)
    return max(30.0, v)


def main() -> None:
    settings.validate_for_service("worker-audit-retention")
    every = _interval_seconds()
    backoff = 1.0
    while True:
        try:
            db = SessionLocal()
            try:
                deleted = purge_admin_evidence(db)
                db.commit()
            finally:
                db.close()

            log_event(logger, "info", "audit_retention_cycle_ok", every_seconds=every, deleted=deleted)
            backoff = 1.0
            time.sleep(every)
        except OperationalError as exc:
            wait_s = min(backoff, 30.0)
            log_event(logger, "warning", "audit_retention_db_not_ready", wait_s=wait_s, error=str(exc).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)
        except Exception as exc:
            wait_s = min(backoff, 30.0)
            log_event(logger, "error", "audit_retention_loop_error", wait_s=wait_s, error=repr(exc))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
