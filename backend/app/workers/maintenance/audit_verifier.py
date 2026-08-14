from __future__ import annotations

import logging
import time
from collections import Counter

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.audit.chain import ChainBreak, chain_floor, verify_page
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.observability import incr_counter, log_event, observe_hist, set_gauge, setup_logging

setup_logging("worker-audit-verifier")
logger = logging.getLogger("seagull.worker.audit_verifier")

_BREAK_REASONS = ("prev_hash_mismatch", "event_hash_mismatch", "missing_predecessor", "seq_gap")


def _interval_seconds() -> float:
    return max(30.0, float(settings.SEAGULL_AUDIT_VERIFY_EVERY_SECONDS or 900))


def _batch_size() -> int:
    return max(100, int(settings.SEAGULL_AUDIT_VERIFY_BATCH or 2000))


def _reported_breaks() -> int:
    return max(1, int(settings.SEAGULL_AUDIT_VERIFY_REPORTED_BREAKS or 20))


def verify_chain(db: Session) -> tuple[int, int, list[ChainBreak]]:
    after_seq = chain_floor(db) - 1
    batch = _batch_size()
    checked = 0
    breaks: list[ChainBreak] = []
    while True:
        page = verify_page(db, after_seq=after_seq, limit=batch)
        checked += page.checked
        breaks.extend(page.breaks)
        after_seq = page.last_seq
        if page.exhausted:
            return checked, after_seq, breaks


def _publish(checked: int, head_seq: int, breaks: list[ChainBreak], elapsed: float) -> None:
    counted = Counter(b.reason for b in breaks)
    for reason in _BREAK_REASONS:
        set_gauge("audit_chain_broken_links", float(counted.get(reason, 0)), reason=reason)
    set_gauge("audit_chain_verified_events", float(checked))
    set_gauge("audit_chain_length", float(head_seq))
    observe_hist("audit_chain_verify_seconds", elapsed)
    incr_counter("audit_chain_verification_total", outcome=("broken" if breaks else "intact"))


def run_once() -> None:
    db = SessionLocal()
    started = time.monotonic()
    try:
        checked, head_seq, breaks = verify_chain(db)
    finally:
        db.close()
    elapsed = time.monotonic() - started
    _publish(checked, head_seq, breaks, elapsed)

    if breaks:
        log_event(
            logger,
            "error",
            "audit_chain_broken",
            checked=checked,
            head_seq=head_seq,
            broken=len(breaks),
            first_breaks=[
                {"seq": b.seq, "event_id": b.event_id, "reason": b.reason}
                for b in breaks[: _reported_breaks()]
            ],
        )
        return
    log_event(logger, "info", "audit_chain_intact", checked=checked, head_seq=head_seq, seconds=round(elapsed, 3))


def main() -> None:
    settings.validate_for_service("worker-audit-verifier")
    every = _interval_seconds()
    backoff = 1.0
    while True:
        try:
            run_once()
            backoff = 1.0
            time.sleep(every)
        except OperationalError as exc:
            wait_s = min(backoff, 30.0)
            log_event(logger, "warning", "audit_verifier_db_not_ready", wait_s=wait_s, error=str(exc).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)
        except Exception as exc:
            incr_counter("audit_chain_verification_total", outcome="error")
            wait_s = min(backoff, 30.0)
            log_event(logger, "error", "audit_verifier_loop_error", wait_s=wait_s, error=repr(exc))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
