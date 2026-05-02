from __future__ import annotations

import logging
import time

from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.observability import log_event, setup_logging
from app.features.attack_chain.worker_runtime import load_config

from .processors import _process_batch
from .repository import _ensure_bootstrap, _fetch_events, _get_last_id, _get_max_event_id, _set_last_id

setup_logging("worker-attack-chain")
logger = logging.getLogger("seagull.worker.attack_chain")


def main() -> None:
    settings.validate_for_service("worker-attack-chain")
    cfg = load_config()

    _ensure_bootstrap()

    log_every_s = float(getattr(cfg, "log_every_seconds", 2.0))
    log_idle_every_s = float(getattr(cfg, "log_idle_every_seconds", 20.0))
    debug = bool(getattr(cfg, "debug", False))

    log_event(
        logger,
        "info",
        "attack_chain_start",
        batch_size=cfg.batch_size,
        every_s=cfg.every_seconds,
        idle_sleep_s=cfg.idle_sleep_seconds,
        dedup_s=cfg.step_dedup_seconds,
        attach_window_s=cfg.attach_local_window_seconds,
        idle_close_s=cfg.case_idle_close_seconds,
        transition_window_s=int(getattr(cfg, "stage_transition_window_seconds", 90 * 60)),
        max_score=cfg.max_score,
        log_every_s=log_every_s,
        log_idle_every_s=log_idle_every_s,
        debug=debug,
    )

    backoff = 1.0
    last_id = 0
    idle_sleep = float(cfg.idle_sleep_seconds)
    every = float(cfg.every_seconds)

    last_ok_log_t = 0.0
    last_idle_log_t = 0.0

    while True:
        try:
            if last_id == 0:
                last_id = _get_last_id()

            events = _fetch_events(last_id, int(cfg.batch_size))
            if not events:
                now_t = time.time()
                if log_idle_every_s > 0 and (now_t - last_idle_log_t) >= log_idle_every_s:
                    max_id = _get_max_event_id()
                    lag = max(0, int(max_id) - int(last_id))
                    log_event(
                        logger,
                        "info",
                        "attack_chain_idle",
                        last_id=last_id,
                        max_id=max_id,
                        lag=lag,
                        sleep_s=idle_sleep,
                    )
                    last_idle_log_t = now_t
                time.sleep(idle_sleep)
                continue

            t0 = time.time()
            new_last, stats = _process_batch(events, cfg)
            if new_last and new_last > last_id:
                last_id = new_last
                _set_last_id(last_id)

            took_ms = int((time.time() - t0) * 1000)

            now_t = time.time()
            if log_every_s <= 0 or (now_t - last_ok_log_t) >= log_every_s:
                max_id = _get_max_event_id()
                lag = max(0, int(max_id) - int(last_id))
                log_event(
                    logger,
                    "info",
                    "attack_chain_ok",
                    last_id=last_id,
                    max_id=max_id,
                    lag=lag,
                    fetched=stats.get("fetched"),
                    events_with_steps=stats.get("events_with_steps"),
                    candidates=stats.get("candidates"),
                    inserted=stats.get("inserted"),
                    dedup=stats.get("dedup"),
                    cases_created=stats.get("cases_created"),
                    cases_attached=stats.get("cases_attached"),
                    cases_touched=stats.get("cases_touched"),
                    cases_closed=stats.get("cases_closed"),
                    took_ms=took_ms,
                )
                last_ok_log_t = now_t

            if every > 0:
                time.sleep(every)

            backoff = 1.0
        except KeyboardInterrupt:
            raise
        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "attack_chain_db_not_ready", wait_s=wait_s, error=str(e).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 30.0)
            log_event(logger, "error", "attack_chain_loop_error", wait_s=wait_s, error=repr(e))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
