import os
import time

from sqlalchemy.exc import OperationalError

from app.workers.rules_engine import run_all_rules


def _get_interval_seconds() -> float:
    raw = (os.getenv("NETWATCH_RULES_EVERY_SECONDS") or "5").strip()
    try:
        v = float(raw)
    except Exception:
        return 5.0
    if v < 0.25:
        return 0.25
    return v


def main() -> None:
    every = _get_interval_seconds()
    backoff = 1.0
    while True:
        try:
            alerts = run_all_rules()
            print(f"Created {len(alerts)} alerts")
            backoff = 1.0
            time.sleep(every)
        except OperationalError as e:
            # DB not ready yet (startup / recovery). Keep the worker alive.
            wait_s = min(backoff, 15.0)
            print(f"[RULES] db_not_ready wait_s={wait_s} error={str(e).splitlines()[0]}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 15.0)
            print(f"[RULES] error wait_s={wait_s} error={repr(e)}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)


if __name__ == "__main__":
    main()
