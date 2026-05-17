from __future__ import annotations

from app.core.config.env_secrets import env_value


def _env_int(name: str, default: int) -> int:
    raw = env_value(name, None)
    if raw is None:
        return default
    try:
        return int(str(raw).strip(), 10)
    except Exception:
        return default

def _config_window_minutes() -> int:
    return max(5, _env_int("SEAGULL_NETWORK_TOPOLOGY_WINDOW_MINUTES", 1440))

def _config_stale_after_minutes() -> int:
    return max(1, _env_int("SEAGULL_NETWORK_TOPOLOGY_STALE_AFTER_MINUTES", 15))

def _config_max_events_per_run() -> int:
    return max(100, _env_int("SEAGULL_NETWORK_TOPOLOGY_MAX_EVENTS_PER_RUN", 5000))
