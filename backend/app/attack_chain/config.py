from __future__ import annotations

import os
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _env_float_alias(names: list[str], default: float) -> float:
    """Read the first defined env var from `names`.

    This keeps the config backward-compatible if env names evolve.
    """
    for n in names:
        raw = os.getenv(n)
        if raw is None:
            continue
        raw = raw.strip()
        if raw == "":
            continue
        try:
            return float(raw)
        except Exception:
            continue
    return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip().lower()
    if raw in ("1", "true", "yes", "y", "on"):
        return True
    if raw in ("0", "false", "no", "n", "off"):
        return False
    return default


@dataclass(frozen=True)
class AttackChainConfig:
    every_seconds: float
    idle_sleep_seconds: float
    max_rows: int
    batch_size: int

    # Logging
    log_every_seconds: float
    log_idle_every_seconds: float
    debug: bool

    # Case lifecycle
    case_idle_close_seconds: int
    attach_local_window_seconds: int

    # Noise control
    step_dedup_seconds: int
    max_score: int

    # Default weights (can evolve without DB migrations)
    ssh_bruteforce_step_score: int
    ssh_success_score: int
    sudo_root_score: int
    sudo_lolbin_score: int
    log_tamper_score: int


def load_config() -> AttackChainConfig:
    return AttackChainConfig(
        every_seconds=_env_float("NETWATCH_ATTACK_CHAIN_EVERY_SECONDS", 1.0),
        idle_sleep_seconds=_env_float("NETWATCH_ATTACK_CHAIN_IDLE_SLEEP_SECONDS", 2.0),
        max_rows=_env_int("NETWATCH_ATTACK_CHAIN_MAX_ROWS", 5000),
        batch_size=_env_int("NETWATCH_ATTACK_CHAIN_BATCH_SIZE", 500),

        # Logging
        log_every_seconds=_env_float_alias(
            ["NETWATCH_ATTACK_CHAIN_LOG_EVERY_SECONDS", "NETWATCH_ATTACK_CHAIN_LOG_EVERY_S"],
            2.0,
        ),
        log_idle_every_seconds=_env_float_alias(
            ["NETWATCH_ATTACK_CHAIN_LOG_IDLE_EVERY_SECONDS", "NETWATCH_ATTACK_CHAIN_LOG_IDLE_EVERY_S"],
            20.0,
        ),
        debug=_env_bool("NETWATCH_ATTACK_CHAIN_DEBUG", False),
        case_idle_close_seconds=_env_int("NETWATCH_ATTACK_CHAIN_IDLE_CLOSE_SECONDS", 45 * 60),
        attach_local_window_seconds=_env_int("NETWATCH_ATTACK_CHAIN_ATTACH_LOCAL_WINDOW_SECONDS", 20 * 60),
        step_dedup_seconds=_env_int("NETWATCH_ATTACK_CHAIN_STEP_DEDUP_SECONDS", 60),
        max_score=_env_int("NETWATCH_ATTACK_CHAIN_MAX_SCORE", 100),
        ssh_bruteforce_step_score=_env_int("NETWATCH_ATTACK_CHAIN_SSH_BRUTEFORCE_SCORE", 12),
        ssh_success_score=_env_int("NETWATCH_ATTACK_CHAIN_SSH_SUCCESS_SCORE", 25),
        sudo_root_score=_env_int("NETWATCH_ATTACK_CHAIN_SUDO_ROOT_SCORE", 20),
        sudo_lolbin_score=_env_int("NETWATCH_ATTACK_CHAIN_SUDO_LOLBIN_SCORE", 14),
        log_tamper_score=_env_int("NETWATCH_ATTACK_CHAIN_LOG_TAMPER_SCORE", 22),
    )
