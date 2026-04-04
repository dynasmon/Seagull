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
    stage_transition_window_seconds: int

    # Default weights (can evolve without DB migrations)
    # SSH correlation
    ssh_fail_window_seconds: int
    ssh_fail_threshold: int
    ssh_bruteforce_score: int
    ssh_bruteforce_success_score: int
    ssh_new_source_score: int

    # Sudo correlation
    sudo_exec_score: int
    sudo_lolbin_score: int
    sudo_priv_escalation_score: int
    sudo_remote_exec_score: int
    sudo_defense_evasion_score: int

    # Misc
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
        stage_transition_window_seconds=_env_int("NETWATCH_ATTACK_CHAIN_STAGE_TRANSITION_WINDOW_SECONDS", 90 * 60),

        # SSH correlation
        ssh_fail_window_seconds=_env_int("NETWATCH_ATTACK_CHAIN_SSH_FAIL_WINDOW_SECONDS", 10 * 60),
        ssh_fail_threshold=_env_int("NETWATCH_ATTACK_CHAIN_SSH_FAIL_THRESHOLD", 6),
        ssh_bruteforce_score=_env_int("NETWATCH_ATTACK_CHAIN_SSH_BRUTEFORCE_SCORE", 28),
        ssh_bruteforce_success_score=_env_int("NETWATCH_ATTACK_CHAIN_SSH_BRUTEFORCE_SUCCESS_SCORE", 34),
        ssh_new_source_score=_env_int("NETWATCH_ATTACK_CHAIN_SSH_NEW_SOURCE_SCORE", 14),

        # Sudo correlation
        sudo_exec_score=_env_int("NETWATCH_ATTACK_CHAIN_SUDO_EXEC_SCORE", 6),
        sudo_lolbin_score=_env_int("NETWATCH_ATTACK_CHAIN_SUDO_LOLBIN_SCORE", 14),
        sudo_priv_escalation_score=_env_int("NETWATCH_ATTACK_CHAIN_SUDO_PRIV_ESCALATION_SCORE", 24),
        sudo_remote_exec_score=_env_int("NETWATCH_ATTACK_CHAIN_SUDO_REMOTE_EXEC_SCORE", 26),
        sudo_defense_evasion_score=_env_int("NETWATCH_ATTACK_CHAIN_SUDO_DEF_EVASION_SCORE", 30),

        # Misc
        log_tamper_score=_env_int("NETWATCH_ATTACK_CHAIN_LOG_TAMPER_SCORE", 22),
    )
