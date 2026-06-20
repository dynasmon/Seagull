from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def _alias_names(name: str) -> tuple[str, ...]:
    if name.startswith("SEAGULL_"):
        return (name, f"NETWATCH_{name[len('SEAGULL_'):]}")
    if name.startswith("NETWATCH_"):
        return (name, f"SEAGULL_{name[len('NETWATCH_'):]}")
    return (name,)


def getenv_compat(name: str, default: Optional[str] = None) -> Optional[str]:
    for candidate in _alias_names(name):
        raw = os.getenv(candidate)
        if raw is None:
            continue
        return raw
    return default


def env_value(name: str, default: Optional[str] = None) -> Optional[str]:

    for candidate in _alias_names(name):
        raw = os.getenv(candidate)
        if raw is not None:
            value = raw.strip()
            if value:
                return value

        file_var = f"{candidate}_FILE"
        file_path = os.getenv(file_var)
        if file_path is not None and file_path.strip():
            path = Path(file_path.strip())
            try:
                return path.read_text(encoding="utf-8").strip() or default
            except Exception as exc:
                raise RuntimeError(f"Unable to read secret file from {file_var}: {path}") from exc

    return default
