from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def env_value(name: str, default: Optional[str] = None) -> Optional[str]:
    """Return an env value supporting <VAR> and <VAR>_FILE.

    Precedence:
    1) VAR (non-empty)
    2) VAR_FILE (path to file with secret)
    3) default
    """

    raw = os.getenv(name)
    if raw is not None:
        value = raw.strip()
        if value:
            return value

    file_var = f"{name}_FILE"
    file_path = os.getenv(file_var)
    if file_path is not None and file_path.strip():
        path = Path(file_path.strip())
        try:
            return path.read_text(encoding="utf-8").strip() or default
        except Exception as exc:
            raise RuntimeError(f"Unable to read secret file from {file_var}: {path}") from exc

    return default

