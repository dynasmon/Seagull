from __future__ import annotations

# Exposure worker is not yet registered in workers/manager.py.
# This module is intentionally disabled and will be activated in the worker phase.

ENABLED = False


def run() -> None:
    raise RuntimeError("Exposure worker is not yet enabled. Set ENABLED = True and register in workers/manager.py.")
