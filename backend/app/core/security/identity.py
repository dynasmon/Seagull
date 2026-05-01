from __future__ import annotations


def canonicalize_username(username: str) -> str:
    return str(username or "").strip().lower()
