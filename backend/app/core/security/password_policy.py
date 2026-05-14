from __future__ import annotations

import re

MIN_PASSWORD_LENGTH = 12


def validate_password_policy(password: str, *, username: str | None = None) -> str | None:
    """Return a stable validation error message, or None when valid."""
    pw = str(password or "")
    uname = str(username or "").strip().lower()

    if len(pw) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if any(ch.isspace() for ch in pw):
        return "Password cannot contain whitespace."
    if uname and uname in pw.lower():
        return "Password must not contain your username."
    if not re.search(r"[a-z]", pw):
        return "Password must include at least one lowercase letter."
    if not re.search(r"[A-Z]", pw):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[0-9]", pw):
        return "Password must include at least one digit."
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "Password must include at least one symbol."
    return None
