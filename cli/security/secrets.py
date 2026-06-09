from __future__ import annotations

import secrets as _secrets
import subprocess
from typing import Optional


_INSECURE_VALUES = {
    "admin", "password", "changeme", "change_me", "change_me_please",
    "secret", "seagull", "seagull123", "deprecated",
}


def generate(byte_length: int = 48) -> str:
    try:
        result = subprocess.run(
            ["openssl", "rand", "-base64", str(byte_length)],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip().replace("\n", "")
    except (FileNotFoundError, subprocess.CalledProcessError):
        return _secrets.token_urlsafe(byte_length)


def is_insecure(value: str) -> bool:
    normalized = value.lower().strip().replace(" ", "")
    if not normalized:
        return True
    if normalized in _INSECURE_VALUES:
        return True
    if "change_me" in normalized:
        return True
    return False


def validate_password_policy(label: str, username: str, password: str) -> Optional[str]:
    if len(password) < 12:
        return f"{label} must be at least 12 characters"
    if any(c.isspace() for c in password):
        return f"{label} cannot contain whitespace"
    if username and username.lower() in password.lower():
        return f"{label} must not contain the username"
    if not any(c.islower() for c in password):
        return f"{label} must include at least one lowercase letter"
    if not any(c.isupper() for c in password):
        return f"{label} must include at least one uppercase letter"
    if not any(c.isdigit() for c in password):
        return f"{label} must include at least one digit"
    if not any(not c.isalnum() for c in password):
        return f"{label} must include at least one symbol"
    return None
