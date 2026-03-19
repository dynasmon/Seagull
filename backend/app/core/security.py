from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import jwt
from passlib.context import CryptContext

from app.core.config import settings


# Support legacy bcrypt hashes and migrate to argon2 on successful login.
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


def verify_and_upgrade_password(password: str, password_hash: str) -> tuple[bool, str | None]:
    """Verify password and return an upgraded hash when needed.

    Returns:
      (verified, upgraded_hash_or_none)
    """
    try:
        verified = bool(pwd_context.verify(password, password_hash))
    except Exception:
        return False, None
    if not verified:
        return False, None
    try:
        if pwd_context.needs_update(password_hash):
            return True, pwd_context.hash(password)
    except Exception:
        # Keep login success even if hash migration fails.
        return True, None
    return True, None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_jwt_secret() -> str:
    secret = (settings.NETWATCH_JWT_SECRET or "").strip()
    # Hard fail on weak/missing secrets.
    # - 32+ bytes is a reasonable minimum for HS256
    if not secret or len(secret) < 32:
        raise RuntimeError(
            "NETWATCH_JWT_SECRET is missing/too short. "
            "Set a strong random value (>= 32 chars) to start the backend."
        )
    return secret


def make_access_token(*, sub: str, ttl_seconds: int, extra: Optional[Dict[str, Any]] = None) -> str:
    secret = _require_jwt_secret()
    now = _utc_now()
    payload: Dict[str, Any] = {
        "typ": "access",
        "sub": sub,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str) -> Dict[str, Any]:
    secret = _require_jwt_secret()
    return jwt.decode(token, secret, algorithms=["HS256"])


def new_refresh_token() -> str:
    # 256-bit random token, URL-safe.
    return secrets.token_urlsafe(32)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(24)


def new_one_time_token(prefix: str = "nw_otp_") -> str:
    # Human-paste friendly, high entropy.
    return prefix + secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """Hash tokens before storing.

    We use a server-side pepper so DB compromise doesn't directly enable token replay.
    """
    pepper = settings.token_pepper()
    raw = (pepper + "|" + token).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    try:
        return secrets.compare_digest(a, b)
    except Exception:
        return False
