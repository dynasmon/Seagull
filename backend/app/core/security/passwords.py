from __future__ import annotations

from passlib.context import CryptContext

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
