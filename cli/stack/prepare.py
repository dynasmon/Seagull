from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from . import env as _env
from . import secrets as _secrets
from . import compose as _compose


def _check_merge_state(root: Path) -> None:
    env_file = _env.env_path()
    if not env_file.exists():
        raise RuntimeError(
            f"[prod-prepare] {env_file} not found; "
            "create it from .env.example and set production secrets"
        )
    for line in env_file.read_text().splitlines():
        if line.startswith(("<<<<<<< ", "=======", ">>>>>>> ")):
            raise RuntimeError(
                f"[prod-prepare] unresolved merge markers found in {env_file}"
            )

    git_dir = root / ".git"
    if git_dir.exists():
        for indicator in (
            git_dir / "MERGE_HEAD",
            git_dir / "rebase-merge",
            git_dir / "rebase-apply",
        ):
            if indicator.exists():
                raise RuntimeError(
                    "[prod-prepare] repository is in an unfinished merge/rebase state; "
                    "run git merge --abort or git rebase --abort before deploying"
                )
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=U"],
                capture_output=True, text=True, cwd=str(root),
            )
            if result.stdout.strip():
                raise RuntimeError(
                    "[prod-prepare] repository has unresolved conflicts in the index:\n"
                    + result.stdout.strip()
                )
        except FileNotFoundError:
            pass


def _ensure_secret_dirs(root: Path) -> None:
    for d in (root / "secrets" / "bootstrap", root / "secrets" / "runtime"):
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)
    bootstrap = root / "secrets" / "bootstrap"
    for f in bootstrap.glob("*.token"):
        f.chmod(0o600)


def _read_file_secret(path_str: str) -> str:
    p = Path(path_str)
    if not p.exists() or not p.is_file():
        raise RuntimeError(f"[prod-prepare] secret file not found or not a file: {p}")
    return p.read_text().strip("\r\n")


def _validate_secret(key: str, min_len: int, gen_bytes: int, auto_fix: bool) -> None:
    value = _env.read(key)
    if value and len(value) >= min_len and not _secrets.is_insecure(value):
        return
    if auto_fix:
        _env.upsert(key, _secrets.generate(gen_bytes))
        print(f"[prod-prepare] auto-generated secure {key} in .env")
        return
    if not value or len(value) < min_len:
        raise RuntimeError(f"[prod-prepare] missing or weak {key} (min {min_len} chars)")
    raise RuntimeError(f"[prod-prepare] insecure placeholder detected for {key}")


def _validate_secret_or_file(
    key: str, file_key: str, min_len: int, gen_bytes: int, auto_fix: bool
) -> None:
    file_path = _env.read(file_key)
    if file_path:
        value = _read_file_secret(file_path)
        if not value or len(value) < min_len:
            raise RuntimeError(
                f"[prod-prepare] secret from {file_key} is too short (min {min_len} chars)"
            )
        if _secrets.is_insecure(value):
            raise RuntimeError(f"[prod-prepare] insecure placeholder detected in {file_key}")
        return
    _validate_secret(key, min_len, gen_bytes, auto_fix)


def _reject_pair_conflict(key: str, file_key: str) -> None:
    if _env.read(key) and _env.read(file_key):
        raise RuntimeError(
            f"[prod-prepare] {key} and {file_key} are both set; "
            "production must use a single source of truth"
        )


def run(auto_fix: Optional[bool] = None) -> None:
    root = _env.root()
    if auto_fix is None:
        auto_fix = _env.read("SEAGULL_PROD_AUTO_FIX_ENV", "true").lower() == "true"

    _check_merge_state(root)
    _ensure_secret_dirs(root)

    _validate_secret("POSTGRES_PASSWORD", 12, 36, auto_fix)
    _validate_secret_or_file(
        "SEAGULL_REDIS_PASSWORD", "SEAGULL_REDIS_PASSWORD_FILE", 12, 36, auto_fix
    )
    _validate_secret("SEAGULL_ES_PASSWORD", 12, 36, auto_fix)
    _validate_secret("SEAGULL_JWT_SECRET", 32, 48, auto_fix)
    _validate_secret("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", 12, 36, auto_fix)
    _validate_secret("SEAGULL_AUDIT_HASH_PEPPER", 32, 48, auto_fix)

    _reject_pair_conflict("POSTGRES_PASSWORD", "POSTGRES_PASSWORD_FILE")
    _reject_pair_conflict("SEAGULL_REDIS_PASSWORD", "SEAGULL_REDIS_PASSWORD_FILE")
    _reject_pair_conflict("SEAGULL_ES_PASSWORD", "SEAGULL_ES_PASSWORD_FILE")
    _reject_pair_conflict("SEAGULL_JWT_SECRET", "SEAGULL_JWT_SECRET_FILE")
    _reject_pair_conflict("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", "SEAGULL_BOOTSTRAP_ADMIN_PASSWORD_FILE")

    if not _compose.validate(_compose.STACK_FILES):
        raise RuntimeError("[prod-prepare] docker compose config validation failed")

    print("[prod-prepare] ok: production environment validated")
