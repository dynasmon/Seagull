# backend/app/core/config.py
import json
import os
from typing import Any, Dict


def _env_str(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip()
    return v if v != "" else default


def _env_int(name: str, default: int) -> int:
    v = _env_str(name, None)
    if v is None:
        return default
    try:
        return int(v, 10)
    except ValueError:
        return default


class Settings:
    # Redis
    NETWATCH_REDIS_HOST: str = _env_str("NETWATCH_REDIS_HOST", "redis") or "redis"
    NETWATCH_REDIS_PORT: int = _env_int("NETWATCH_REDIS_PORT", 6379)

    # Optional full SQLAlchemy DSN (preferred). Example:
    #   postgresql+psycopg2://user:pass@postgres:5432/netwatch
    DB_URL: str | None = _env_str("NETWATCH_DB_URL", None)

    DB_HOST: str = _env_str("NETWATCH_DB_HOST", "postgres") or "postgres"
    DB_PORT: int = _env_int("NETWATCH_DB_PORT", 5432)
    DB_NAME: str = _env_str("NETWATCH_DB_NAME", "netwatch") or "netwatch"
    DB_USER: str = _env_str("NETWATCH_DB_USER", "netwatch") or "netwatch"
    DB_PASSWORD: str = _env_str("NETWATCH_DB_PASSWORD", "netwatch123") or "netwatch123"

    # Admin-only operations (e.g., pushing agent config)
    NETWATCH_ADMIN_TOKEN: str | None = _env_str("NETWATCH_ADMIN_TOKEN", None)

    # Default agent configuration applied on first enroll (JSON object).
    NETWATCH_DEFAULT_AGENT_CONFIG_JSON: str = _env_str("NETWATCH_DEFAULT_AGENT_CONFIG_JSON", "{}") or "{}"

    # Hard limit for agent config payloads (JSON-encoded bytes).
    NETWATCH_MAX_AGENT_CONFIG_BYTES: int = _env_int("NETWATCH_MAX_AGENT_CONFIG_BYTES", 262144)

    @property
    def database_url(self) -> str:
        if self.DB_URL:
            return self.DB_URL

        return (
            f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    def default_agent_config(self) -> Dict[str, Any]:
        raw = (self.NETWATCH_DEFAULT_AGENT_CONFIG_JSON or "{}").strip() or "{}"
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        return {}


settings = Settings()
