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


def _env_bool(name: str, default: bool) -> bool:
    v = _env_str(name, None)
    if v is None:
        return default
    s = v.strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _env_csv(name: str, default: str = "") -> list[str]:
    raw = _env_str(name, default) or ""
    out: list[str] = []
    for part in raw.split(","):
        v = part.strip()
        if not v:
            continue
        out.append(v)
    return out


class Settings:
    # Environment
    NETWATCH_ENV: str = (_env_str("NETWATCH_ENV", "dev") or "dev").lower()

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

    # Enroll token
    NETWATCH_ENROLL_TOKEN: str | None = _env_str("NETWATCH_ENROLL_TOKEN", None)

    # Portal auth
    NETWATCH_JWT_SECRET: str | None = _env_str("NETWATCH_JWT_SECRET", None)
    NETWATCH_TOKEN_PEPPER: str | None = _env_str("NETWATCH_TOKEN_PEPPER", None)

    NETWATCH_ACCESS_TOKEN_TTL_SECONDS: int = _env_int("NETWATCH_ACCESS_TOKEN_TTL_SECONDS", 600)
    NETWATCH_REFRESH_TOKEN_TTL_SECONDS: int = _env_int("NETWATCH_REFRESH_TOKEN_TTL_SECONDS", 60 * 60 * 24 * 7)
    NETWATCH_OTP_TOKEN_TTL_SECONDS: int = _env_int("NETWATCH_OTP_TOKEN_TTL_SECONDS", 15 * 60)

    NETWATCH_COOKIE_SECURE: bool = _env_bool("NETWATCH_COOKIE_SECURE", False)
    NETWATCH_COOKIE_SAMESITE: str = (_env_str("NETWATCH_COOKIE_SAMESITE", "lax") or "lax").lower()
    NETWATCH_COOKIE_DOMAIN: str | None = _env_str("NETWATCH_COOKIE_DOMAIN", None)
    NETWATCH_ENABLE_HSTS: bool = _env_bool("NETWATCH_ENABLE_HSTS", False)
    NETWATCH_ALLOWED_HOSTS: list[str] = _env_csv("NETWATCH_ALLOWED_HOSTS", "*")
    NETWATCH_MAX_REQUEST_BODY_BYTES: int = _env_int("NETWATCH_MAX_REQUEST_BODY_BYTES", 2 * 1024 * 1024)

    # Search backend selection:
    # - auto: use Elasticsearch when available, fallback to Postgres
    # - elasticsearch: require Elasticsearch (API returns 503 if ES is down)
    # - postgres: always use Postgres
    NETWATCH_SEARCH_BACKEND: str = (_env_str("NETWATCH_SEARCH_BACKEND", "auto") or "auto").lower()

    # Elasticsearch connection (used by API hunting endpoints)
    NETWATCH_ES_URL: str = _env_str("NETWATCH_ES_URL", "http://elasticsearch:9200") or "http://elasticsearch:9200"
    NETWATCH_ES_INDEX_PREFIX: str = _env_str("NETWATCH_ES_INDEX_PREFIX", "netwatch-events") or "netwatch-events"
    NETWATCH_ES_REQUEST_TIMEOUT_SECONDS: int = _env_int("NETWATCH_ES_REQUEST_TIMEOUT_SECONDS", 30)
    NETWATCH_ES_USERNAME: str | None = _env_str("NETWATCH_ES_USERNAME", None)
    NETWATCH_ES_PASSWORD: str | None = _env_str("NETWATCH_ES_PASSWORD", None)
    NETWATCH_ES_VERIFY_CERTS: bool = _env_bool("NETWATCH_ES_VERIFY_CERTS", True)
    NETWATCH_ES_CA_CERTS: str | None = _env_str("NETWATCH_ES_CA_CERTS", None)
    NETWATCH_ES_PING_TTL_SECONDS: int = _env_int("NETWATCH_ES_PING_TTL_SECONDS", 2)

    # Bootstrap admin user (required on first run).
    NETWATCH_BOOTSTRAP_ADMIN_USERNAME: str = _env_str("NETWATCH_BOOTSTRAP_ADMIN_USERNAME", "admin") or "admin"
    NETWATCH_BOOTSTRAP_ADMIN_PASSWORD: str | None = _env_str("NETWATCH_BOOTSTRAP_ADMIN_PASSWORD", None)

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

    def token_pepper(self) -> str:
        # Separate pepper allows rotating JWT secret without invalidating stored hashes.
        # If not configured, fall back to the JWT secret.
        return (self.NETWATCH_TOKEN_PEPPER or self.NETWATCH_JWT_SECRET or "").strip()


settings = Settings()
