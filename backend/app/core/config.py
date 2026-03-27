# backend/app/core/config.py
import json
from urllib.parse import urlsplit
from typing import Any, Dict

from app.core.env_secrets import env_value


def _env_str(name: str, default: str | None = None) -> str | None:
    return env_value(name, default)


def _env_int(name: str, default: int) -> int:
    v = _env_str(name, None)
    if v is None:
        return default
    try:
        return int(v, 10)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    v = _env_str(name, None)
    if v is None:
        return default
    try:
        return float(v)
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
    NETWATCH_DB_AUTO_UPGRADE: bool = _env_bool(
        "NETWATCH_DB_AUTO_UPGRADE",
        NETWATCH_ENV in {"dev", "development"},
    )
    NETWATCH_SKIP_STARTUP_BOOTSTRAP: bool = _env_bool("NETWATCH_SKIP_STARTUP_BOOTSTRAP", False)
    NETWATCH_LOG_LEVEL: str = (_env_str("NETWATCH_LOG_LEVEL", "INFO") or "INFO").upper()

    # Redis
    NETWATCH_REDIS_HOST: str = _env_str("NETWATCH_REDIS_HOST", "redis") or "redis"
    NETWATCH_REDIS_PORT: int = _env_int("NETWATCH_REDIS_PORT", 6379)
    NETWATCH_REDIS_USERNAME: str | None = _env_str("NETWATCH_REDIS_USERNAME", None)
    NETWATCH_REDIS_PASSWORD: str | None = _env_str("NETWATCH_REDIS_PASSWORD", None)
    NETWATCH_RULES_DIR: str = _env_str("NETWATCH_RULES_DIR", "/app/rules") or "/app/rules"

    # Optional full SQLAlchemy DSN (preferred). Example:
    #   postgresql+psycopg2://user:pass@postgres:5432/netwatch
    DB_URL: str | None = _env_str("NETWATCH_DB_URL", None)

    DB_HOST: str = _env_str("NETWATCH_DB_HOST", "postgres") or "postgres"
    DB_PORT: int = _env_int("NETWATCH_DB_PORT", 5432)
    DB_NAME: str = _env_str("NETWATCH_DB_NAME", "netwatch") or "netwatch"
    DB_USER: str = _env_str("NETWATCH_DB_USER", "netwatch") or "netwatch"
    DB_PASSWORD: str | None = _env_str("NETWATCH_DB_PASSWORD", _env_str("POSTGRES_PASSWORD", None))
    NETWATCH_DB_POOL_SIZE: int = _env_int("NETWATCH_DB_POOL_SIZE", 10)
    NETWATCH_DB_MAX_OVERFLOW: int = _env_int("NETWATCH_DB_MAX_OVERFLOW", 20)
    NETWATCH_DB_EXECUTEMANY_MODE: str = _env_str("NETWATCH_DB_EXECUTEMANY_MODE", "values_plus_batch") or "values_plus_batch"
    NETWATCH_DB_EXECUTEMANY_VALUES_PAGE_SIZE: int = _env_int("NETWATCH_DB_EXECUTEMANY_VALUES_PAGE_SIZE", 1000)

    # Portal auth
    NETWATCH_JWT_SECRET: str | None = _env_str("NETWATCH_JWT_SECRET", None)
    NETWATCH_TOKEN_PEPPER: str | None = _env_str("NETWATCH_TOKEN_PEPPER", None)

    NETWATCH_ACCESS_TOKEN_TTL_SECONDS: int = _env_int("NETWATCH_ACCESS_TOKEN_TTL_SECONDS", 600)
    NETWATCH_REFRESH_TOKEN_TTL_SECONDS: int = _env_int("NETWATCH_REFRESH_TOKEN_TTL_SECONDS", 60 * 60 * 24 * 7)
    NETWATCH_OTP_TOKEN_TTL_SECONDS: int = _env_int("NETWATCH_OTP_TOKEN_TTL_SECONDS", 15 * 60)
    NETWATCH_AUTH_OTP_ENABLED: bool = _env_bool(
        "NETWATCH_AUTH_OTP_ENABLED",
        NETWATCH_ENV not in {"prod", "production"},
    )
    NETWATCH_JWT_ISSUER: str = _env_str("NETWATCH_JWT_ISSUER", "netwatch-backend") or "netwatch-backend"
    NETWATCH_JWT_AUDIENCE: str = _env_str("NETWATCH_JWT_AUDIENCE", "netwatch-portal") or "netwatch-portal"

    NETWATCH_COOKIE_SECURE: bool = _env_bool("NETWATCH_COOKIE_SECURE", False)
    NETWATCH_COOKIE_SAMESITE: str = (_env_str("NETWATCH_COOKIE_SAMESITE", "lax") or "lax").lower()
    NETWATCH_COOKIE_DOMAIN: str | None = _env_str("NETWATCH_COOKIE_DOMAIN", None)
    NETWATCH_ENABLE_HSTS: bool = _env_bool("NETWATCH_ENABLE_HSTS", False)
    NETWATCH_TRUST_PROXY_HEADERS: bool = _env_bool("NETWATCH_TRUST_PROXY_HEADERS", False)
    NETWATCH_TRUSTED_PROXY_CIDRS: str = _env_str("NETWATCH_TRUSTED_PROXY_CIDRS", "127.0.0.1,::1") or "127.0.0.1,::1"
    NETWATCH_ALLOWED_HOSTS: list[str] = _env_csv("NETWATCH_ALLOWED_HOSTS", "*")
    NETWATCH_MAX_REQUEST_BODY_BYTES: int = _env_int("NETWATCH_MAX_REQUEST_BODY_BYTES", 2 * 1024 * 1024)
    NETWATCH_AUDIT_HASH_PEPPER: str | None = _env_str("NETWATCH_AUDIT_HASH_PEPPER", None)
    NETWATCH_AUDIT_RETENTION_ENABLED: bool = _env_bool("NETWATCH_AUDIT_RETENTION_ENABLED", True)
    NETWATCH_AUDIT_RETENTION_DAYS: int = _env_int(
        "NETWATCH_AUDIT_RETENTION_DAYS",
        365 if NETWATCH_ENV in {"prod", "production"} else 30,
    )
    NETWATCH_LOGIN_AUDIT_RETENTION_DAYS: int = _env_int(
        "NETWATCH_LOGIN_AUDIT_RETENTION_DAYS",
        NETWATCH_AUDIT_RETENTION_DAYS,
    )
    NETWATCH_GOVERNANCE_RETENTION_DAYS: int = _env_int(
        "NETWATCH_GOVERNANCE_RETENTION_DAYS",
        NETWATCH_AUDIT_RETENTION_DAYS,
    )
    NETWATCH_AUDIT_RETENTION_EVERY_SECONDS: int = _env_int("NETWATCH_AUDIT_RETENTION_EVERY_SECONDS", 3600)
    NETWATCH_AUDIT_RETENTION_DELETE_BATCH: int = _env_int("NETWATCH_AUDIT_RETENTION_DELETE_BATCH", 5000)

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

    # ClickHouse analytics backend. This is the primary analytical store.
    NETWATCH_CLICKHOUSE_ENABLED: bool = _env_bool("NETWATCH_CLICKHOUSE_ENABLED", True)
    NETWATCH_CLICKHOUSE_REQUIRED: bool = _env_bool("NETWATCH_CLICKHOUSE_REQUIRED", True)
    NETWATCH_CLICKHOUSE_HOST: str = _env_str("NETWATCH_CLICKHOUSE_HOST", "clickhouse") or "clickhouse"
    NETWATCH_CLICKHOUSE_PORT: int = _env_int("NETWATCH_CLICKHOUSE_PORT", 8123)
    NETWATCH_CLICKHOUSE_DATABASE: str = _env_str("NETWATCH_CLICKHOUSE_DATABASE", "netwatch") or "netwatch"
    NETWATCH_CLICKHOUSE_USERNAME: str = _env_str("NETWATCH_CLICKHOUSE_USERNAME", "default") or "default"
    NETWATCH_CLICKHOUSE_PASSWORD: str | None = _env_str("NETWATCH_CLICKHOUSE_PASSWORD", None)
    NETWATCH_CLICKHOUSE_SECURE: bool = _env_bool("NETWATCH_CLICKHOUSE_SECURE", False)
    NETWATCH_CLICKHOUSE_VERIFY: bool = _env_bool("NETWATCH_CLICKHOUSE_VERIFY", True)
    NETWATCH_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS: float = _env_float("NETWATCH_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS", 2.0)
    NETWATCH_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS: float = _env_float("NETWATCH_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS", 5.0)
    NETWATCH_CLICKHOUSE_PING_TTL_SECONDS: int = _env_int("NETWATCH_CLICKHOUSE_PING_TTL_SECONDS", 2)
    NETWATCH_CLICKHOUSE_EVENTS_TABLE: str = _env_str("NETWATCH_CLICKHOUSE_EVENTS_TABLE", "net_events_raw") or "net_events_raw"
    NETWATCH_CLICKHOUSE_EVENTS_RETENTION_DAYS: int = _env_int("NETWATCH_CLICKHOUSE_EVENTS_RETENTION_DAYS", 30)

    # Bootstrap admin user (required on first run).
    NETWATCH_BOOTSTRAP_ADMIN_USERNAME: str = _env_str("NETWATCH_BOOTSTRAP_ADMIN_USERNAME", "admin") or "admin"
    NETWATCH_BOOTSTRAP_ADMIN_PASSWORD: str | None = _env_str("NETWATCH_BOOTSTRAP_ADMIN_PASSWORD", None)
    NETWATCH_BOOTSTRAP_ADMIN_RESET_ON_START: bool = _env_bool(
        "NETWATCH_BOOTSTRAP_ADMIN_RESET_ON_START",
        NETWATCH_ENV in {"dev", "development"},
    )
    # Deprecated compatibility flag. Startup password sync is blocked by default.
    NETWATCH_BOOTSTRAP_ADMIN_SYNC_ON_START: bool = _env_bool(
        "NETWATCH_BOOTSTRAP_ADMIN_SYNC_ON_START",
        False,
    )
    # Explicit break-glass gate required to allow startup password sync.
    NETWATCH_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START: bool = _env_bool(
        "NETWATCH_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START",
        False,
    )

    # Default agent configuration applied on first enroll (JSON object).
    NETWATCH_DEFAULT_AGENT_CONFIG_JSON: str = _env_str("NETWATCH_DEFAULT_AGENT_CONFIG_JSON", "{}") or "{}"

    # Hard limit for agent config payloads (JSON-encoded bytes).
    NETWATCH_MAX_AGENT_CONFIG_BYTES: int = _env_int("NETWATCH_MAX_AGENT_CONFIG_BYTES", 262144)

    # Agent identity/auth hardening.
    # Agents authenticate using rotating credentials bound to agent_id.
    NETWATCH_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS: int = _env_int("NETWATCH_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS", 900)
    NETWATCH_AGENT_BOOTSTRAP_TOKEN_MAX_USES: int = _env_int("NETWATCH_AGENT_BOOTSTRAP_TOKEN_MAX_USES", 1)
    NETWATCH_AGENT_CREDENTIAL_TTL_SECONDS: int = _env_int("NETWATCH_AGENT_CREDENTIAL_TTL_SECONDS", 604800)
    NETWATCH_AGENT_CREDENTIAL_MAX_USES: int = _env_int("NETWATCH_AGENT_CREDENTIAL_MAX_USES", 100000)
    NETWATCH_AGENT_CREDENTIAL_ROTATE_BEFORE_SECONDS: int = _env_int("NETWATCH_AGENT_CREDENTIAL_ROTATE_BEFORE_SECONDS", 86400)

    # Rules worker
    NETWATCH_RULES_EVERY_SECONDS: float = _env_float("NETWATCH_RULES_EVERY_SECONDS", 5.0)
    NETWATCH_RULES_ENV: str = (_env_str("NETWATCH_RULES_ENV", NETWATCH_ENV) or NETWATCH_ENV or "dev").lower()
    NETWATCH_RULES_ENABLED_PACKS: list[str] = _env_csv(
        "NETWATCH_RULES_ENABLED_PACKS",
        "core,network" if NETWATCH_ENV in {"prod", "production"} else "core,network,lab",
    )
    NETWATCH_RULES_DISABLED_PACKS: list[str] = _env_csv("NETWATCH_RULES_DISABLED_PACKS", "")
    NETWATCH_RULES_INCLUDE_EXPERIMENTAL: bool = _env_bool(
        "NETWATCH_RULES_INCLUDE_EXPERIMENTAL",
        NETWATCH_ENV not in {"prod", "production"},
    )

    # Ingest controls
    NETWATCH_MAX_EVENT_CLOCK_SKEW_SECONDS: int = _env_int("NETWATCH_MAX_EVENT_CLOCK_SKEW_SECONDS", 300)
    NETWATCH_INGEST_MAX_BATCH: int = _env_int("NETWATCH_INGEST_MAX_BATCH", 10000)
    NETWATCH_INGEST_ROLLUP_ALWAYS: bool = _env_bool("NETWATCH_INGEST_ROLLUP_ALWAYS", False)
    NETWATCH_INGEST_WARM_ENABLED: bool = _env_bool("NETWATCH_INGEST_WARM_ENABLED", True)
    NETWATCH_INGEST_WARM_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_WARM_SAMPLE_PERCENT", 0)
    NETWATCH_INGEST_STORM_EVENTS_PER_SECOND: int = _env_int("NETWATCH_INGEST_STORM_EVENTS_PER_SECOND", 8000)
    NETWATCH_INGEST_STORM_MIN_BATCH: int = _env_int("NETWATCH_INGEST_STORM_MIN_BATCH", 2500)
    NETWATCH_INGEST_STORM_TTL_SECONDS: int = _env_int("NETWATCH_INGEST_STORM_TTL_SECONDS", 20)
    NETWATCH_INGEST_STORM_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_STORM_SAMPLE_PERCENT", 2)
    NETWATCH_INGEST_STORM_HOT_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_STORM_HOT_SAMPLE_PERCENT", 2)
    NETWATCH_INGEST_STORM_WARM_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_STORM_WARM_SAMPLE_PERCENT", 5)
    NETWATCH_INGEST_STORM_ALERT_TTL_SECONDS: int = _env_int("NETWATCH_INGEST_STORM_ALERT_TTL_SECONDS", 3600)
    NETWATCH_INGEST_QUEUE_KEY: str = _env_str("NETWATCH_INGEST_QUEUE_KEY", "netwatch:ingest:queue") or "netwatch:ingest:queue"
    NETWATCH_INGEST_PROCESSING_KEY: str = _env_str("NETWATCH_INGEST_PROCESSING_KEY", "netwatch:ingest:queue:processing") or "netwatch:ingest:queue:processing"
    NETWATCH_INGEST_BACKLOG_EVENTS_KEY: str = _env_str("NETWATCH_INGEST_BACKLOG_EVENTS_KEY", "netwatch:ingest:backlog_events") or "netwatch:ingest:backlog_events"
    NETWATCH_INGEST_STORM_ACTIVE_KEY: str = _env_str("NETWATCH_INGEST_STORM_ACTIVE_KEY", "netwatch:ingest:storm_active") or "netwatch:ingest:storm_active"
    NETWATCH_INGEST_STORM_SESSION_KEY: str = _env_str("NETWATCH_INGEST_STORM_SESSION_KEY", "netwatch:ingest:storm_session") or "netwatch:ingest:storm_session"
    NETWATCH_INGEST_STORM_SINCE_KEY: str = _env_str("NETWATCH_INGEST_STORM_SINCE_KEY", "netwatch:ingest:storm_since") or "netwatch:ingest:storm_since"
    NETWATCH_INGEST_STORM_ALERT_ID_KEY: str = _env_str("NETWATCH_INGEST_STORM_ALERT_ID_KEY", "netwatch:ingest:storm_alert_id") or "netwatch:ingest:storm_alert_id"
    NETWATCH_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS: int = _env_int("NETWATCH_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS", 50000)
    NETWATCH_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS: int = _env_int("NETWATCH_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS", 200000)
    NETWATCH_INGEST_BACKPRESSURE_MODE: str = (_env_str("NETWATCH_INGEST_BACKPRESSURE_MODE", "rollup_only") or "rollup_only").lower()
    NETWATCH_INGEST_BACKPRESSURE_WARM_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_BACKPRESSURE_WARM_SAMPLE_PERCENT", 2)
    NETWATCH_INGEST_RECENT_FEED_MAX_EVENTS: int = _env_int("NETWATCH_INGEST_RECENT_FEED_MAX_EVENTS", 5000)
    NETWATCH_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS: int = _env_int("NETWATCH_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS", 1000)
    NETWATCH_INGEST_RECENT_FEED_MIN_BATCH: int = _env_int("NETWATCH_INGEST_RECENT_FEED_MIN_BATCH", 24)
    NETWATCH_INGEST_RECENT_FEED_LOOKBACK_SECONDS: int = _env_int("NETWATCH_INGEST_RECENT_FEED_LOOKBACK_SECONDS", 900)
    NETWATCH_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL: int = _env_int("NETWATCH_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL", 512)
    NETWATCH_INGEST_MIN_HOT_EVENTS_PER_BATCH: int = _env_int("NETWATCH_INGEST_MIN_HOT_EVENTS_PER_BATCH", 1)
    NETWATCH_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH: int = _env_int("NETWATCH_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH", 32)
    NETWATCH_INGEST_ELEVATED_HOT_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_ELEVATED_HOT_SAMPLE_PERCENT", 50)
    NETWATCH_INGEST_DEGRADED_HOT_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_DEGRADED_HOT_SAMPLE_PERCENT", 5)
    NETWATCH_INGEST_CRITICAL_HOT_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_CRITICAL_HOT_SAMPLE_PERCENT", 1)
    NETWATCH_INGEST_CLICKHOUSE_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_CLICKHOUSE_SAMPLE_PERCENT", 100)
    NETWATCH_INGEST_DEGRADED_CLICKHOUSE_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_DEGRADED_CLICKHOUSE_SAMPLE_PERCENT", 25)
    NETWATCH_INGEST_CRITICAL_CLICKHOUSE_SAMPLE_PERCENT: int = _env_int("NETWATCH_INGEST_CRITICAL_CLICKHOUSE_SAMPLE_PERCENT", 10)

    # Overview cache/tuning
    NETWATCH_OVERVIEW_CACHE_TTL_SECONDS: int = _env_int("NETWATCH_OVERVIEW_CACHE_TTL_SECONDS", 3)
    NETWATCH_OVERVIEW_CACHE_MAX_ENTRIES: int = _env_int("NETWATCH_OVERVIEW_CACHE_MAX_ENTRIES", 128)
    NETWATCH_OVERVIEW_PRESSURE_LOOKBACK_SECONDS: int = _env_int("NETWATCH_OVERVIEW_PRESSURE_LOOKBACK_SECONDS", 120)
    NETWATCH_OVERVIEW_INGEST_ROLLUP_FRESH_SECONDS: int = _env_int("NETWATCH_OVERVIEW_INGEST_ROLLUP_FRESH_SECONDS", 120)
    NETWATCH_OVERVIEW_DRAINING_BACKLOG_EVENTS_THRESHOLD: int = _env_int("NETWATCH_OVERVIEW_DRAINING_BACKLOG_EVENTS_THRESHOLD", 25000)
    NETWATCH_OVERVIEW_DRAINING_BACKLOG_MESSAGES_THRESHOLD: int = _env_int("NETWATCH_OVERVIEW_DRAINING_BACKLOG_MESSAGES_THRESHOLD", 5)
    NETWATCH_EVENTS_SUMMARY_CACHE_TTL_SECONDS: int = _env_int("NETWATCH_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15)
    NETWATCH_EVENTS_ES_STALE_MARGIN_SECONDS: int = _env_int("NETWATCH_EVENTS_ES_STALE_MARGIN_SECONDS", 15)

    # Vulnerability ingest controls
    NETWATCH_VULN_MAX_FINDINGS_PER_INGEST: int = _env_int("NETWATCH_VULN_MAX_FINDINGS_PER_INGEST", 2000)
    NETWATCH_VULN_MAX_EVIDENCE_BYTES: int = _env_int("NETWATCH_VULN_MAX_EVIDENCE_BYTES", 32768)
    NETWATCH_VULN_AUTO_REOPEN: bool = _env_bool("NETWATCH_VULN_AUTO_REOPEN", True)

    # Protocol intelligence
    NETWATCH_PROTO_INTEL_PORT_HINTS: str = _env_str("NETWATCH_PROTO_INTEL_PORT_HINTS", "") or ""

    @property
    def database_url(self) -> str:
        if self.DB_URL:
            return self.DB_URL

        if not (self.DB_PASSWORD or "").strip():
            raise RuntimeError("NETWATCH_DB_PASSWORD (or NETWATCH_DB_URL) is required.")

        return (
            f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    @staticmethod
    def _looks_insecure_secret(secret: str) -> bool:
        s = (secret or "").strip().lower()
        if not s:
            return True
        known_weak = {
            "admin",
            "password",
            "changeme",
            "change_me",
            "change_me_please",
            "secret",
            "netwatch",
            "netwatch123",
            "deprecated",
        }
        return s in known_weak or "change_me" in s

    def _database_password(self) -> str:
        db_url = (self.DB_URL or "").strip()
        if db_url:
            parsed = urlsplit(db_url)
            if parsed.password:
                return parsed.password.strip()
            return ""
        return (self.DB_PASSWORD or "").strip()

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

    def validate_for_service(self, service: str) -> None:
        svc = (service or "").strip().lower()
        errors: list[str] = []

        if (self.NETWATCH_DB_POOL_SIZE or 0) < 1:
            errors.append("NETWATCH_DB_POOL_SIZE must be >= 1")
        if (self.NETWATCH_DB_MAX_OVERFLOW or 0) < 0:
            errors.append("NETWATCH_DB_MAX_OVERFLOW must be >= 0")
        if (self.NETWATCH_DB_EXECUTEMANY_VALUES_PAGE_SIZE or 0) < 100:
            errors.append("NETWATCH_DB_EXECUTEMANY_VALUES_PAGE_SIZE must be >= 100")
        if (self.NETWATCH_INGEST_MAX_BATCH or 0) < 1:
            errors.append("NETWATCH_INGEST_MAX_BATCH must be >= 1")
        if (self.NETWATCH_MAX_REQUEST_BODY_BYTES or 0) < 1024:
            errors.append("NETWATCH_MAX_REQUEST_BODY_BYTES must be >= 1024")
        if (self.NETWATCH_REDIS_PORT or 0) < 1:
            errors.append("NETWATCH_REDIS_PORT must be >= 1")
        if (self.NETWATCH_AUDIT_RETENTION_DAYS or 0) < 1:
            errors.append("NETWATCH_AUDIT_RETENTION_DAYS must be >= 1")
        if (self.NETWATCH_LOGIN_AUDIT_RETENTION_DAYS or 0) < 1:
            errors.append("NETWATCH_LOGIN_AUDIT_RETENTION_DAYS must be >= 1")
        if (self.NETWATCH_GOVERNANCE_RETENTION_DAYS or 0) < 1:
            errors.append("NETWATCH_GOVERNANCE_RETENTION_DAYS must be >= 1")
        if (self.NETWATCH_AUDIT_RETENTION_EVERY_SECONDS or 0) < 30:
            errors.append("NETWATCH_AUDIT_RETENTION_EVERY_SECONDS must be >= 30")
        if (self.NETWATCH_AUDIT_RETENTION_DELETE_BATCH or 0) < 100:
            errors.append("NETWATCH_AUDIT_RETENTION_DELETE_BATCH must be >= 100")
        if self.NETWATCH_SEARCH_BACKEND not in {"auto", "elasticsearch", "postgres"}:
            errors.append("NETWATCH_SEARCH_BACKEND must be one of: auto, elasticsearch, postgres")
        if (self.NETWATCH_CLICKHOUSE_PORT or 0) < 1:
            errors.append("NETWATCH_CLICKHOUSE_PORT must be >= 1")
        if (self.NETWATCH_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS or 0) <= 0:
            errors.append("NETWATCH_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS must be > 0")
        if (self.NETWATCH_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS or 0) <= 0:
            errors.append("NETWATCH_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS must be > 0")
        if (self.NETWATCH_CLICKHOUSE_PING_TTL_SECONDS or 0) < 1:
            errors.append("NETWATCH_CLICKHOUSE_PING_TTL_SECONDS must be >= 1")
        if (self.NETWATCH_CLICKHOUSE_EVENTS_RETENTION_DAYS or 0) < 1:
            errors.append("NETWATCH_CLICKHOUSE_EVENTS_RETENTION_DAYS must be >= 1")
        if self.NETWATCH_CLICKHOUSE_REQUIRED and not self.NETWATCH_CLICKHOUSE_ENABLED:
            errors.append("NETWATCH_CLICKHOUSE_REQUIRED=true requires NETWATCH_CLICKHOUSE_ENABLED=true")
        if self.NETWATCH_INGEST_BACKPRESSURE_MODE not in {"rollup_only", "reject_429"}:
            errors.append("NETWATCH_INGEST_BACKPRESSURE_MODE must be one of: rollup_only, reject_429")
        if (self.NETWATCH_INGEST_RECENT_FEED_MAX_EVENTS or 0) < 100:
            errors.append("NETWATCH_INGEST_RECENT_FEED_MAX_EVENTS must be >= 100")
        if (self.NETWATCH_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS or 0) < 50:
            errors.append("NETWATCH_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS must be >= 50")
        if (self.NETWATCH_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH or 0) < 1:
            errors.append("NETWATCH_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH must be >= 1")
        if (self.NETWATCH_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL or 0) < 1:
            errors.append("NETWATCH_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL must be >= 1")
        if (self.NETWATCH_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS or 0) < 60:
            errors.append("NETWATCH_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS must be >= 60")
        if (self.NETWATCH_AGENT_BOOTSTRAP_TOKEN_MAX_USES or 0) < 1:
            errors.append("NETWATCH_AGENT_BOOTSTRAP_TOKEN_MAX_USES must be >= 1")

        if svc == "backend-api":
            secret = (self.NETWATCH_JWT_SECRET or "").strip()
            if len(secret) < 32:
                errors.append("NETWATCH_JWT_SECRET is required and must be >= 32 chars")
            if not (self.NETWATCH_JWT_ISSUER or "").strip():
                errors.append("NETWATCH_JWT_ISSUER must be set")
            if not (self.NETWATCH_JWT_AUDIENCE or "").strip():
                errors.append("NETWATCH_JWT_AUDIENCE must be set")
            if self.NETWATCH_ENV in {"prod", "production"} and self._looks_insecure_secret(secret):
                errors.append("NETWATCH_JWT_SECRET cannot use a default/placeholder value in prod")
            if self.NETWATCH_ENV in {"prod", "production"} and not self.NETWATCH_COOKIE_SECURE:
                errors.append("NETWATCH_COOKIE_SECURE must be true in prod")
            if self.NETWATCH_ENV in {"prod", "production"} and not self.NETWATCH_ENABLE_HSTS:
                errors.append("NETWATCH_ENABLE_HSTS must be true in prod")
            if self.NETWATCH_ENV in {"prod", "production"} and not self.NETWATCH_TRUST_PROXY_HEADERS:
                errors.append("NETWATCH_TRUST_PROXY_HEADERS must be true in prod")
            if self.NETWATCH_ENV in {"prod", "production"} and (
                not self.NETWATCH_ALLOWED_HOSTS or self.NETWATCH_ALLOWED_HOSTS == ["*"]
            ):
                errors.append("NETWATCH_ALLOWED_HOSTS cannot be '*' in prod")
            if self.NETWATCH_ENV in {"prod", "production"} and self.NETWATCH_AUDIT_RETENTION_DAYS < 90:
                errors.append("NETWATCH_AUDIT_RETENTION_DAYS must be >= 90 in prod")
            bootstrap_password = (self.NETWATCH_BOOTSTRAP_ADMIN_PASSWORD or "").strip()
            bootstrap_reset_mode = bool(self.NETWATCH_BOOTSTRAP_ADMIN_RESET_ON_START or self.NETWATCH_BOOTSTRAP_ADMIN_SYNC_ON_START)
            if self.NETWATCH_ENV in {"prod", "production"} and bootstrap_reset_mode and len(bootstrap_password) < 12:
                errors.append("NETWATCH_BOOTSTRAP_ADMIN_PASSWORD must be set with >= 12 chars when bootstrap reset/sync is enabled")
            if self.NETWATCH_ENV in {"prod", "production"} and bootstrap_password and self._looks_insecure_secret(bootstrap_password):
                errors.append("NETWATCH_BOOTSTRAP_ADMIN_PASSWORD cannot use a default/placeholder value in prod")
            if self.NETWATCH_ENV in {"prod", "production"} and self.NETWATCH_BOOTSTRAP_ADMIN_RESET_ON_START:
                errors.append("NETWATCH_BOOTSTRAP_ADMIN_RESET_ON_START must be false in prod")
            if self.NETWATCH_BOOTSTRAP_ADMIN_SYNC_ON_START and not self.NETWATCH_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START:
                errors.append(
                    "NETWATCH_BOOTSTRAP_ADMIN_SYNC_ON_START requires NETWATCH_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START=true"
                )
            if self.NETWATCH_ENV in {"prod", "production"} and self.NETWATCH_BOOTSTRAP_ADMIN_SYNC_ON_START:
                errors.append("NETWATCH_BOOTSTRAP_ADMIN_SYNC_ON_START must be false in prod")

            db_password = self._database_password()
            if self.NETWATCH_ENV in {"prod", "production"} and len(db_password) < 12:
                errors.append("Database password must be set with >= 12 chars in prod")
            if self.NETWATCH_ENV in {"prod", "production"} and self._looks_insecure_secret(db_password):
                errors.append("Database password cannot use a default/placeholder value in prod")

            redis_password = (self.NETWATCH_REDIS_PASSWORD or "").strip()
            if self.NETWATCH_ENV in {"prod", "production"} and len(redis_password) < 12:
                errors.append("NETWATCH_REDIS_PASSWORD must be set with >= 12 chars in prod")
            if self.NETWATCH_ENV in {"prod", "production"} and self._looks_insecure_secret(redis_password):
                errors.append("NETWATCH_REDIS_PASSWORD cannot use a default/placeholder value in prod")

            if self.NETWATCH_SEARCH_BACKEND in {"auto", "elasticsearch"}:
                es_username = (self.NETWATCH_ES_USERNAME or "").strip()
                es_password = (self.NETWATCH_ES_PASSWORD or "").strip()
                if self.NETWATCH_ENV in {"prod", "production"} and not es_username:
                    errors.append("NETWATCH_ES_USERNAME is required in prod when Elasticsearch is enabled")
                if self.NETWATCH_ENV in {"prod", "production"} and len(es_password) < 12:
                    errors.append("NETWATCH_ES_PASSWORD must be set with >= 12 chars in prod when Elasticsearch is enabled")
                if self.NETWATCH_ENV in {"prod", "production"} and self._looks_insecure_secret(es_password):
                    errors.append("NETWATCH_ES_PASSWORD cannot use a default/placeholder value in prod")

        if errors:
            raise RuntimeError("Invalid runtime config:\n- " + "\n- ".join(errors))

    def runtime_config_for_admin(self) -> Dict[str, Any]:
        return {
            "environment": self.NETWATCH_ENV,
            "backend": {
                "search_backend": self.NETWATCH_SEARCH_BACKEND,
                "es_url": self.NETWATCH_ES_URL,
                "clickhouse_enabled": bool(self.NETWATCH_CLICKHOUSE_ENABLED),
                "clickhouse_required": bool(self.NETWATCH_CLICKHOUSE_REQUIRED),
                "clickhouse_host": self.NETWATCH_CLICKHOUSE_HOST,
                "clickhouse_port": int(self.NETWATCH_CLICKHOUSE_PORT),
                "clickhouse_database": self.NETWATCH_CLICKHOUSE_DATABASE,
                "clickhouse_events_table": self.NETWATCH_CLICKHOUSE_EVENTS_TABLE,
                "clickhouse_events_retention_days": int(self.NETWATCH_CLICKHOUSE_EVENTS_RETENTION_DAYS),
                "clickhouse_ping_ttl_seconds": int(self.NETWATCH_CLICKHOUSE_PING_TTL_SECONDS),
                "request_body_max_bytes": self.NETWATCH_MAX_REQUEST_BODY_BYTES,
                "clock_skew_max_seconds": self.NETWATCH_MAX_EVENT_CLOCK_SKEW_SECONDS,
                "allowed_hosts": list(self.NETWATCH_ALLOWED_HOSTS or []),
            },
            "ingest": {
                "max_batch": self.NETWATCH_INGEST_MAX_BATCH,
                "storm_eps_limit": self.NETWATCH_INGEST_STORM_EVENTS_PER_SECOND,
                "storm_min_batch": self.NETWATCH_INGEST_STORM_MIN_BATCH,
                "storm_ttl_seconds": self.NETWATCH_INGEST_STORM_TTL_SECONDS,
                "storm_sample_percent": self.NETWATCH_INGEST_STORM_SAMPLE_PERCENT,
                "clickhouse_sample_percent": self.NETWATCH_INGEST_CLICKHOUSE_SAMPLE_PERCENT,
                "degraded_clickhouse_sample_percent": self.NETWATCH_INGEST_DEGRADED_CLICKHOUSE_SAMPLE_PERCENT,
                "critical_clickhouse_sample_percent": self.NETWATCH_INGEST_CRITICAL_CLICKHOUSE_SAMPLE_PERCENT,
                "min_clickhouse_events_per_batch": self.NETWATCH_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH,
                "warm_enabled": bool(self.NETWATCH_INGEST_WARM_ENABLED),
                "backpressure_mode": self.NETWATCH_INGEST_BACKPRESSURE_MODE,
                "backpressure_soft_events": self.NETWATCH_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS,
                "backpressure_hard_events": self.NETWATCH_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS,
                "recent_feed_max_events": self.NETWATCH_INGEST_RECENT_FEED_MAX_EVENTS,
                "recent_feed_per_agent_max_events": self.NETWATCH_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS,
                "recent_feed_min_batch": self.NETWATCH_INGEST_RECENT_FEED_MIN_BATCH,
                "recent_feed_lookback_seconds": self.NETWATCH_INGEST_RECENT_FEED_LOOKBACK_SECONDS,
                "recent_feed_max_push_per_call": self.NETWATCH_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL,
                "queue_key": self.NETWATCH_INGEST_QUEUE_KEY,
                "processing_key": self.NETWATCH_INGEST_PROCESSING_KEY,
            },
            "security": {
                "cookie_secure": bool(self.NETWATCH_COOKIE_SECURE),
                "cookie_samesite": self.NETWATCH_COOKIE_SAMESITE,
                "hsts_enabled": bool(self.NETWATCH_ENABLE_HSTS),
                "trust_proxy_headers": bool(self.NETWATCH_TRUST_PROXY_HEADERS),
                "trusted_proxy_cidrs": self.NETWATCH_TRUSTED_PROXY_CIDRS,
                "audit_retention_enabled": bool(self.NETWATCH_AUDIT_RETENTION_ENABLED),
                "audit_retention_days": int(self.NETWATCH_AUDIT_RETENTION_DAYS),
                "login_audit_retention_days": int(self.NETWATCH_LOGIN_AUDIT_RETENTION_DAYS),
                "governance_retention_days": int(self.NETWATCH_GOVERNANCE_RETENTION_DAYS),
                "has_jwt_secret": bool((self.NETWATCH_JWT_SECRET or "").strip()),
                "jwt_issuer": self.NETWATCH_JWT_ISSUER,
                "jwt_audience": self.NETWATCH_JWT_AUDIENCE,
                "otp_enabled": bool(self.NETWATCH_AUTH_OTP_ENABLED),
                "has_token_pepper": bool((self.NETWATCH_TOKEN_PEPPER or "").strip()),
                "has_audit_hash_pepper": bool((self.NETWATCH_AUDIT_HASH_PEPPER or "").strip()),
                "agent_bootstrap_token_ttl_seconds": int(self.NETWATCH_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS),
                "agent_bootstrap_token_max_uses": int(self.NETWATCH_AGENT_BOOTSTRAP_TOKEN_MAX_USES),
                "bootstrap_admin_sync_on_start": bool(self.NETWATCH_BOOTSTRAP_ADMIN_SYNC_ON_START),
                "bootstrap_admin_allow_sync_on_start": bool(self.NETWATCH_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START),
            },
            "vuln": {
                "max_findings_per_ingest": self.NETWATCH_VULN_MAX_FINDINGS_PER_INGEST,
                "max_evidence_bytes": self.NETWATCH_VULN_MAX_EVIDENCE_BYTES,
                "auto_reopen": bool(self.NETWATCH_VULN_AUTO_REOPEN),
            },
        }


settings = Settings()
