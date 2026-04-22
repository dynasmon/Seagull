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
    SEAGULL_ENV: str = (_env_str("SEAGULL_ENV", "dev") or "dev").lower()
    SEAGULL_DB_AUTO_UPGRADE: bool = _env_bool(
        "SEAGULL_DB_AUTO_UPGRADE",
        SEAGULL_ENV in {"dev", "development"},
    )
    SEAGULL_SKIP_STARTUP_BOOTSTRAP: bool = _env_bool("SEAGULL_SKIP_STARTUP_BOOTSTRAP", False)
    SEAGULL_LOG_LEVEL: str = (_env_str("SEAGULL_LOG_LEVEL", "INFO") or "INFO").upper()

    SEAGULL_REDIS_HOST: str = _env_str("SEAGULL_REDIS_HOST", "redis") or "redis"
    SEAGULL_REDIS_PORT: int = _env_int("SEAGULL_REDIS_PORT", 6379)
    SEAGULL_REDIS_USERNAME: str | None = _env_str("SEAGULL_REDIS_USERNAME", None)
    SEAGULL_REDIS_PASSWORD: str | None = _env_str("SEAGULL_REDIS_PASSWORD", None)
    SEAGULL_REALTIME_STREAM_TOKEN_TTL_SECONDS: int = _env_int("SEAGULL_REALTIME_STREAM_TOKEN_TTL_SECONDS", 30)
    SEAGULL_REALTIME_SSE_KEEPALIVE_SECONDS: int = _env_int("SEAGULL_REALTIME_SSE_KEEPALIVE_SECONDS", 15)
    SEAGULL_REALTIME_STREAM_READ_BLOCK_MS: int = _env_int("SEAGULL_REALTIME_STREAM_READ_BLOCK_MS", 200)
    SEAGULL_REALTIME_REPLAY_DELIVERY_MAX: int = _env_int("SEAGULL_REALTIME_REPLAY_DELIVERY_MAX", 200)
    SEAGULL_REALTIME_WS_KEEPALIVE_SECONDS: int = _env_int("SEAGULL_REALTIME_WS_KEEPALIVE_SECONDS", 20)
    SEAGULL_RULES_DIR: str = _env_str("SEAGULL_RULES_DIR", "/app/rules") or "/app/rules"

    # Optional full SQLAlchemy DSN (preferred). Example:
    #   postgresql+psycopg2://user:pass@postgres:5432/seagull
    DB_URL: str | None = _env_str("SEAGULL_DB_URL", None)

    DB_HOST: str = _env_str("SEAGULL_DB_HOST", "postgres") or "postgres"
    DB_PORT: int = _env_int("SEAGULL_DB_PORT", 5432)
    DB_NAME: str = _env_str("SEAGULL_DB_NAME", "seagull") or "seagull"
    DB_USER: str = _env_str("SEAGULL_DB_USER", "seagull") or "seagull"
    DB_PASSWORD: str | None = _env_str("SEAGULL_DB_PASSWORD", _env_str("POSTGRES_PASSWORD", None))
    SEAGULL_DB_POOL_SIZE: int = _env_int("SEAGULL_DB_POOL_SIZE", 10)
    SEAGULL_DB_MAX_OVERFLOW: int = _env_int("SEAGULL_DB_MAX_OVERFLOW", 20)
    SEAGULL_DB_EXECUTEMANY_MODE: str = _env_str("SEAGULL_DB_EXECUTEMANY_MODE", "values_plus_batch") or "values_plus_batch"
    SEAGULL_DB_EXECUTEMANY_VALUES_PAGE_SIZE: int = _env_int("SEAGULL_DB_EXECUTEMANY_VALUES_PAGE_SIZE", 1000)

    SEAGULL_JWT_SECRET: str | None = _env_str("SEAGULL_JWT_SECRET", None)
    SEAGULL_TOKEN_PEPPER: str | None = _env_str("SEAGULL_TOKEN_PEPPER", None)

    SEAGULL_ACCESS_TOKEN_TTL_SECONDS: int = _env_int("SEAGULL_ACCESS_TOKEN_TTL_SECONDS", 600)
    SEAGULL_REFRESH_TOKEN_TTL_SECONDS: int = _env_int("SEAGULL_REFRESH_TOKEN_TTL_SECONDS", 60 * 60 * 24 * 7)
    SEAGULL_OTP_TOKEN_TTL_SECONDS: int = _env_int("SEAGULL_OTP_TOKEN_TTL_SECONDS", 15 * 60)
    SEAGULL_AUTH_OTP_ENABLED: bool = _env_bool(
        "SEAGULL_AUTH_OTP_ENABLED",
        SEAGULL_ENV not in {"prod", "production"},
    )
    SEAGULL_JWT_ISSUER: str = _env_str("SEAGULL_JWT_ISSUER", "seagull-backend") or "seagull-backend"
    SEAGULL_JWT_AUDIENCE: str = _env_str("SEAGULL_JWT_AUDIENCE", "seagull-portal") or "seagull-portal"

    SEAGULL_COOKIE_SECURE: bool = _env_bool("SEAGULL_COOKIE_SECURE", False)
    SEAGULL_COOKIE_SAMESITE: str = (_env_str("SEAGULL_COOKIE_SAMESITE", "lax") or "lax").lower()
    SEAGULL_COOKIE_DOMAIN: str | None = _env_str("SEAGULL_COOKIE_DOMAIN", None)
    SEAGULL_ENABLE_HSTS: bool = _env_bool("SEAGULL_ENABLE_HSTS", False)
    SEAGULL_TRUST_PROXY_HEADERS: bool = _env_bool("SEAGULL_TRUST_PROXY_HEADERS", False)
    SEAGULL_TRUSTED_PROXY_CIDRS: str = _env_str("SEAGULL_TRUSTED_PROXY_CIDRS", "127.0.0.1,::1") or "127.0.0.1,::1"
    SEAGULL_ALLOWED_HOSTS: list[str] = _env_csv("SEAGULL_ALLOWED_HOSTS", "*")
    SEAGULL_MAX_REQUEST_BODY_BYTES: int = _env_int("SEAGULL_MAX_REQUEST_BODY_BYTES", 2 * 1024 * 1024)
    SEAGULL_AUDIT_HASH_PEPPER: str | None = _env_str("SEAGULL_AUDIT_HASH_PEPPER", None)
    SEAGULL_AUDIT_RETENTION_ENABLED: bool = _env_bool("SEAGULL_AUDIT_RETENTION_ENABLED", True)
    SEAGULL_AUDIT_RETENTION_DAYS: int = _env_int(
        "SEAGULL_AUDIT_RETENTION_DAYS",
        365 if SEAGULL_ENV in {"prod", "production"} else 30,
    )
    SEAGULL_LOGIN_AUDIT_RETENTION_DAYS: int = _env_int(
        "SEAGULL_LOGIN_AUDIT_RETENTION_DAYS",
        SEAGULL_AUDIT_RETENTION_DAYS,
    )
    SEAGULL_GOVERNANCE_RETENTION_DAYS: int = _env_int(
        "SEAGULL_GOVERNANCE_RETENTION_DAYS",
        SEAGULL_AUDIT_RETENTION_DAYS,
    )
    SEAGULL_AUDIT_RETENTION_EVERY_SECONDS: int = _env_int("SEAGULL_AUDIT_RETENTION_EVERY_SECONDS", 3600)
    SEAGULL_AUDIT_RETENTION_DELETE_BATCH: int = _env_int("SEAGULL_AUDIT_RETENTION_DELETE_BATCH", 5000)

    # Search backend selection:
    # - auto: use Elasticsearch when available, fallback to Postgres
    # - elasticsearch: require Elasticsearch (API returns 503 if ES is down)
    # - postgres: always use Postgres
    SEAGULL_SEARCH_BACKEND: str = (_env_str("SEAGULL_SEARCH_BACKEND", "auto") or "auto").lower()

    SEAGULL_ES_URL: str = _env_str("SEAGULL_ES_URL", "http://elasticsearch:9200") or "http://elasticsearch:9200"
    SEAGULL_ES_INDEX_PREFIX: str = _env_str("SEAGULL_ES_INDEX_PREFIX", "seagull-events") or "seagull-events"
    SEAGULL_ES_REQUEST_TIMEOUT_SECONDS: int = _env_int("SEAGULL_ES_REQUEST_TIMEOUT_SECONDS", 30)
    SEAGULL_ES_USERNAME: str | None = _env_str("SEAGULL_ES_USERNAME", None)
    SEAGULL_ES_PASSWORD: str | None = _env_str("SEAGULL_ES_PASSWORD", None)
    SEAGULL_ES_VERIFY_CERTS: bool = _env_bool("SEAGULL_ES_VERIFY_CERTS", True)
    SEAGULL_ES_CA_CERTS: str | None = _env_str("SEAGULL_ES_CA_CERTS", None)
    SEAGULL_ES_PING_TTL_SECONDS: int = _env_int("SEAGULL_ES_PING_TTL_SECONDS", 2)

    SEAGULL_CLICKHOUSE_ENABLED: bool = _env_bool("SEAGULL_CLICKHOUSE_ENABLED", True)
    SEAGULL_CLICKHOUSE_REQUIRED: bool = _env_bool("SEAGULL_CLICKHOUSE_REQUIRED", True)
    SEAGULL_CLICKHOUSE_HOST: str = _env_str("SEAGULL_CLICKHOUSE_HOST", "clickhouse") or "clickhouse"
    SEAGULL_CLICKHOUSE_PORT: int = _env_int("SEAGULL_CLICKHOUSE_PORT", 8123)
    SEAGULL_CLICKHOUSE_DATABASE: str = _env_str("SEAGULL_CLICKHOUSE_DATABASE", "seagull") or "seagull"
    SEAGULL_CLICKHOUSE_USERNAME: str = _env_str("SEAGULL_CLICKHOUSE_USERNAME", "default") or "default"
    SEAGULL_CLICKHOUSE_PASSWORD: str | None = _env_str("SEAGULL_CLICKHOUSE_PASSWORD", None)
    SEAGULL_CLICKHOUSE_SECURE: bool = _env_bool("SEAGULL_CLICKHOUSE_SECURE", False)
    SEAGULL_CLICKHOUSE_VERIFY: bool = _env_bool("SEAGULL_CLICKHOUSE_VERIFY", True)
    SEAGULL_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS: float = _env_float("SEAGULL_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS", 2.0)
    SEAGULL_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS: float = _env_float("SEAGULL_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS", 5.0)
    SEAGULL_CLICKHOUSE_PING_TTL_SECONDS: int = _env_int("SEAGULL_CLICKHOUSE_PING_TTL_SECONDS", 2)
    SEAGULL_CLICKHOUSE_EVENTS_TABLE: str = _env_str("SEAGULL_CLICKHOUSE_EVENTS_TABLE", "net_events_raw") or "net_events_raw"
    SEAGULL_CLICKHOUSE_EVENTS_RETENTION_DAYS: int = _env_int("SEAGULL_CLICKHOUSE_EVENTS_RETENTION_DAYS", 30)

    SEAGULL_BOOTSTRAP_ADMIN_USERNAME: str = _env_str("SEAGULL_BOOTSTRAP_ADMIN_USERNAME", "admin") or "admin"
    SEAGULL_BOOTSTRAP_ADMIN_PASSWORD: str | None = _env_str("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD", None)
    SEAGULL_BOOTSTRAP_ADMIN_RESET_ON_START: bool = _env_bool(
        "SEAGULL_BOOTSTRAP_ADMIN_RESET_ON_START",
        SEAGULL_ENV in {"dev", "development"},
    )
    # Deprecated compatibility flag. Startup password sync is blocked by default.
    SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START: bool = _env_bool(
        "SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START",
        False,
    )
    # Explicit break-glass gate required to allow startup password sync.
    SEAGULL_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START: bool = _env_bool(
        "SEAGULL_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START",
        False,
    )

    SEAGULL_DEFAULT_AGENT_CONFIG_JSON: str = _env_str("SEAGULL_DEFAULT_AGENT_CONFIG_JSON", "{}") or "{}"

    SEAGULL_MAX_AGENT_CONFIG_BYTES: int = _env_int("SEAGULL_MAX_AGENT_CONFIG_BYTES", 262144)

    SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS: int = _env_int("SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS", 900)
    SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES: int = _env_int("SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES", 1)
    SEAGULL_AGENT_CREDENTIAL_TTL_SECONDS: int = _env_int("SEAGULL_AGENT_CREDENTIAL_TTL_SECONDS", 604800)
    SEAGULL_AGENT_CREDENTIAL_MAX_USES: int = _env_int("SEAGULL_AGENT_CREDENTIAL_MAX_USES", 100000)
    SEAGULL_AGENT_CREDENTIAL_ROTATE_BEFORE_SECONDS: int = _env_int("SEAGULL_AGENT_CREDENTIAL_ROTATE_BEFORE_SECONDS", 86400)
    SEAGULL_AGENT_CREDENTIAL_OVERLAP_SECONDS: int = _env_int("SEAGULL_AGENT_CREDENTIAL_OVERLAP_SECONDS", 900)
    SEAGULL_AGENT_RENEWAL_TOKEN_TTL_SECONDS: int = _env_int("SEAGULL_AGENT_RENEWAL_TOKEN_TTL_SECONDS", 2592000)
    SEAGULL_AGENT_RENEWAL_TOKEN_MAX_ACTIVE: int = _env_int("SEAGULL_AGENT_RENEWAL_TOKEN_MAX_ACTIVE", 2)

    SEAGULL_RULES_EVERY_SECONDS: float = _env_float("SEAGULL_RULES_EVERY_SECONDS", 5.0)
    SEAGULL_RULES_ENV: str = (_env_str("SEAGULL_RULES_ENV", SEAGULL_ENV) or SEAGULL_ENV or "dev").lower()
    SEAGULL_RULES_ENABLED_PACKS: list[str] = _env_csv(
        "SEAGULL_RULES_ENABLED_PACKS",
        "core,network,host" if SEAGULL_ENV in {"prod", "production"} else "core,network,host,lab",
    )
    SEAGULL_RULES_DISABLED_PACKS: list[str] = _env_csv("SEAGULL_RULES_DISABLED_PACKS", "")
    SEAGULL_RULES_INCLUDE_EXPERIMENTAL: bool = _env_bool(
        "SEAGULL_RULES_INCLUDE_EXPERIMENTAL",
        SEAGULL_ENV not in {"prod", "production"},
    )

    SEAGULL_MAX_EVENT_CLOCK_SKEW_SECONDS: int = _env_int("SEAGULL_MAX_EVENT_CLOCK_SKEW_SECONDS", 300)
    SEAGULL_INGEST_MAX_BATCH: int = _env_int("SEAGULL_INGEST_MAX_BATCH", 10000)
    SEAGULL_INGEST_ROLLUP_ALWAYS: bool = _env_bool("SEAGULL_INGEST_ROLLUP_ALWAYS", False)
    SEAGULL_INGEST_WARM_ENABLED: bool = _env_bool("SEAGULL_INGEST_WARM_ENABLED", True)
    SEAGULL_INGEST_WARM_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_WARM_SAMPLE_PERCENT", 0)
    SEAGULL_INGEST_STORM_EVENTS_PER_SECOND: int = _env_int("SEAGULL_INGEST_STORM_EVENTS_PER_SECOND", 8000)
    SEAGULL_INGEST_STORM_MIN_BATCH: int = _env_int("SEAGULL_INGEST_STORM_MIN_BATCH", 2500)
    SEAGULL_INGEST_STORM_TTL_SECONDS: int = _env_int("SEAGULL_INGEST_STORM_TTL_SECONDS", 20)
    SEAGULL_INGEST_STORM_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_STORM_SAMPLE_PERCENT", 2)
    SEAGULL_INGEST_STORM_HOT_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_STORM_HOT_SAMPLE_PERCENT", 2)
    SEAGULL_INGEST_STORM_WARM_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_STORM_WARM_SAMPLE_PERCENT", 5)
    SEAGULL_INGEST_STORM_ALERT_TTL_SECONDS: int = _env_int("SEAGULL_INGEST_STORM_ALERT_TTL_SECONDS", 3600)
    SEAGULL_INGEST_QUEUE_KEY: str = _env_str("SEAGULL_INGEST_QUEUE_KEY", "seagull:ingest:queue") or "seagull:ingest:queue"
    SEAGULL_INGEST_PROCESSING_KEY: str = _env_str("SEAGULL_INGEST_PROCESSING_KEY", "seagull:ingest:queue:processing") or "seagull:ingest:queue:processing"
    SEAGULL_INGEST_BACKLOG_EVENTS_KEY: str = _env_str("SEAGULL_INGEST_BACKLOG_EVENTS_KEY", "seagull:ingest:backlog_events") or "seagull:ingest:backlog_events"
    SEAGULL_INGEST_STORM_ACTIVE_KEY: str = _env_str("SEAGULL_INGEST_STORM_ACTIVE_KEY", "seagull:ingest:storm_active") or "seagull:ingest:storm_active"
    SEAGULL_INGEST_STORM_SESSION_KEY: str = _env_str("SEAGULL_INGEST_STORM_SESSION_KEY", "seagull:ingest:storm_session") or "seagull:ingest:storm_session"
    SEAGULL_INGEST_STORM_SINCE_KEY: str = _env_str("SEAGULL_INGEST_STORM_SINCE_KEY", "seagull:ingest:storm_since") or "seagull:ingest:storm_since"
    SEAGULL_INGEST_STORM_ALERT_ID_KEY: str = _env_str("SEAGULL_INGEST_STORM_ALERT_ID_KEY", "seagull:ingest:storm_alert_id") or "seagull:ingest:storm_alert_id"
    SEAGULL_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS: int = _env_int("SEAGULL_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS", 50000)
    SEAGULL_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS: int = _env_int("SEAGULL_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS", 200000)
    SEAGULL_INGEST_BACKPRESSURE_MODE: str = (_env_str("SEAGULL_INGEST_BACKPRESSURE_MODE", "rollup_only") or "rollup_only").lower()
    SEAGULL_INGEST_BACKPRESSURE_WARM_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_BACKPRESSURE_WARM_SAMPLE_PERCENT", 2)
    SEAGULL_INGEST_RECENT_FEED_MAX_EVENTS: int = _env_int("SEAGULL_INGEST_RECENT_FEED_MAX_EVENTS", 5000)
    SEAGULL_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS: int = _env_int("SEAGULL_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS", 1000)
    SEAGULL_INGEST_RECENT_FEED_MIN_BATCH: int = _env_int("SEAGULL_INGEST_RECENT_FEED_MIN_BATCH", 24)
    SEAGULL_INGEST_RECENT_FEED_LOOKBACK_SECONDS: int = _env_int("SEAGULL_INGEST_RECENT_FEED_LOOKBACK_SECONDS", 900)
    SEAGULL_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL: int = _env_int("SEAGULL_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL", 512)
    SEAGULL_INGEST_MIN_HOT_EVENTS_PER_BATCH: int = _env_int("SEAGULL_INGEST_MIN_HOT_EVENTS_PER_BATCH", 1)
    SEAGULL_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH: int = _env_int("SEAGULL_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH", 32)
    SEAGULL_INGEST_ELEVATED_HOT_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_ELEVATED_HOT_SAMPLE_PERCENT", 50)
    SEAGULL_INGEST_DEGRADED_HOT_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_DEGRADED_HOT_SAMPLE_PERCENT", 5)
    SEAGULL_INGEST_CRITICAL_HOT_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_CRITICAL_HOT_SAMPLE_PERCENT", 1)
    SEAGULL_INGEST_CLICKHOUSE_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_CLICKHOUSE_SAMPLE_PERCENT", 100)
    SEAGULL_INGEST_DEGRADED_CLICKHOUSE_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_DEGRADED_CLICKHOUSE_SAMPLE_PERCENT", 25)
    SEAGULL_INGEST_CRITICAL_CLICKHOUSE_SAMPLE_PERCENT: int = _env_int("SEAGULL_INGEST_CRITICAL_CLICKHOUSE_SAMPLE_PERCENT", 10)

    SEAGULL_OVERVIEW_CACHE_TTL_SECONDS: int = _env_int("SEAGULL_OVERVIEW_CACHE_TTL_SECONDS", 3)
    SEAGULL_OVERVIEW_CACHE_MAX_ENTRIES: int = _env_int("SEAGULL_OVERVIEW_CACHE_MAX_ENTRIES", 128)
    SEAGULL_OVERVIEW_PRESSURE_LOOKBACK_SECONDS: int = _env_int("SEAGULL_OVERVIEW_PRESSURE_LOOKBACK_SECONDS", 120)
    SEAGULL_OVERVIEW_INGEST_ROLLUP_FRESH_SECONDS: int = _env_int("SEAGULL_OVERVIEW_INGEST_ROLLUP_FRESH_SECONDS", 120)
    SEAGULL_OVERVIEW_DRAINING_BACKLOG_EVENTS_THRESHOLD: int = _env_int("SEAGULL_OVERVIEW_DRAINING_BACKLOG_EVENTS_THRESHOLD", 25000)
    SEAGULL_OVERVIEW_DRAINING_BACKLOG_MESSAGES_THRESHOLD: int = _env_int("SEAGULL_OVERVIEW_DRAINING_BACKLOG_MESSAGES_THRESHOLD", 5)
    SEAGULL_EVENTS_SUMMARY_CACHE_TTL_SECONDS: int = _env_int("SEAGULL_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15)
    SEAGULL_EVENTS_ES_STALE_MARGIN_SECONDS: int = _env_int("SEAGULL_EVENTS_ES_STALE_MARGIN_SECONDS", 15)

    SEAGULL_VULN_MAX_FINDINGS_PER_INGEST: int = _env_int("SEAGULL_VULN_MAX_FINDINGS_PER_INGEST", 2000)
    SEAGULL_VULN_MAX_EVIDENCE_BYTES: int = _env_int("SEAGULL_VULN_MAX_EVIDENCE_BYTES", 32768)

    SEAGULL_PROTO_INTEL_PORT_HINTS: str = _env_str("SEAGULL_PROTO_INTEL_PORT_HINTS", "") or ""

    SEAGULL_HEUR_MAX_ROWS: int = _env_int("SEAGULL_HEUR_MAX_ROWS", 50000)
    SEAGULL_HEUR_BEACON_WINDOW_SECONDS: int = _env_int("SEAGULL_HEUR_BEACON_WINDOW_SECONDS", 3600)
    SEAGULL_HEUR_BEACON_MIN_EVENTS: int = _env_int("SEAGULL_HEUR_BEACON_MIN_EVENTS", 7)
    SEAGULL_HEUR_BEACON_MIN_INTERVAL_SECONDS: float = _env_float("SEAGULL_HEUR_BEACON_MIN_INTERVAL_SECONDS", 8.0)
    SEAGULL_HEUR_BEACON_MAX_INTERVAL_SECONDS: float = _env_float("SEAGULL_HEUR_BEACON_MAX_INTERVAL_SECONDS", 900.0)
    SEAGULL_HEUR_BEACON_MAX_JITTER: float = _env_float("SEAGULL_HEUR_BEACON_MAX_JITTER", 0.22)
    SEAGULL_HEUR_BEACON_COOLDOWN_SECONDS: int = _env_int("SEAGULL_HEUR_BEACON_COOLDOWN_SECONDS", 900)

    SEAGULL_HEUR_EXFIL_BASELINE_SECONDS: int = _env_int("SEAGULL_HEUR_EXFIL_BASELINE_SECONDS", 86400)
    SEAGULL_HEUR_EXFIL_WINDOW_SECONDS: int = _env_int("SEAGULL_HEUR_EXFIL_WINDOW_SECONDS", 600)
    SEAGULL_HEUR_EXFIL_MIN_EVENTS: int = _env_int("SEAGULL_HEUR_EXFIL_MIN_EVENTS", 8)
    SEAGULL_HEUR_EXFIL_MIN_BYTES: int = _env_int("SEAGULL_HEUR_EXFIL_MIN_BYTES", 8 * 1024 * 1024)
    SEAGULL_HEUR_EXFIL_SPIKE_FACTOR: float = _env_float("SEAGULL_HEUR_EXFIL_SPIKE_FACTOR", 3.0)
    SEAGULL_HEUR_EXFIL_RARE_BASELINE_EVENTS: int = _env_int("SEAGULL_HEUR_EXFIL_RARE_BASELINE_EVENTS", 5)
    SEAGULL_HEUR_EXFIL_COOLDOWN_SECONDS: int = _env_int("SEAGULL_HEUR_EXFIL_COOLDOWN_SECONDS", 1200)

    SEAGULL_HEUR_EGRESS_BASELINE_SECONDS: int = _env_int("SEAGULL_HEUR_EGRESS_BASELINE_SECONDS", 21600)
    SEAGULL_HEUR_EGRESS_WINDOW_SECONDS: int = _env_int("SEAGULL_HEUR_EGRESS_WINDOW_SECONDS", 900)
    SEAGULL_HEUR_EGRESS_MIN_EVENTS: int = _env_int("SEAGULL_HEUR_EGRESS_MIN_EVENTS", 5)
    SEAGULL_HEUR_EGRESS_MIN_BYTES: int = _env_int("SEAGULL_HEUR_EGRESS_MIN_BYTES", 2 * 1024 * 1024)
    SEAGULL_HEUR_EGRESS_SPIKE_FACTOR: float = _env_float("SEAGULL_HEUR_EGRESS_SPIKE_FACTOR", 2.5)
    SEAGULL_HEUR_EGRESS_RARE_BASELINE_EVENTS: int = _env_int("SEAGULL_HEUR_EGRESS_RARE_BASELINE_EVENTS", 3)
    SEAGULL_HEUR_EGRESS_CORRELATION_SECONDS: int = _env_int("SEAGULL_HEUR_EGRESS_CORRELATION_SECONDS", 900)
    SEAGULL_HEUR_EGRESS_COOLDOWN_SECONDS: int = _env_int("SEAGULL_HEUR_EGRESS_COOLDOWN_SECONDS", 1200)

    @property
    def database_url(self) -> str:
        if self.DB_URL:
            return self.DB_URL

        if not (self.DB_PASSWORD or "").strip():
            raise RuntimeError("SEAGULL_DB_PASSWORD (or SEAGULL_DB_URL) is required.")

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
            "seagull",
            "seagull123",
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
        raw = (self.SEAGULL_DEFAULT_AGENT_CONFIG_JSON or "{}").strip() or "{}"
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
        return (self.SEAGULL_TOKEN_PEPPER or self.SEAGULL_JWT_SECRET or "").strip()

    def validate_for_service(self, service: str) -> None:
        svc = (service or "").strip().lower()
        errors: list[str] = []

        if (self.SEAGULL_DB_POOL_SIZE or 0) < 1:
            errors.append("SEAGULL_DB_POOL_SIZE must be >= 1")
        if (self.SEAGULL_DB_MAX_OVERFLOW or 0) < 0:
            errors.append("SEAGULL_DB_MAX_OVERFLOW must be >= 0")
        if (self.SEAGULL_DB_EXECUTEMANY_VALUES_PAGE_SIZE or 0) < 100:
            errors.append("SEAGULL_DB_EXECUTEMANY_VALUES_PAGE_SIZE must be >= 100")
        if (self.SEAGULL_INGEST_MAX_BATCH or 0) < 1:
            errors.append("SEAGULL_INGEST_MAX_BATCH must be >= 1")
        if (self.SEAGULL_MAX_REQUEST_BODY_BYTES or 0) < 1024:
            errors.append("SEAGULL_MAX_REQUEST_BODY_BYTES must be >= 1024")
        if (self.SEAGULL_REDIS_PORT or 0) < 1:
            errors.append("SEAGULL_REDIS_PORT must be >= 1")
        if (self.SEAGULL_REALTIME_STREAM_TOKEN_TTL_SECONDS or 0) < 5:
            errors.append("SEAGULL_REALTIME_STREAM_TOKEN_TTL_SECONDS must be >= 5")
        if (self.SEAGULL_REALTIME_STREAM_TOKEN_TTL_SECONDS or 0) > 300:
            errors.append("SEAGULL_REALTIME_STREAM_TOKEN_TTL_SECONDS must be <= 300")
        if (self.SEAGULL_REALTIME_SSE_KEEPALIVE_SECONDS or 0) < 5:
            errors.append("SEAGULL_REALTIME_SSE_KEEPALIVE_SECONDS must be >= 5")
        if (self.SEAGULL_REALTIME_SSE_KEEPALIVE_SECONDS or 0) > 60:
            errors.append("SEAGULL_REALTIME_SSE_KEEPALIVE_SECONDS must be <= 60")
        if (self.SEAGULL_REALTIME_STREAM_READ_BLOCK_MS or 0) < 100:
            errors.append("SEAGULL_REALTIME_STREAM_READ_BLOCK_MS must be >= 100")
        if (self.SEAGULL_REALTIME_STREAM_READ_BLOCK_MS or 0) > 5000:
            errors.append("SEAGULL_REALTIME_STREAM_READ_BLOCK_MS must be <= 5000")
        if (self.SEAGULL_REALTIME_REPLAY_DELIVERY_MAX or 0) < 16:
            errors.append("SEAGULL_REALTIME_REPLAY_DELIVERY_MAX must be >= 16")
        if (self.SEAGULL_REALTIME_REPLAY_DELIVERY_MAX or 0) > 5000:
            errors.append("SEAGULL_REALTIME_REPLAY_DELIVERY_MAX must be <= 5000")
        if (self.SEAGULL_REALTIME_WS_KEEPALIVE_SECONDS or 0) < 5:
            errors.append("SEAGULL_REALTIME_WS_KEEPALIVE_SECONDS must be >= 5")
        if (self.SEAGULL_REALTIME_WS_KEEPALIVE_SECONDS or 0) > 60:
            errors.append("SEAGULL_REALTIME_WS_KEEPALIVE_SECONDS must be <= 60")
        if (self.SEAGULL_AUDIT_RETENTION_DAYS or 0) < 1:
            errors.append("SEAGULL_AUDIT_RETENTION_DAYS must be >= 1")
        if (self.SEAGULL_LOGIN_AUDIT_RETENTION_DAYS or 0) < 1:
            errors.append("SEAGULL_LOGIN_AUDIT_RETENTION_DAYS must be >= 1")
        if (self.SEAGULL_GOVERNANCE_RETENTION_DAYS or 0) < 1:
            errors.append("SEAGULL_GOVERNANCE_RETENTION_DAYS must be >= 1")
        if (self.SEAGULL_AUDIT_RETENTION_EVERY_SECONDS or 0) < 30:
            errors.append("SEAGULL_AUDIT_RETENTION_EVERY_SECONDS must be >= 30")
        if (self.SEAGULL_AUDIT_RETENTION_DELETE_BATCH or 0) < 100:
            errors.append("SEAGULL_AUDIT_RETENTION_DELETE_BATCH must be >= 100")
        if self.SEAGULL_SEARCH_BACKEND not in {"auto", "elasticsearch", "postgres"}:
            errors.append("SEAGULL_SEARCH_BACKEND must be one of: auto, elasticsearch, postgres")
        if (self.SEAGULL_CLICKHOUSE_PORT or 0) < 1:
            errors.append("SEAGULL_CLICKHOUSE_PORT must be >= 1")
        if (self.SEAGULL_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS or 0) <= 0:
            errors.append("SEAGULL_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS must be > 0")
        if (self.SEAGULL_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS or 0) <= 0:
            errors.append("SEAGULL_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS must be > 0")
        if (self.SEAGULL_CLICKHOUSE_PING_TTL_SECONDS or 0) < 1:
            errors.append("SEAGULL_CLICKHOUSE_PING_TTL_SECONDS must be >= 1")
        if (self.SEAGULL_CLICKHOUSE_EVENTS_RETENTION_DAYS or 0) < 1:
            errors.append("SEAGULL_CLICKHOUSE_EVENTS_RETENTION_DAYS must be >= 1")
        if self.SEAGULL_CLICKHOUSE_REQUIRED and not self.SEAGULL_CLICKHOUSE_ENABLED:
            errors.append("SEAGULL_CLICKHOUSE_REQUIRED=true requires SEAGULL_CLICKHOUSE_ENABLED=true")
        if self.SEAGULL_INGEST_BACKPRESSURE_MODE not in {"rollup_only", "reject_429"}:
            errors.append("SEAGULL_INGEST_BACKPRESSURE_MODE must be one of: rollup_only, reject_429")
        if (self.SEAGULL_INGEST_RECENT_FEED_MAX_EVENTS or 0) < 100:
            errors.append("SEAGULL_INGEST_RECENT_FEED_MAX_EVENTS must be >= 100")
        if (self.SEAGULL_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS or 0) < 50:
            errors.append("SEAGULL_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS must be >= 50")
        if (self.SEAGULL_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH or 0) < 1:
            errors.append("SEAGULL_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH must be >= 1")
        if (self.SEAGULL_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL or 0) < 1:
            errors.append("SEAGULL_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL must be >= 1")
        if (self.SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS or 0) < 60:
            errors.append("SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS must be >= 60")
        if (self.SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES or 0) < 1:
            errors.append("SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES must be >= 1")
        if (self.SEAGULL_AGENT_CREDENTIAL_TTL_SECONDS or 0) < 300:
            errors.append("SEAGULL_AGENT_CREDENTIAL_TTL_SECONDS must be >= 300")
        if (self.SEAGULL_AGENT_CREDENTIAL_MAX_USES or 0) < 1:
            errors.append("SEAGULL_AGENT_CREDENTIAL_MAX_USES must be >= 1")
        if (self.SEAGULL_AGENT_CREDENTIAL_ROTATE_BEFORE_SECONDS or 0) < 60:
            errors.append("SEAGULL_AGENT_CREDENTIAL_ROTATE_BEFORE_SECONDS must be >= 60")
        if (self.SEAGULL_AGENT_CREDENTIAL_OVERLAP_SECONDS or 0) < 0:
            errors.append("SEAGULL_AGENT_CREDENTIAL_OVERLAP_SECONDS must be >= 0")
        if (self.SEAGULL_AGENT_RENEWAL_TOKEN_TTL_SECONDS or 0) < 3600:
            errors.append("SEAGULL_AGENT_RENEWAL_TOKEN_TTL_SECONDS must be >= 3600")
        if (self.SEAGULL_AGENT_RENEWAL_TOKEN_MAX_ACTIVE or 0) < 1:
            errors.append("SEAGULL_AGENT_RENEWAL_TOKEN_MAX_ACTIVE must be >= 1")

        if svc == "backend-api":
            secret = (self.SEAGULL_JWT_SECRET or "").strip()
            if len(secret) < 32:
                errors.append("SEAGULL_JWT_SECRET is required and must be >= 32 chars")
            if not (self.SEAGULL_JWT_ISSUER or "").strip():
                errors.append("SEAGULL_JWT_ISSUER must be set")
            if not (self.SEAGULL_JWT_AUDIENCE or "").strip():
                errors.append("SEAGULL_JWT_AUDIENCE must be set")
            if self.SEAGULL_ENV in {"prod", "production"} and self._looks_insecure_secret(secret):
                errors.append("SEAGULL_JWT_SECRET cannot use a default/placeholder value in prod")
            if self.SEAGULL_ENV in {"prod", "production"} and not self.SEAGULL_COOKIE_SECURE:
                errors.append("SEAGULL_COOKIE_SECURE must be true in prod")
            if self.SEAGULL_ENV in {"prod", "production"} and not self.SEAGULL_ENABLE_HSTS:
                errors.append("SEAGULL_ENABLE_HSTS must be true in prod")
            if self.SEAGULL_ENV in {"prod", "production"} and not self.SEAGULL_TRUST_PROXY_HEADERS:
                errors.append("SEAGULL_TRUST_PROXY_HEADERS must be true in prod")
            if self.SEAGULL_ENV in {"prod", "production"} and (
                not self.SEAGULL_ALLOWED_HOSTS or self.SEAGULL_ALLOWED_HOSTS == ["*"]
            ):
                errors.append("SEAGULL_ALLOWED_HOSTS cannot be '*' in prod")
            if self.SEAGULL_ENV in {"prod", "production"} and self.SEAGULL_AUDIT_RETENTION_DAYS < 90:
                errors.append("SEAGULL_AUDIT_RETENTION_DAYS must be >= 90 in prod")
            bootstrap_password = (self.SEAGULL_BOOTSTRAP_ADMIN_PASSWORD or "").strip()
            bootstrap_reset_mode = bool(self.SEAGULL_BOOTSTRAP_ADMIN_RESET_ON_START or self.SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START)
            if self.SEAGULL_ENV in {"prod", "production"} and bootstrap_reset_mode and len(bootstrap_password) < 12:
                errors.append("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD must be set with >= 12 chars when bootstrap reset/sync is enabled")
            if self.SEAGULL_ENV in {"prod", "production"} and bootstrap_password and self._looks_insecure_secret(bootstrap_password):
                errors.append("SEAGULL_BOOTSTRAP_ADMIN_PASSWORD cannot use a default/placeholder value in prod")
            if self.SEAGULL_ENV in {"prod", "production"} and self.SEAGULL_BOOTSTRAP_ADMIN_RESET_ON_START:
                errors.append("SEAGULL_BOOTSTRAP_ADMIN_RESET_ON_START must be false in prod")
            if self.SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START and not self.SEAGULL_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START:
                errors.append(
                    "SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START requires SEAGULL_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START=true"
                )
            if self.SEAGULL_ENV in {"prod", "production"} and self.SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START:
                errors.append("SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START must be false in prod")

            db_password = self._database_password()
            if self.SEAGULL_ENV in {"prod", "production"} and len(db_password) < 12:
                errors.append("Database password must be set with >= 12 chars in prod")
            if self.SEAGULL_ENV in {"prod", "production"} and self._looks_insecure_secret(db_password):
                errors.append("Database password cannot use a default/placeholder value in prod")

            redis_password = (self.SEAGULL_REDIS_PASSWORD or "").strip()
            if self.SEAGULL_ENV in {"prod", "production"} and len(redis_password) < 12:
                errors.append("SEAGULL_REDIS_PASSWORD must be set with >= 12 chars in prod")
            if self.SEAGULL_ENV in {"prod", "production"} and self._looks_insecure_secret(redis_password):
                errors.append("SEAGULL_REDIS_PASSWORD cannot use a default/placeholder value in prod")

            if self.SEAGULL_SEARCH_BACKEND in {"auto", "elasticsearch"}:
                es_username = (self.SEAGULL_ES_USERNAME or "").strip()
                es_password = (self.SEAGULL_ES_PASSWORD or "").strip()
                if self.SEAGULL_ENV in {"prod", "production"} and not es_username:
                    errors.append("SEAGULL_ES_USERNAME is required in prod when Elasticsearch is enabled")
                if self.SEAGULL_ENV in {"prod", "production"} and len(es_password) < 12:
                    errors.append("SEAGULL_ES_PASSWORD must be set with >= 12 chars in prod when Elasticsearch is enabled")
                if self.SEAGULL_ENV in {"prod", "production"} and self._looks_insecure_secret(es_password):
                    errors.append("SEAGULL_ES_PASSWORD cannot use a default/placeholder value in prod")

        if errors:
            raise RuntimeError("Invalid runtime config:\n- " + "\n- ".join(errors))

    def runtime_config_for_admin(self) -> Dict[str, Any]:
        return {
            "environment": self.SEAGULL_ENV,
            "backend": {
                "search_backend": self.SEAGULL_SEARCH_BACKEND,
                "es_url": self.SEAGULL_ES_URL,
                "clickhouse_enabled": bool(self.SEAGULL_CLICKHOUSE_ENABLED),
                "clickhouse_required": bool(self.SEAGULL_CLICKHOUSE_REQUIRED),
                "clickhouse_host": self.SEAGULL_CLICKHOUSE_HOST,
                "clickhouse_port": int(self.SEAGULL_CLICKHOUSE_PORT),
                "clickhouse_database": self.SEAGULL_CLICKHOUSE_DATABASE,
                "clickhouse_events_table": self.SEAGULL_CLICKHOUSE_EVENTS_TABLE,
                "clickhouse_events_retention_days": int(self.SEAGULL_CLICKHOUSE_EVENTS_RETENTION_DAYS),
                "clickhouse_ping_ttl_seconds": int(self.SEAGULL_CLICKHOUSE_PING_TTL_SECONDS),
                "request_body_max_bytes": self.SEAGULL_MAX_REQUEST_BODY_BYTES,
                "clock_skew_max_seconds": self.SEAGULL_MAX_EVENT_CLOCK_SKEW_SECONDS,
                "allowed_hosts": list(self.SEAGULL_ALLOWED_HOSTS or []),
                "realtime_stream_token_ttl_seconds": int(self.SEAGULL_REALTIME_STREAM_TOKEN_TTL_SECONDS),
                "realtime_sse_keepalive_seconds": int(self.SEAGULL_REALTIME_SSE_KEEPALIVE_SECONDS),
                "realtime_stream_read_block_ms": int(self.SEAGULL_REALTIME_STREAM_READ_BLOCK_MS),
                "realtime_replay_delivery_max": int(self.SEAGULL_REALTIME_REPLAY_DELIVERY_MAX),
                "realtime_ws_keepalive_seconds": int(self.SEAGULL_REALTIME_WS_KEEPALIVE_SECONDS),
            },
            "ingest": {
                "max_batch": self.SEAGULL_INGEST_MAX_BATCH,
                "storm_eps_limit": self.SEAGULL_INGEST_STORM_EVENTS_PER_SECOND,
                "storm_min_batch": self.SEAGULL_INGEST_STORM_MIN_BATCH,
                "storm_ttl_seconds": self.SEAGULL_INGEST_STORM_TTL_SECONDS,
                "storm_sample_percent": self.SEAGULL_INGEST_STORM_SAMPLE_PERCENT,
                "clickhouse_sample_percent": self.SEAGULL_INGEST_CLICKHOUSE_SAMPLE_PERCENT,
                "degraded_clickhouse_sample_percent": self.SEAGULL_INGEST_DEGRADED_CLICKHOUSE_SAMPLE_PERCENT,
                "critical_clickhouse_sample_percent": self.SEAGULL_INGEST_CRITICAL_CLICKHOUSE_SAMPLE_PERCENT,
                "min_clickhouse_events_per_batch": self.SEAGULL_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH,
                "warm_enabled": bool(self.SEAGULL_INGEST_WARM_ENABLED),
                "backpressure_mode": self.SEAGULL_INGEST_BACKPRESSURE_MODE,
                "backpressure_soft_events": self.SEAGULL_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS,
                "backpressure_hard_events": self.SEAGULL_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS,
                "recent_feed_max_events": self.SEAGULL_INGEST_RECENT_FEED_MAX_EVENTS,
                "recent_feed_per_agent_max_events": self.SEAGULL_INGEST_RECENT_FEED_PER_AGENT_MAX_EVENTS,
                "recent_feed_min_batch": self.SEAGULL_INGEST_RECENT_FEED_MIN_BATCH,
                "recent_feed_lookback_seconds": self.SEAGULL_INGEST_RECENT_FEED_LOOKBACK_SECONDS,
                "recent_feed_max_push_per_call": self.SEAGULL_INGEST_RECENT_FEED_MAX_PUSH_PER_CALL,
                "queue_key": self.SEAGULL_INGEST_QUEUE_KEY,
                "processing_key": self.SEAGULL_INGEST_PROCESSING_KEY,
            },
            "security": {
                "cookie_secure": bool(self.SEAGULL_COOKIE_SECURE),
                "cookie_samesite": self.SEAGULL_COOKIE_SAMESITE,
                "hsts_enabled": bool(self.SEAGULL_ENABLE_HSTS),
                "trust_proxy_headers": bool(self.SEAGULL_TRUST_PROXY_HEADERS),
                "trusted_proxy_cidrs": self.SEAGULL_TRUSTED_PROXY_CIDRS,
                "audit_retention_enabled": bool(self.SEAGULL_AUDIT_RETENTION_ENABLED),
                "audit_retention_days": int(self.SEAGULL_AUDIT_RETENTION_DAYS),
                "login_audit_retention_days": int(self.SEAGULL_LOGIN_AUDIT_RETENTION_DAYS),
                "governance_retention_days": int(self.SEAGULL_GOVERNANCE_RETENTION_DAYS),
                "has_jwt_secret": bool((self.SEAGULL_JWT_SECRET or "").strip()),
                "jwt_issuer": self.SEAGULL_JWT_ISSUER,
                "jwt_audience": self.SEAGULL_JWT_AUDIENCE,
                "otp_enabled": bool(self.SEAGULL_AUTH_OTP_ENABLED),
                "has_token_pepper": bool((self.SEAGULL_TOKEN_PEPPER or "").strip()),
                "has_audit_hash_pepper": bool((self.SEAGULL_AUDIT_HASH_PEPPER or "").strip()),
                "agent_bootstrap_token_ttl_seconds": int(self.SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS),
                "agent_bootstrap_token_max_uses": int(self.SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES),
                "agent_credential_ttl_seconds": int(self.SEAGULL_AGENT_CREDENTIAL_TTL_SECONDS),
                "agent_credential_max_uses": int(self.SEAGULL_AGENT_CREDENTIAL_MAX_USES),
                "agent_credential_rotate_before_seconds": int(self.SEAGULL_AGENT_CREDENTIAL_ROTATE_BEFORE_SECONDS),
                "agent_credential_overlap_seconds": int(self.SEAGULL_AGENT_CREDENTIAL_OVERLAP_SECONDS),
                "agent_renewal_token_ttl_seconds": int(self.SEAGULL_AGENT_RENEWAL_TOKEN_TTL_SECONDS),
                "agent_renewal_token_max_active": int(self.SEAGULL_AGENT_RENEWAL_TOKEN_MAX_ACTIVE),
                "bootstrap_admin_sync_on_start": bool(self.SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START),
                "bootstrap_admin_allow_sync_on_start": bool(self.SEAGULL_BOOTSTRAP_ADMIN_ALLOW_SYNC_ON_START),
            },
            "vuln": {
                "max_findings_per_ingest": self.SEAGULL_VULN_MAX_FINDINGS_PER_INGEST,
                "max_evidence_bytes": self.SEAGULL_VULN_MAX_EVIDENCE_BYTES,
            },
        }


settings = Settings()
