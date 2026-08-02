from __future__ import annotations

import os
import re
from datetime import date
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parent.parent.parent

_DEPRECATED_KEYS = [
    "COMPOSE_IGNORE_ORPHANS",
    "SEAGULL_AGENT_LOCAL_RECONCILE",
    "SEAGULL_SKIP_AGENT_RECONCILE",
    "SEAGULL_API_URL",
    "SEAGULL_ENROLL_URL",
    "SEAGULL_AGENT_TLS_SERVER_NAME",
    "SEAGULL_AGENT_SERVER_CA_FILE",
    "AGENT_CORE_ID",
    "AGENT_SENSOR_ID",
    "AGENT_LATERAL_ID",
    "AGENT_PROC_ID",
    "AGENT_SCAN_ID",
    "AGENT_DDOS_ID",
    "AGENT_VULN_ID",
    "AGENT_CORE_BOOTSTRAP_TOKEN",
    "AGENT_SENSOR_BOOTSTRAP_TOKEN",
    "AGENT_LATERAL_BOOTSTRAP_TOKEN",
    "AGENT_PROC_BOOTSTRAP_TOKEN",
    "AGENT_SCAN_BOOTSTRAP_TOKEN",
    "AGENT_DDOS_BOOTSTRAP_TOKEN",
    "AGENT_VULN_BOOTSTRAP_TOKEN",
    "AGENT_CORE_BOOTSTRAP_TOKEN_FILE",
    "AGENT_SENSOR_BOOTSTRAP_TOKEN_FILE",
    "AGENT_LATERAL_BOOTSTRAP_TOKEN_FILE",
    "AGENT_PROC_BOOTSTRAP_TOKEN_FILE",
    "AGENT_SCAN_BOOTSTRAP_TOKEN_FILE",
    "AGENT_DDOS_BOOTSTRAP_TOKEN_FILE",
    "AGENT_VULN_BOOTSTRAP_TOKEN_FILE",
    "SEAGULL_AUDIT_RETENTION_DAYS_PROD",
    "SEAGULL_AUTH_OTP_ENABLED_PROD",
    "SEAGULL_BOOTSTRAP_ADMIN_SYNC_ON_START_PROD",
    "SEAGULL_DB_AUTO_UPGRADE_PROD",
    "SEAGULL_GOVERNANCE_RETENTION_DAYS_PROD",
    "SEAGULL_LOGIN_AUDIT_RETENTION_DAYS_PROD",
    "SEAGULL_PROD_BACKEND_PORT",
    "SEAGULL_PROD_DB_MAX_OVERFLOW",
    "SEAGULL_PROD_DB_POOL_SIZE",
    "SEAGULL_PROD_DB_READ_MAX_OVERFLOW",
    "SEAGULL_PROD_DB_READ_POOL_SIZE",
    "SEAGULL_PROD_DB_REPLICA_HOSTS",
    "SEAGULL_PROD_ES01_PORT",
    "SEAGULL_PROD_ES02_PORT",
    "SEAGULL_PROD_ES03_PORT",
    "SEAGULL_PROD_ES_CLUSTER_NAME",
    "SEAGULL_PROD_ES_EXPECTED_STATUS",
    "SEAGULL_PROD_ES_HEAP",
    "SEAGULL_PROD_ES_ILM_MIGRATE_ENABLED",
    "SEAGULL_PROD_ES_ILM_WARM_SHRINK_SHARDS",
    "SEAGULL_PROD_ES_MEMORY_LOCK",
    "SEAGULL_PROD_ES_MEM_LIMIT",
    "SEAGULL_PROD_ES_NODE_ROLES",
    "SEAGULL_PROD_ES_NUMBER_OF_REPLICAS",
    "SEAGULL_PROD_ES_NUMBER_OF_SHARDS",
    "SEAGULL_PROD_ES_SECURITY_ENABLED",
    "SEAGULL_PROD_ES_TIER_PREFERENCE",
    "SEAGULL_PROD_ES_URL",
    "SEAGULL_PROD_ES_VERSION",
    "SEAGULL_PROD_PG_MAX_CONNECTIONS",
    "SEAGULL_PROD_PG_MAX_REPLICATION_SLOTS",
    "SEAGULL_PROD_PG_MAX_SLOT_WAL_KEEP_SIZE",
    "SEAGULL_PROD_PG_MAX_WAL_SENDERS",
    "SEAGULL_PROD_PG_PORT",
    "SEAGULL_PROD_PG_REPLICA1_PORT",
    "SEAGULL_PROD_PG_REPLICA2_PORT",
    "SEAGULL_PROD_PG_REPLICATION_SLOTS",
    "SEAGULL_PROD_PG_SYNCHRONOUS_COMMIT",
    "SEAGULL_PROD_REDPANDA1_ADMIN_PORT",
    "SEAGULL_PROD_REDPANDA1_PORT",
    "SEAGULL_PROD_REDPANDA2_ADMIN_PORT",
    "SEAGULL_PROD_REDPANDA2_PORT",
    "SEAGULL_PROD_REDPANDA3_ADMIN_PORT",
    "SEAGULL_PROD_REDPANDA3_PORT",
    "SEAGULL_PROD_REDPANDA_BROKERS",
    "SEAGULL_PROD_REDPANDA_MEMORY",
    "SEAGULL_PROD_REDPANDA_MEM_LIMIT",
    "SEAGULL_PROD_REDPANDA_SMP",
    "SEAGULL_PROD_REDPANDA_TOPIC_REPLICATION",
]

ENV_FILE_MODE = 0o600

DEFAULT_ENVIRONMENT = "dev"
PRODUCTION_ENVIRONMENTS = ("prod", "production")


def root() -> Path:
    return ROOT


def env_path(name: str = ".env") -> Path:
    return ROOT / name


def write_secure(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, ENV_FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    os.chmod(tmp, ENV_FILE_MODE)
    os.replace(tmp, path)


def enforce_secure_mode(path: Optional[Path] = None) -> None:
    p = path or env_path()
    if p.exists():
        os.chmod(p, ENV_FILE_MODE)


def read(key: str, default: str = "", path: Optional[Path] = None) -> str:
    p = path or env_path()
    if not p.exists():
        return default
    for line in p.read_text().splitlines():
        if line.startswith(f"{key}="):
            return line[len(key) + 1:].strip()
    return default


def environment(path: Optional[Path] = None) -> str:
    value = (os.environ.get("SEAGULL_ENV") or "").strip().lower()
    if value:
        return value
    value = (read("SEAGULL_ENV", "", path) or "").strip().lower()
    if value:
        return value
    value = (os.environ.get("SEAGULL_MODE") or "").strip().lower()
    if value:
        return value
    value = (read("SEAGULL_MODE", "", path) or "").strip().lower()
    if value:
        return value
    return DEFAULT_ENVIRONMENT


def is_production(path: Optional[Path] = None) -> bool:
    return environment(path) in PRODUCTION_ENVIRONMENTS


def upsert(key: str, value: str, path: Optional[Path] = None) -> None:
    p = path or env_path()
    lines = p.read_text().splitlines() if p.exists() else []
    out: list[str] = []
    found = False
    for line in lines:
        if line.startswith(f"{key}="):
            out.append(f"{key}={value}")
            found = True
        else:
            out.append(line)
    if not found:
        if out and out[-1].strip():
            out.append("")
        out.append(f"{key}={value}")
    write_secure(p, "\n".join(out) + "\n")


def bootstrap(env_file: Optional[Path] = None, template: Optional[Path] = None) -> None:
    path = env_file or env_path()
    tmpl = template or env_path(".env.example")

    if not tmpl.exists():
        raise FileNotFoundError(f"template not found: {tmpl}")

    if not path.exists():
        write_secure(path, tmpl.read_text())
        print(f"[bootstrap] created {path.name} from {tmpl.name}")
        return

    enforce_secure_mode(path)

    text = path.read_text()
    removed = 0
    for key in _DEPRECATED_KEYS:
        new_text = re.sub(
            rf"^\s*{re.escape(key)}=.*\n?", "", text, flags=re.MULTILINE
        )
        if new_text != text:
            text = new_text
            removed += 1

    existing: set[str] = set()
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        if m:
            existing.add(m.group(1))

    added: list[str] = []
    for line in tmpl.read_text().splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        if m and m.group(1) not in existing:
            added.append(line)
            existing.add(m.group(1))

    if added or removed:
        if not text.endswith("\n"):
            text += "\n"
        if added:
            header = f"\n# --- Auto-added from {tmpl.name} on {date.today().isoformat()} ---\n"
            text += header + "".join(f"{line}\n" for line in added)
        write_secure(path, text)

    if added:
        print(f"[bootstrap] synced {len(added)} missing vars from {tmpl.name} into {path.name}")
    else:
        print(f"[bootstrap] {path.name} already up-to-date")

    if removed:
        print(f"[bootstrap] removed {removed} deprecated var(s) from {path.name}")
