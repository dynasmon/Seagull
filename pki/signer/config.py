from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8460
DEFAULT_CA_CERT_FILE = "/etc/seagull/pki/agent-ca.crt"
DEFAULT_CA_KEY_FILE = "/etc/seagull/pki/agent-ca.key"
DEFAULT_VALIDITY_DAYS = 365
DEFAULT_MAX_BODY_BYTES = 65536
MIN_TOKEN_LENGTH = 32


class ConfigurationError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    ca_cert_file: Path
    ca_key_file: Path
    validity_days: int
    max_body_bytes: int
    token: str


def value(name: str, default: str = "") -> str:
    raw = os.getenv(name)
    if raw is not None and raw.strip():
        return raw.strip()
    location = os.getenv(f"{name}_FILE")
    if location is not None and location.strip():
        path = Path(location.strip())
        try:
            content = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigurationError(f"unable to read {name}_FILE at {path}: {exc}") from exc
        if content:
            return content
    return default


def _positive_int(name: str, default: int) -> int:
    raw = value(name)
    if not raw:
        return default
    try:
        parsed = int(raw, 10)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from exc
    if parsed <= 0:
        raise ConfigurationError(f"{name} must be greater than zero, got {parsed}")
    return parsed


def load() -> Config:
    token = value("SEAGULL_PKI_SIGNER_TOKEN")
    if len(token) < MIN_TOKEN_LENGTH:
        raise ConfigurationError(
            f"SEAGULL_PKI_SIGNER_TOKEN must be at least {MIN_TOKEN_LENGTH} characters"
        )
    return Config(
        host=value("SEAGULL_PKI_SIGNER_HOST", DEFAULT_HOST),
        port=_positive_int("SEAGULL_PKI_SIGNER_PORT", DEFAULT_PORT),
        ca_cert_file=Path(value("SEAGULL_AGENT_MTLS_CA_CERT_FILE", DEFAULT_CA_CERT_FILE)),
        ca_key_file=Path(value("SEAGULL_AGENT_MTLS_CA_KEY_FILE", DEFAULT_CA_KEY_FILE)),
        validity_days=_positive_int("SEAGULL_AGENT_CERT_VALIDITY_DAYS", DEFAULT_VALIDITY_DAYS),
        max_body_bytes=_positive_int("SEAGULL_PKI_SIGNER_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES),
        token=token,
    )
