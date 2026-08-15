from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.config.env_secrets import env_value

DEFAULT_SIGNER_URL = "http://seagull-pki:8460"
DEFAULT_TIMEOUT_SECONDS = 10.0
CERTIFICATES_PATH = "/certificates"
_REQUIRED_FIELDS = (
    "certificate_pem",
    "ca_pem",
    "subject",
    "serial_hex",
    "fingerprint_sha256",
    "public_key_sha256",
)


class SignerUnavailable(Exception):
    pass


class SignerRejected(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class SignedCertificate:
    agent_id: str
    certificate_pem: str
    ca_pem: str
    subject: str
    serial_hex: str
    fingerprint_sha256: str
    public_key_sha256: str
    not_before: datetime
    not_after: datetime


def signer_url() -> str:
    return (env_value("SEAGULL_PKI_SIGNER_URL", DEFAULT_SIGNER_URL) or DEFAULT_SIGNER_URL).rstrip("/")


def _token() -> str:
    return (env_value("SEAGULL_PKI_SIGNER_TOKEN", "") or "").strip()


def _timeout() -> float:
    raw = env_value("SEAGULL_PKI_SIGNER_TIMEOUT_SECONDS", "")
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return value if value > 0 else DEFAULT_TIMEOUT_SECONDS


def _decoded(raw: bytes) -> dict:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignerUnavailable("certificate authority returned a malformed response") from exc
    if not isinstance(payload, dict):
        raise SignerUnavailable("certificate authority returned a malformed response")
    return payload


def _timestamp(payload: dict, field: str) -> datetime:
    try:
        return datetime.fromisoformat(str(payload[field]))
    except (KeyError, TypeError, ValueError) as exc:
        raise SignerUnavailable(f"certificate authority omitted {field}") from exc


def _text(payload: dict, field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SignerUnavailable(f"certificate authority omitted {field}")
    return value


def _rejected(status: int, raw: bytes) -> Exception:
    if status == 422:
        payload = _decoded(raw)
        reason = str(payload.get("reason") or "invalid_request")
        detail = str(payload.get("detail") or "certificate request rejected")
        return SignerRejected(reason, detail)
    return SignerUnavailable(f"certificate authority refused the request with status {status}")


def _post(payload: dict[str, Any]) -> bytes:
    token = _token()
    if not token:
        raise SignerUnavailable("certificate authority token is not configured")
    request = urllib.request.Request(
        f"{signer_url()}{CERTIFICATES_PATH}",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
    )
    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=_timeout()) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise _rejected(exc.code, exc.read()) from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SignerUnavailable(f"certificate authority unreachable: {exc}") from exc


def sign_agent_certificate(agent_id: str, csr_pem: str) -> SignedCertificate:
    payload = _decoded(_post({"agent_id": agent_id, "csr_pem": csr_pem}))
    return SignedCertificate(
        agent_id=agent_id,
        not_before=_timestamp(payload, "not_before"),
        not_after=_timestamp(payload, "not_after"),
        **{field: _text(payload, field) for field in _REQUIRED_FIELDS},
    )
