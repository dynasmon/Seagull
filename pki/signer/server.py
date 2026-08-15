from __future__ import annotations

import hmac
import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

from signer import issuer
from signer.config import Config

CERTIFICATES_PATH = "/certificates"
HEALTH_PATH = "/health"
CONNECTION_TIMEOUT_SECONDS = 15

logger = logging.getLogger("seagull.pki")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "seagull-pki"
    sys_version = ""
    timeout = CONNECTION_TIMEOUT_SECONDS

    def do_GET(self) -> None:
        if self.path != HEALTH_PATH:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "unknown path")
            return
        try:
            issuer.Authority.load(self._config.ca_cert_file, self._config.ca_key_file)
        except issuer.AuthorityUnavailable as exc:
            self._error(HTTPStatus.SERVICE_UNAVAILABLE, "ca_unavailable", str(exc))
            return
        self._json(HTTPStatus.OK, {"status": "ok"})

    def do_POST(self) -> None:
        if self.path != CERTIFICATES_PATH:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "unknown path")
            return
        if not self._authorized():
            self._error(HTTPStatus.UNAUTHORIZED, "unauthorized", "invalid signing token")
            return
        payload = self._read_payload()
        if payload is None:
            return
        try:
            authority = issuer.Authority.load(self._config.ca_cert_file, self._config.ca_key_file)
            issued = authority.issue(
                str(payload.get("agent_id") or ""),
                str(payload.get("csr_pem") or ""),
                self._config.validity_days,
            )
        except issuer.AuthorityUnavailable as exc:
            logger.error("signing refused: %s", exc)
            self._error(HTTPStatus.SERVICE_UNAVAILABLE, "ca_unavailable", str(exc))
            return
        except issuer.CertificateRequestError as exc:
            self._error(HTTPStatus.UNPROCESSABLE_ENTITY, exc.reason, exc.detail)
            return
        logger.info("issued certificate for %s serial %s", issued.agent_id, issued.serial_hex)
        self._json(
            HTTPStatus.OK,
            {
                "agent_id": issued.agent_id,
                "certificate_pem": issued.certificate_pem,
                "ca_pem": issued.ca_pem,
                "subject": issued.subject,
                "serial_hex": issued.serial_hex,
                "fingerprint_sha256": issued.fingerprint_sha256,
                "public_key_sha256": issued.public_key_sha256,
                "not_before": issued.not_before.isoformat(),
                "not_after": issued.not_after.isoformat(),
            },
        )

    def log_message(self, format: str, *args: Any) -> None:
        logger.info("%s %s", self.address_string(), format % args)

    @property
    def _config(self) -> Config:
        return self.server.config

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer":
            return False
        return hmac.compare_digest(presented.strip(), self._config.token)

    def _read_payload(self) -> Optional[dict]:
        declared = self.headers.get("Content-Length")
        if declared is None:
            self._error(HTTPStatus.LENGTH_REQUIRED, "length_required", "Content-Length is required")
            return None
        try:
            length = int(declared)
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_length", "Content-Length is not an integer")
            return None
        if length < 0:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_length", "Content-Length is negative")
            return None
        if length > self._config.max_body_bytes:
            self._error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "body_too_large",
                f"body exceeds {self._config.max_body_bytes} bytes",
            )
            return None
        body = self.rfile.read(length)
        if len(body) != length:
            self._error(HTTPStatus.BAD_REQUEST, "truncated_body", "body is shorter than declared")
            return None
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json", "body is not valid JSON")
            return None
        if not isinstance(payload, dict):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json", "body must be a JSON object")
            return None
        return payload

    def _error(self, status: HTTPStatus, reason: str, detail: str) -> None:
        self._json(status, {"reason": reason, "detail": detail})

    def _json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class SigningServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, config: Config) -> None:
        self.config = config
        super().__init__((config.host, config.port), _Handler)

    @property
    def bound_port(self) -> int:
        return int(self.server_address[1])
