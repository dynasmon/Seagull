from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.core.pki import signer

TOKEN = "signer-client-token-0123456789abcdef"
ISSUED = {
    "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n",
    "subject": "CN=agent-core-1,O=Seagull Agents",
    "serial_hex": "2a",
    "fingerprint_sha256": "ab" * 32,
    "public_key_sha256": "cd" * 32,
    "not_before": "2026-08-15T12:00:00+00:00",
    "not_after": "2027-08-15T12:00:00+00:00",
}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        self.server.seen.append(
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "body": json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0")))),
            }
        )
        status, body = self.server.reply
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:
        return


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self) -> None:
        self.seen: list[dict] = []
        self.reply = (200, dict(ISSUED))
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


@contextmanager
def _serving():
    server = _Server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def authority(monkeypatch):
    with _serving() as server:
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_URL", server.url)
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TOKEN", TOKEN)
        monkeypatch.delenv("SEAGULL_PKI_SIGNER_TIMEOUT_SECONDS", raising=False)
        yield server


class TestRequest:
    def test_posts_the_request_to_the_certificates_endpoint(self, authority):
        signer.sign_agent_certificate("agent-core-1", "csr")
        assert authority.seen[0]["path"] == signer.CERTIFICATES_PATH
        assert authority.seen[0]["body"] == {"agent_id": "agent-core-1", "csr_pem": "csr"}

    def test_presents_the_configured_token(self, authority):
        signer.sign_agent_certificate("agent-core-1", "csr")
        assert authority.seen[0]["authorization"] == f"Bearer {TOKEN}"

    def test_refuses_to_call_without_a_token(self, authority, monkeypatch):
        monkeypatch.delenv("SEAGULL_PKI_SIGNER_TOKEN", raising=False)
        with pytest.raises(signer.SignerUnavailable):
            signer.sign_agent_certificate("agent-core-1", "csr")
        assert authority.seen == []


class TestResponse:
    def test_parses_the_issued_certificate(self, authority):
        signed = signer.sign_agent_certificate("agent-core-1", "csr")
        assert signed.agent_id == "agent-core-1"
        assert signed.certificate_pem == ISSUED["certificate_pem"]
        assert signed.subject == ISSUED["subject"]
        assert signed.serial_hex == "2a"
        assert signed.not_before.isoformat() == ISSUED["not_before"]
        assert signed.not_after.isoformat() == ISSUED["not_after"]

    def test_rejects_a_policy_failure_with_its_reason(self, authority):
        authority.reply = (422, {"reason": "weak_key", "detail": "RSA key must be >= 2048 bits"})
        with pytest.raises(signer.SignerRejected) as exc:
            signer.sign_agent_certificate("agent-core-1", "csr")
        assert exc.value.reason == "weak_key"
        assert "2048" in exc.value.detail

    def test_an_unauthorized_signer_is_unavailable_not_a_bad_request(self, authority):
        authority.reply = (401, {"reason": "unauthorized", "detail": "invalid signing token"})
        with pytest.raises(signer.SignerUnavailable):
            signer.sign_agent_certificate("agent-core-1", "csr")

    def test_a_failing_signer_is_unavailable(self, authority):
        authority.reply = (503, {"reason": "ca_unavailable", "detail": "material unavailable"})
        with pytest.raises(signer.SignerUnavailable):
            signer.sign_agent_certificate("agent-core-1", "csr")

    def test_a_malformed_body_is_unavailable(self, authority):
        authority.reply = (200, b"not json")
        with pytest.raises(signer.SignerUnavailable):
            signer.sign_agent_certificate("agent-core-1", "csr")

    def test_a_missing_field_is_unavailable(self, authority):
        incomplete = dict(ISSUED)
        incomplete.pop("serial_hex")
        authority.reply = (200, incomplete)
        with pytest.raises(signer.SignerUnavailable):
            signer.sign_agent_certificate("agent-core-1", "csr")

    def test_an_unparseable_timestamp_is_unavailable(self, authority):
        broken = dict(ISSUED)
        broken["not_after"] = "whenever"
        authority.reply = (200, broken)
        with pytest.raises(signer.SignerUnavailable):
            signer.sign_agent_certificate("agent-core-1", "csr")

    def test_an_unreachable_signer_is_unavailable(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_URL", "http://127.0.0.1:1")
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TOKEN", TOKEN)
        with pytest.raises(signer.SignerUnavailable):
            signer.sign_agent_certificate("agent-core-1", "csr")


class TestConfiguration:
    def test_url_defaults_to_the_isolated_service(self, monkeypatch):
        monkeypatch.delenv("SEAGULL_PKI_SIGNER_URL", raising=False)
        assert signer.signer_url() == signer.DEFAULT_SIGNER_URL

    def test_url_drops_a_trailing_slash(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_URL", "http://seagull-pki:8460/")
        assert signer.signer_url() == "http://seagull-pki:8460"

    def test_timeout_falls_back_on_a_bad_value(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TIMEOUT_SECONDS", "soon")
        assert signer._timeout() == signer.DEFAULT_TIMEOUT_SECONDS

    def test_timeout_rejects_a_non_positive_value(self, monkeypatch):
        monkeypatch.setenv("SEAGULL_PKI_SIGNER_TIMEOUT_SECONDS", "0")
        assert signer._timeout() == signer.DEFAULT_TIMEOUT_SECONDS
