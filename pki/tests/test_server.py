from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest
from conftest import make_csr
from cryptography import x509

from signer.config import Config
from signer.server import SigningServer

TOKEN = "s" * 48


def _config(authority_dir, **overrides) -> Config:
    settings = {
        "host": "127.0.0.1",
        "port": 0,
        "ca_cert_file": authority_dir / "agent-ca.crt",
        "ca_key_file": authority_dir / "agent-ca.key",
        "validity_days": 365,
        "max_body_bytes": 65536,
        "token": TOKEN,
    }
    settings.update(overrides)
    return Config(**settings)


@pytest.fixture
def signer(authority_dir):
    server = SigningServer(_config(authority_dir))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.bound_port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _post(base: str, payload, token: str = TOKEN, path: str = "/certificates", headers=None):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    request = urllib.request.Request(f"{base}{path}", data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _get(base: str, path: str):
    try:
        with urllib.request.urlopen(f"{base}{path}", timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class TestSigningEndpoint:
    def test_signs_a_valid_request(self, signer):
        csr_pem, _ = make_csr("agent-core-1")
        status, body = _post(signer, {"agent_id": "agent-core-1", "csr_pem": csr_pem})
        certificate = x509.load_pem_x509_certificate(body["certificate_pem"].encode())

        assert status == 200
        assert body["agent_id"] == "agent-core-1"
        assert body["serial_hex"] == format(certificate.serial_number, "x")
        assert body["not_after"] > body["not_before"]
        assert "BEGIN CERTIFICATE" in body["ca_pem"]

    def test_rejects_a_missing_token(self, signer):
        csr_pem, _ = make_csr("agent-core-1")
        status, body = _post(signer, {"agent_id": "agent-core-1", "csr_pem": csr_pem}, token=None)
        assert status == 401
        assert body["reason"] == "unauthorized"

    def test_rejects_a_wrong_token(self, signer):
        csr_pem, _ = make_csr("agent-core-1")
        status, body = _post(signer, {"agent_id": "agent-core-1", "csr_pem": csr_pem}, token="x" * 48)
        assert status == 401
        assert body["reason"] == "unauthorized"

    def test_reports_the_policy_reason(self, signer):
        csr_pem, _ = make_csr("agent-evil")
        status, body = _post(signer, {"agent_id": "agent-core-1", "csr_pem": csr_pem})
        assert status == 422
        assert body["reason"] == "subject_mismatch"

    def test_refuses_a_body_over_the_ceiling(self, authority_dir):
        server = SigningServer(_config(authority_dir, max_body_bytes=256))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            csr_pem, _ = make_csr("agent-core-1")
            status, body = _post(
                f"http://127.0.0.1:{server.bound_port}",
                {"agent_id": "agent-core-1", "csr_pem": csr_pem},
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        assert status == 413
        assert body["reason"] == "body_too_large"

    def test_refuses_a_non_json_body(self, signer):
        status, body = _post(signer, b"not json")
        assert status == 400
        assert body["reason"] == "invalid_json"

    def test_refuses_an_unknown_path(self, signer):
        status, body = _post(signer, {}, path="/sign")
        assert status == 404
        assert body["reason"] == "not_found"


class TestHealthEndpoint:
    def test_reports_ready_while_the_material_loads(self, signer):
        status, body = _get(signer, "/health")
        assert status == 200
        assert body["status"] == "ok"

    def test_reports_unavailable_without_material(self, authority_dir):
        (authority_dir / "agent-ca.key").unlink()
        server = SigningServer(_config(authority_dir))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, body = _get(f"http://127.0.0.1:{server.bound_port}", "/health")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        assert status == 503
        assert body["reason"] == "ca_unavailable"

    def test_health_needs_no_token(self, signer):
        status, _ = _get(signer, "/health")
        assert status == 200
