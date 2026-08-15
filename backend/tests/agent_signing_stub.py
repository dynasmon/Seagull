from __future__ import annotations

import hashlib
import json
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TOKEN = "agent-signing-stub-token-0123456789abcdef"

_CA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_CA_SUBJECT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Seagull Agent CA")])
_NOW = datetime.now(timezone.utc)
_CA_CERT = (
    x509.CertificateBuilder()
    .subject_name(_CA_SUBJECT)
    .issuer_name(_CA_SUBJECT)
    .public_key(_CA_KEY.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(_NOW - timedelta(minutes=1))
    .not_valid_after(_NOW + timedelta(days=30))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .sign(_CA_KEY, hashes.SHA256())
)
CA_PEM = _CA_CERT.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _sign(agent_id: str, csr: x509.CertificateSigningRequest) -> dict:
    public_key = csr.public_key()
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=1)
    not_after = now + timedelta(days=365)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Seagull Agents"),
                    x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                ]
            )
        )
        .issuer_name(_CA_SUBJECT)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(_CA_KEY, hashes.SHA256())
    )
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "agent_id": agent_id,
        "certificate_pem": certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "ca_pem": CA_PEM,
        "subject": certificate.subject.rfc4514_string(),
        "serial_hex": format(certificate.serial_number, "x"),
        "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "public_key_sha256": hashlib.sha256(der).hexdigest(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
    }


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        if self.server.unavailable:
            self._json(503, {"reason": "ca_unavailable", "detail": "agent CA material unavailable"})
            return
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._json(401, {"reason": "unauthorized", "detail": "invalid signing token"})
            return
        payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        agent_id = str(payload.get("agent_id") or "")
        self.server.requests.append(agent_id)
        try:
            csr = x509.load_pem_x509_csr(str(payload.get("csr_pem") or "").encode("utf-8"))
        except ValueError:
            self._json(422, {"reason": "invalid_pem", "detail": "CSR is not valid PEM"})
            return
        common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not common_names or str(common_names[0].value) != agent_id:
            self._json(422, {"reason": "subject_mismatch", "detail": "CSR common name does not match"})
            return
        self._json(200, _sign(agent_id, csr))

    def log_message(self, format: str, *args) -> None:
        return

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self) -> None:
        self.unavailable = False
        self.requests: list[str] = []
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


@contextmanager
def serving():
    server = _Server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
