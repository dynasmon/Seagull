from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID


def write_authority(directory: Path, is_ca: bool = True) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Seagull Agent CA")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    (directory / "agent-ca.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (directory / "agent-ca.key").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return certificate


def make_csr(agent_id: str, key=None) -> tuple[str, object]:
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Seagull Agents"),
                    x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                ]
            )
        )
        .sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"), key


@pytest.fixture
def authority_dir(tmp_path):
    write_authority(tmp_path)
    return tmp_path
