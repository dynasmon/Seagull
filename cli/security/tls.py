from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID


def _is_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def cert_has_san(cert_path: Path, server_name: str) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (FileNotFoundError, ValueError):
        return False
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return False
    if _is_ipv4(server_name):
        return ipaddress.ip_address(server_name) in san.value.get_values_for_type(x509.IPAddress)
    return server_name in san.value.get_values_for_type(x509.DNSName)


def generate_dev_cert(cert_path: Path, key_path: Path, server_name: str) -> None:
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    loopback = ipaddress.ip_address("127.0.0.1")
    san_entries: list[x509.GeneralName] = [x509.DNSName("localhost"), x509.IPAddress(loopback)]
    if _is_ipv4(server_name):
        addr = ipaddress.ip_address(server_name)
        if addr != loopback:
            san_entries.append(x509.IPAddress(addr))
    elif server_name and server_name != "localhost":
        san_entries.append(x509.DNSName(server_name))

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    cert_path.chmod(0o644)
    key_path.chmod(0o640)
    print("[preflight] regenerated dev TLS cert/key with SAN entries")


def ensure_readable(path: Path) -> None:
    mode = path.stat().st_mode & 0o777
    group_read = (mode >> 3) & 4
    other_read = mode & 4
    if not group_read and not other_read:
        path.chmod(0o644)


def harden_key_perms(path: Path) -> None:
    mode = path.stat().st_mode & 0o777
    new_mode = (mode | 0o040) & ~0o007
    if new_mode != mode:
        path.chmod(new_mode)


def is_group_or_world_readable(path: Path) -> bool:
    mode = path.stat().st_mode & 0o777
    group_read = (mode >> 3) & 4
    other_read = mode & 4
    return bool(group_read or other_read)
