from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ..config import env as _env


DEFAULT_AGENT_IDS = (
    "agent-core-1,agent-sensor-1,agent-lateral-1,"
    "agent-proc-1,agent-scan-1,agent-ddos-1,agent-vuln-1"
)

CA_KEY_NAME = "agent-ca.key"
CA_CERT_NAME = "agent-ca.crt"
AGENTS_DIR_NAME = "agents"

SERVER_CA_KEY_NAME = "server-ca.key"
SERVER_CA_CERT_NAME = "server-ca.crt"
SERVER_DIR_NAME = "server"
SERVER_CERT_NAME = "mtls.crt"
SERVER_KEY_NAME = "mtls.key"
DEFAULT_SERVER_NAMES = "localhost,127.0.0.1"


def _cfg(key: str, default: str) -> str:
    value = os.environ.get(key)
    if value is not None and value.strip() != "":
        return value.strip()
    return _env.read(key, default)


def _cfg_int(key: str, default: int) -> int:
    try:
        return int(_cfg(key, str(default)))
    except (TypeError, ValueError):
        return default


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _not_valid_after_utc(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _resolve_pki_dir(pki_dir: Optional[Path]) -> Path:
    if pki_dir is not None:
        return Path(pki_dir)
    configured = Path(_cfg("SEAGULL_PKI_DIR", "./secrets/pki"))
    if configured.is_absolute():
        return configured
    return _env.root() / configured


def _chmod(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        pass


def _write_key(key: rsa.RSAPrivateKey, path: Path, mode: int = 0o600) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    _chmod(path, mode)


def _write_cert(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _chmod(path, 0o644)


def resolve_agent_ids() -> List[str]:
    raw = _cfg("SEAGULL_BOOTSTRAP_ROTATOR_AGENT_IDS", DEFAULT_AGENT_IDS)
    out: List[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        agent_id = item.strip()
        if not agent_id or agent_id in seen:
            continue
        seen.add(agent_id)
        out.append(agent_id)
    return out


def _build_ca(
    pki_dir: Path,
    common_name: str,
    key_name: str,
    cert_name: str,
    validity_days: int,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    pki_dir = Path(pki_dir)
    pki_dir.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = key.public_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Seagull"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .sign(key, hashes.SHA256())
    )

    _write_key(key, pki_dir / key_name)
    _write_cert(cert, pki_dir / cert_name)
    return key, cert


def generate_ca(pki_dir: Path) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    return _build_ca(
        pki_dir,
        "Seagull Agent CA",
        CA_KEY_NAME,
        CA_CERT_NAME,
        _cfg_int("SEAGULL_AGENT_CA_VALIDITY_DAYS", 3650),
    )


def generate_server_ca(pki_dir: Path) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    return _build_ca(
        pki_dir,
        "Seagull Server CA",
        SERVER_CA_KEY_NAME,
        SERVER_CA_CERT_NAME,
        _cfg_int("SEAGULL_SERVER_CA_VALIDITY_DAYS", 3650),
    )


def _load_ca(
    pki_dir: Path, key_name: str, cert_name: str
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    pki_dir = Path(pki_dir)
    key = serialization.load_pem_private_key(
        (pki_dir / key_name).read_bytes(), password=None
    )
    cert = x509.load_pem_x509_certificate((pki_dir / cert_name).read_bytes())
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        raise ValueError(f"{pki_dir / cert_name} is not a CA certificate")
    if not constraints.value.ca:
        raise ValueError(f"{pki_dir / cert_name} is not a CA certificate")
    return key, cert


def load_ca(pki_dir: Path) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    return _load_ca(pki_dir, CA_KEY_NAME, CA_CERT_NAME)


def load_server_ca(pki_dir: Path) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    return _load_ca(pki_dir, SERVER_CA_KEY_NAME, SERVER_CA_CERT_NAME)


def issue_agent_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    agent_id: str,
    pki_dir: Path,
) -> x509.Certificate:
    pki_dir = Path(pki_dir)
    agents_dir = pki_dir / AGENTS_DIR_NAME
    agents_dir.mkdir(parents=True, exist_ok=True)

    key_size = _cfg_int("SEAGULL_AGENT_CERT_KEY_SIZE", 2048)
    validity_days = _cfg_int("SEAGULL_AGENT_CERT_VALIDITY_DAYS", 365)

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = key.public_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Seagull Agents"),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        ]
    )
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    _write_key(key, agents_dir / f"{agent_id}.key")
    _write_cert(cert, agents_dir / f"{agent_id}.crt")
    return cert


def cert_needs_renewal(cert_path: Path, renew_before_days: int) -> bool:
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    threshold = _utcnow() + timedelta(days=renew_before_days)
    return _not_valid_after_utc(cert) <= threshold


def validate_cert_chain(cert_path: Path, ca_path: Path) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        ca_cert = x509.load_pem_x509_certificate(Path(ca_path).read_bytes())
    except (FileNotFoundError, ValueError):
        return False
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def resolve_server_names() -> List[str]:
    raw = _cfg("SEAGULL_AGENT_MTLS_SERVER_NAMES", DEFAULT_SERVER_NAMES)
    out: List[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        name = item.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _build_san(server_names: List[str]) -> x509.SubjectAlternativeName:
    entries: List[x509.GeneralName] = []
    for name in server_names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            entries.append(x509.DNSName(name))
    return x509.SubjectAlternativeName(entries)


def _cert_san_names(cert: x509.Certificate) -> set[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return set()
    names = set(ext.value.get_values_for_type(x509.DNSName))
    names |= {str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)}
    return names


def issue_server_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    server_names: List[str],
    pki_dir: Path,
) -> x509.Certificate:
    pki_dir = Path(pki_dir)
    server_dir = pki_dir / SERVER_DIR_NAME
    server_dir.mkdir(parents=True, exist_ok=True)
    _chmod(server_dir, 0o700)

    key_size = _cfg_int("SEAGULL_SERVER_CERT_KEY_SIZE", 2048)
    validity_days = _cfg_int("SEAGULL_SERVER_CERT_VALIDITY_DAYS", 365)
    common_name = server_names[0] if server_names else "localhost"

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = key.public_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Seagull"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
        .add_extension(_build_san(server_names), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    _write_key(key, server_dir / SERVER_KEY_NAME, 0o644)
    _write_cert(cert, server_dir / SERVER_CERT_NAME)
    return cert


def ensure_server_pki(pki_dir: Optional[Path] = None) -> bool:
    pki_dir = _resolve_pki_dir(pki_dir)
    pki_dir.mkdir(parents=True, exist_ok=True)
    _chmod(pki_dir, 0o700)

    server_ca_cert_path = pki_dir / SERVER_CA_CERT_NAME
    if server_ca_cert_path.exists():
        ca_key, ca_cert = load_server_ca(pki_dir)
    else:
        ca_key, ca_cert = generate_server_ca(pki_dir)

    server_names = resolve_server_names()
    server_dir = pki_dir / SERVER_DIR_NAME
    cert_path = server_dir / SERVER_CERT_NAME
    key_path = server_dir / SERVER_KEY_NAME
    renew_before_days = _cfg_int("SEAGULL_SERVER_CERT_RENEW_BEFORE_DAYS", 30)

    reissue = False
    if not cert_path.exists() or not key_path.exists():
        reissue = True
    elif cert_needs_renewal(cert_path, renew_before_days):
        reissue = True
    elif not validate_cert_chain(cert_path, server_ca_cert_path):
        reissue = True
    else:
        existing = x509.load_pem_x509_certificate(cert_path.read_bytes())
        if _cert_san_names(existing) != set(server_names):
            reissue = True

    if reissue:
        issue_server_cert(ca_key, ca_cert, server_names, pki_dir)
    return reissue


def ensure_agent_pki(pki_dir: Optional[Path] = None) -> List[str]:
    pki_dir = _resolve_pki_dir(pki_dir)
    agents_dir = pki_dir / AGENTS_DIR_NAME
    pki_dir.mkdir(parents=True, exist_ok=True)
    agents_dir.mkdir(parents=True, exist_ok=True)
    _chmod(pki_dir, 0o700)
    _chmod(agents_dir, 0o700)

    ca_cert_path = pki_dir / CA_CERT_NAME
    if ca_cert_path.exists():
        ca_key, ca_cert = load_ca(pki_dir)
    else:
        ca_key, ca_cert = generate_ca(pki_dir)

    renew_before_days = _cfg_int("SEAGULL_AGENT_CERT_RENEW_BEFORE_DAYS", 30)
    renewed: List[str] = []
    for agent_id in resolve_agent_ids():
        cert_path = agents_dir / f"{agent_id}.crt"
        key_path = agents_dir / f"{agent_id}.key"
        if not cert_path.exists() or not key_path.exists():
            issue_agent_cert(ca_key, ca_cert, agent_id, pki_dir)
            renewed.append(agent_id)
            continue
        if cert_needs_renewal(cert_path, renew_before_days):
            issue_agent_cert(ca_key, ca_cert, agent_id, pki_dir)
            renewed.append(agent_id)
            continue
        if not validate_cert_chain(cert_path, ca_cert_path):
            issue_agent_cert(ca_key, ca_cert, agent_id, pki_dir)
            renewed.append(agent_id)
    return renewed
