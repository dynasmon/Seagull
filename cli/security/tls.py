from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


def _is_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def cert_has_san(cert_path: Path, server_name: str) -> bool:
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-ext", "subjectAltName"],
            capture_output=True, text=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    text = result.stdout
    if _is_ipv4(server_name):
        return f"IP Address:{server_name}" in text
    return f"DNS:{server_name}" in text


def generate_dev_cert(cert_path: Path, key_path: Path, server_name: str) -> None:
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    san_line = f"IP.2 = {server_name}" if _is_ipv4(server_name) else f"DNS.2 = {server_name}"
    cfg_content = f"""[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
x509_extensions    = v3_req
prompt             = no

[ req_distinguished_name ]
CN = localhost

[ v3_req ]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
{san_line}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cnf", delete=False) as f:
        f.write(cfg_content)
        cfg_path = f.name

    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:4096",
                "-days", "365",
                "-keyout", str(key_path),
                "-out", str(cert_path),
                "-config", cfg_path,
            ],
            capture_output=True, check=True,
        )
    finally:
        os.unlink(cfg_path)

    cert_path.chmod(0o644)
    key_path.chmod(0o644)
    print("[preflight] regenerated dev TLS cert/key with SAN entries")


def ensure_readable(path: Path) -> None:
    mode = path.stat().st_mode & 0o777
    group_read = (mode >> 3) & 4
    other_read = mode & 4
    if not group_read and not other_read:
        path.chmod(0o644)


def is_group_or_world_readable(path: Path) -> bool:
    mode = path.stat().st_mode & 0o777
    group_read = (mode >> 3) & 4
    other_read = mode & 4
    return bool(group_read or other_read)
