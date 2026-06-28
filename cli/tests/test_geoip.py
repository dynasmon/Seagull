from __future__ import annotations

import io
import tarfile
import urllib.error
import urllib.parse
from pathlib import Path

import pytest

from cli.stack import geoip


def _mmdb_payload() -> bytes:
    return b"\0" * 2048 + geoip.METADATA_MARKER + b"\0" * 32


def _archive(edition: str, filename: str) -> bytes:
    output = io.BytesIO()
    payload = _mmdb_payload()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"{edition}_20260628/{filename}")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def _write_env(root: Path, text: str) -> None:
    (root / ".env").write_text(text)


def _write_databases(root: Path) -> None:
    output_dir = root / "backend" / "data" / "geoip"
    output_dir.mkdir(parents=True)
    for filename in geoip.DATABASES.values():
        (output_dir / filename).write_bytes(_mmdb_payload())


def test_database_validation_requires_mmdb_metadata_marker(tmp_path: Path) -> None:
    database = tmp_path / "database.mmdb"
    database.write_bytes(b"x" * 4096)
    assert geoip._database_valid(database) is False

    database.write_bytes(_mmdb_payload())
    assert geoip._database_valid(database) is True


def test_ensure_is_idempotent_when_both_databases_are_valid(tmp_path: Path, monkeypatch) -> None:
    _write_env(tmp_path, "SEAGULL_IP_INTEL_PROVIDER=auto\n")
    _write_databases(tmp_path)
    monkeypatch.setattr(
        geoip,
        "_open_url",
        lambda request: (_ for _ in ()).throw(AssertionError("download must not run")),
    )

    assert geoip.ensure(root=tmp_path) is False


def test_ensure_requires_license_key_when_local_provider_needs_databases(tmp_path: Path) -> None:
    _write_env(tmp_path, "SEAGULL_IP_INTEL_PROVIDER=auto\nMAXMIND_LICENSE_KEY=\n")

    with pytest.raises(RuntimeError, match="MAXMIND_LICENSE_KEY is required"):
        geoip.ensure(root=tmp_path)


def test_ensure_skips_download_for_explicit_ipinfo_provider(tmp_path: Path, monkeypatch) -> None:
    _write_env(tmp_path, "SEAGULL_IP_INTEL_PROVIDER=ipinfo\n")
    monkeypatch.setattr(
        geoip,
        "_open_url",
        lambda request: (_ for _ in ()).throw(AssertionError("download must not run")),
    )

    assert geoip.ensure(root=tmp_path) is False


def test_ensure_downloads_and_installs_both_databases(tmp_path: Path, monkeypatch) -> None:
    _write_env(tmp_path, "SEAGULL_IP_INTEL_PROVIDER=auto\nMAXMIND_LICENSE_KEY=test-license\n")
    requested = []

    def open_url(request):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)
        edition = query["edition_id"][0]
        requested.append(edition)
        return io.BytesIO(_archive(edition, geoip.DATABASES[edition]))

    monkeypatch.setattr(geoip, "_open_url", open_url)

    assert geoip.ensure(root=tmp_path) is True
    assert requested == list(geoip.DATABASES)
    for filename in geoip.DATABASES.values():
        database = tmp_path / "backend" / "data" / "geoip" / filename
        assert geoip._database_valid(database) is True
        assert database.stat().st_mode & 0o777 == 0o644


def test_download_error_does_not_expose_license_key(tmp_path: Path, monkeypatch) -> None:
    license_key = "never-print-this-license"
    _write_env(tmp_path, f"SEAGULL_IP_INTEL_PROVIDER=auto\nMAXMIND_LICENSE_KEY={license_key}\n")

    def reject(request):
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(geoip, "_open_url", reject)

    with pytest.raises(RuntimeError) as error:
        geoip.ensure(root=tmp_path)
    assert "HTTP 401" in str(error.value)
    assert license_key not in str(error.value)
