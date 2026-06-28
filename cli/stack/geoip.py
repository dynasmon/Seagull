from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import BinaryIO

from ..config import env as _env


DATABASES = {
    "GeoLite2-City": "GeoLite2-City.mmdb",
    "GeoLite2-ASN": "GeoLite2-ASN.mmdb",
}
DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"
METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
MIN_DATABASE_BYTES = 1024
VALIDATION_TAIL_BYTES = 131072
DOWNLOAD_TIMEOUT_SECONDS = 60


def _setting(key: str, default: str, root: Path) -> str:
    value = os.environ.get(key)
    if value is None:
        value = _env.read(key, default, path=root / ".env")
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value


def _database_valid(path: Path) -> bool:
    try:
        size = path.stat().st_size
        if size < MIN_DATABASE_BYTES:
            return False
        with path.open("rb") as database:
            database.seek(max(0, size - VALIDATION_TAIL_BYTES))
            return METADATA_MARKER in database.read()
    except OSError:
        return False


def _open_url(request: urllib.request.Request):
    return urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS)


def _download_archive(edition: str, license_key: str, destination: Path) -> None:
    query = urllib.parse.urlencode(
        {
            "edition_id": edition,
            "license_key": license_key,
            "suffix": "tar.gz",
        }
    )
    request = urllib.request.Request(
        f"{DOWNLOAD_URL}?{query}",
        headers={"Accept": "application/gzip", "User-Agent": "seagull-installer"},
    )
    try:
        with _open_url(request) as response, destination.open("wb") as archive:
            shutil.copyfileobj(response, archive)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"[geoip] MaxMind rejected the {edition} download with HTTP {exc.code}; "
            "verify MAXMIND_LICENSE_KEY"
        ) from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"[geoip] unable to download {edition}: network error") from exc
    except OSError as exc:
        raise RuntimeError(f"[geoip] unable to store the {edition} download") from exc


def _extract_database(archive_path: Path, filename: str, destination: Path) -> None:
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            matches = [
                member
                for member in archive.getmembers()
                if member.isfile() and Path(member.name).name == filename
            ]
            if len(matches) != 1:
                raise RuntimeError(f"[geoip] {filename} not found in MaxMind archive")
            source: BinaryIO | None = archive.extractfile(matches[0])
            if source is None:
                raise RuntimeError(f"[geoip] unable to read {filename} from MaxMind archive")
            with source, destination.open("wb") as database:
                shutil.copyfileobj(source, database)
    except tarfile.TarError as exc:
        raise RuntimeError(f"[geoip] invalid MaxMind archive for {filename}") from exc

    if not _database_valid(destination):
        raise RuntimeError(f"[geoip] downloaded {filename} is not a valid MMDB database")


def status(*, root: Path | None = None) -> bool:
    project_root = root or _env.root()
    output_dir = project_root / "backend" / "data" / "geoip"
    ready = True
    for filename in DATABASES.values():
        path = output_dir / filename
        valid = _database_valid(path)
        state = "ready" if valid else "missing or invalid"
        print(f"[geoip] {filename}: {state}")
        ready = ready and valid
    return ready


def ensure(*, force: bool = False, root: Path | None = None) -> bool:
    project_root = root or _env.root()
    output_dir = project_root / "backend" / "data" / "geoip"
    output_dir.mkdir(parents=True, exist_ok=True)

    targets = {edition: output_dir / filename for edition, filename in DATABASES.items()}
    if not force and all(_database_valid(path) for path in targets.values()):
        print("[geoip] MaxMind GeoLite2 databases ready")
        return False

    provider = _setting("SEAGULL_IP_INTEL_PROVIDER", "auto", project_root).lower()
    if provider in {"ipinfo", "none", "off", "disabled"}:
        print(f"[geoip] provider={provider}; local MaxMind download skipped")
        return False

    license_key = _setting("MAXMIND_LICENSE_KEY", "", project_root)
    if not license_key:
        raise RuntimeError(
            "[geoip] MAXMIND_LICENSE_KEY is required before the first ./seagull up; "
            "create a free MaxMind account and add the license key to .env"
        )

    print("[geoip] downloading MaxMind GeoLite2 City and ASN databases")
    with tempfile.TemporaryDirectory(prefix=".geoip-", dir=output_dir) as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        staged: dict[Path, Path] = {}
        for edition, target in targets.items():
            archive_path = temp_dir / f"{edition}.tar.gz"
            staged_path = temp_dir / target.name
            _download_archive(edition, license_key, archive_path)
            _extract_database(archive_path, target.name, staged_path)
            staged[target] = staged_path

        for target, staged_path in staged.items():
            os.replace(staged_path, target)
            target.chmod(0o644)

    print(f"[geoip] MaxMind GeoLite2 installed in {output_dir.relative_to(project_root)}/")
    return True
