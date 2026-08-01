from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from app.core.config import settings
from app.core.observability import incr_counter

_BUNDLED_MANIFEST = Path(__file__).with_name("releases.json")
_CHUNK_BYTES = 262144
_SHA256_LENGTH = 64


class PackageError(RuntimeError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class PackageNotPinned(PackageError):
    pass


class PackageUnavailable(PackageError):
    pass


@dataclass(frozen=True)
class PackageRef:
    version: str
    os: str
    architecture: str
    filename: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class PackageState:
    architecture: str
    filename: str
    sha256: str
    size_bytes: int
    cached: bool


def manifest_path() -> Path:
    configured = (settings.SEAGULL_AGENT_RELEASE_MANIFEST_FILE or "").strip()
    return Path(configured) if configured else _BUNDLED_MANIFEST


def _read_manifest() -> dict:
    path = manifest_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PackageNotPinned("manifest_unreadable", f"agent release manifest is unreadable: {path}") from exc
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PackageNotPinned("manifest_invalid", f"agent release manifest is not valid JSON: {path}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("releases"), list):
        raise PackageNotPinned("manifest_invalid", f"agent release manifest has no releases: {path}")
    return document


def _entry(document: dict, version: str, architecture: str) -> dict:
    for release in document["releases"]:
        if not isinstance(release, dict) or str(release.get("version") or "") != version:
            continue
        for artifact in release.get("artifacts") or ():
            if isinstance(artifact, dict) and str(artifact.get("architecture") or "") == architecture:
                return artifact
    raise PackageNotPinned(
        "not_pinned",
        f"agent release {version} linux/{architecture} is not pinned in {manifest_path()}",
    )


def reference(version: Optional[str] = None, architecture: str = "amd64") -> PackageRef:
    resolved_version = (version or settings.SEAGULL_AGENT_RELEASE_VERSION).strip()
    entry = _entry(_read_manifest(), resolved_version, architecture)
    digest = str(entry.get("sha256") or "").strip().lower()
    filename = str(entry.get("filename") or "").strip()
    size = int(entry.get("size_bytes") or 0)
    if len(digest) != _SHA256_LENGTH or any(char not in "0123456789abcdef" for char in digest):
        raise PackageNotPinned("digest_invalid", f"agent release {resolved_version} has an invalid pinned digest")
    if not filename.endswith(".tar.gz") or "/" in filename or filename.startswith("."):
        raise PackageNotPinned("filename_invalid", f"agent release {resolved_version} has an invalid pinned filename")
    if size <= 0:
        raise PackageNotPinned("size_invalid", f"agent release {resolved_version} has an invalid pinned size")
    return PackageRef(
        version=resolved_version,
        os=str(entry.get("os") or "linux"),
        architecture=architecture,
        filename=filename,
        sha256=digest,
        size_bytes=size,
    )


def store_dir() -> Path:
    return Path(settings.SEAGULL_AGENT_PACKAGE_DIR)


def _package_path(ref: PackageRef) -> Path:
    return store_dir() / ref.version / ref.filename


def _digest_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _present(ref: PackageRef) -> bool:
    try:
        return _package_path(ref).stat().st_size == ref.size_bytes
    except OSError:
        return False


def _cached(ref: PackageRef) -> Optional[Path]:
    if not _present(ref):
        return None
    path = _package_path(ref)
    if _digest_of(path) != ref.sha256:
        return None
    return path


def _download_url(ref: PackageRef) -> str:
    base = settings.SEAGULL_AGENT_RELEASE_BASE_URL.rstrip("/")
    return f"{base}/v{ref.version}/{ref.filename}"


class _HttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError("agent release redirect left https")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _prepare_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PackageUnavailable("store_unwritable", f"the agent package directory is unusable: {exc}") from exc


def _fetch(ref: PackageRef, destination: Path) -> None:
    url = _download_url(ref)
    if urlsplit(url).scheme != "https":
        raise PackageUnavailable("insecure_source", "the agent release source must use https")
    opener = urllib.request.build_opener(_HttpsRedirectHandler())
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    timeout = max(5, int(settings.SEAGULL_AGENT_PACKAGE_FETCH_TIMEOUT_SECONDS))
    handle = tempfile.NamedTemporaryFile(dir=destination.parent, delete=False)
    temporary = Path(handle.name)
    written = 0
    try:
        with opener.open(request, timeout=timeout) as response:
            while True:
                chunk = response.read(_CHUNK_BYTES)
                if not chunk:
                    break
                written += len(chunk)
                if written > ref.size_bytes:
                    raise PackageUnavailable("size_mismatch", f"{ref.filename} is larger than its pinned size")
                handle.write(chunk)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        if written != ref.size_bytes:
            raise PackageUnavailable("size_mismatch", f"{ref.filename} does not match its pinned size")
        if _digest_of(temporary) != ref.sha256:
            raise PackageUnavailable("digest_mismatch", f"{ref.filename} does not match its pinned sha256")
        temporary.chmod(0o644)
        os.replace(temporary, destination)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PackageUnavailable("fetch_failed", f"unable to download {ref.filename}: {exc}") from exc
    finally:
        if not handle.closed:
            handle.close()
        temporary.unlink(missing_ok=True)


def state(ref: PackageRef) -> PackageState:
    return PackageState(
        architecture=ref.architecture,
        filename=ref.filename,
        sha256=ref.sha256,
        size_bytes=ref.size_bytes,
        cached=_present(ref),
    )


def ensure(ref: PackageRef) -> Path:
    path = _cached(ref)
    if path is not None:
        return path
    if not settings.SEAGULL_AGENT_PACKAGE_FETCH_ENABLED:
        raise PackageUnavailable(
            "fetch_disabled",
            f"{ref.filename} is not in {store_dir()} and upstream download is disabled",
        )
    destination = _package_path(ref)
    _prepare_directory(destination.parent)
    lock_path = destination.parent / f".{ref.filename}.lock"
    with lock_path.open("w") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        path = _cached(ref)
        if path is not None:
            return path
        try:
            _fetch(ref, destination)
        except PackageError as exc:
            incr_counter(
                "agent_package_fetch_total",
                outcome="failure",
                architecture=ref.architecture,
                reason=exc.reason,
            )
            raise
        incr_counter("agent_package_fetch_total", outcome="success", architecture=ref.architecture, reason="")
    return destination


def read(ref: PackageRef) -> bytes:
    return ensure(ref).read_bytes()
