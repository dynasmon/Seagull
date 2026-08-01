from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_PASSWORD", "test-password")

from app.core.config import settings
from app.features.agents import packages

PLATFORM_MANIFEST = Path(__file__).resolve().parents[1] / "app/features/agents/releases.json"


def build_package(name: str = "seagull-agent_9.9.9_linux_amd64") -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        payload = b"#!/usr/bin/env bash\nexit 0\n"
        info = tarfile.TarInfo(f"{name}/install.sh")
        info.size = len(payload)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(payload))
    return gzip.compress(raw.getvalue(), mtime=0)


@pytest.fixture
def store(tmp_path, monkeypatch):
    package = build_package()
    digest = hashlib.sha256(package).hexdigest()
    manifest = tmp_path / "releases.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "releases": [
                    {
                        "version": "9.9.9",
                        "channel": "stable",
                        "artifacts": [
                            {
                                "os": "linux",
                                "architecture": "amd64",
                                "filename": "seagull-agent_9.9.9_linux_amd64.tar.gz",
                                "sha256": digest,
                                "size_bytes": len(package),
                            }
                        ],
                    }
                ],
            }
        )
    )
    monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_MANIFEST_FILE", str(manifest))
    monkeypatch.setattr(settings, "SEAGULL_AGENT_PACKAGE_DIR", str(tmp_path / "packages"))
    monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_VERSION", "9.9.9")
    monkeypatch.setattr(settings, "SEAGULL_AGENT_PACKAGE_FETCH_ENABLED", False)
    return package, digest, manifest


def place(ref: packages.PackageRef, content: bytes) -> Path:
    path = packages.store_dir() / ref.version / ref.filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


class TestPinnedManifest:
    def test_reference_reads_the_pinned_artifact(self, store):
        package, digest, _ = store
        ref = packages.reference(architecture="amd64")
        assert ref.version == "9.9.9"
        assert ref.sha256 == digest
        assert ref.size_bytes == len(package)
        assert ref.filename.endswith(".tar.gz")

    def test_unpinned_architecture_is_refused(self, store):
        with pytest.raises(packages.PackageNotPinned):
            packages.reference(architecture="arm64")

    def test_unpinned_version_is_refused(self, store):
        with pytest.raises(packages.PackageNotPinned):
            packages.reference("1.2.3", "amd64")

    def test_missing_manifest_is_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_MANIFEST_FILE", str(tmp_path / "absent.json"))
        with pytest.raises(packages.PackageNotPinned):
            packages.reference(architecture="amd64")

    @pytest.mark.parametrize(
        "artifact",
        [
            {"architecture": "amd64", "filename": "a.tar.gz", "sha256": "short", "size_bytes": 10},
            {"architecture": "amd64", "filename": "../escape.tar.gz", "sha256": "a" * 64, "size_bytes": 10},
            {"architecture": "amd64", "filename": "a.zip", "sha256": "a" * 64, "size_bytes": 10},
            {"architecture": "amd64", "filename": "a.tar.gz", "sha256": "a" * 64, "size_bytes": 0},
        ],
    )
    def test_malformed_pins_are_refused(self, tmp_path, monkeypatch, artifact):
        manifest = tmp_path / "releases.json"
        manifest.write_text(json.dumps({"releases": [{"version": "9.9.9", "artifacts": [artifact]}]}))
        monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_MANIFEST_FILE", str(manifest))
        with pytest.raises(packages.PackageNotPinned):
            packages.reference("9.9.9", "amd64")

    def test_platform_manifest_matches_the_pinned_release_version(self):
        document = json.loads(PLATFORM_MANIFEST.read_text())
        versions = {entry["version"] for entry in document["releases"]}
        assert settings.SEAGULL_AGENT_RELEASE_VERSION in versions

    def test_platform_manifest_pins_every_supported_architecture(self, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_MANIFEST_FILE", "")
        for architecture in settings.SEAGULL_AGENT_SUPPORTED_ARCHITECTURES:
            ref = packages.reference(architecture=architecture)
            assert len(ref.sha256) == 64
            assert ref.filename == f"seagull-agent_{ref.version}_linux_{architecture}.tar.gz"


class TestLocalStore:
    def test_reads_a_package_placed_by_an_operator(self, store):
        package, _, _ = store
        ref = packages.reference(architecture="amd64")
        place(ref, package)
        assert packages.state(ref).cached is True
        assert packages.read(ref) == package

    def test_absent_package_without_fetching_is_reported(self, store):
        ref = packages.reference(architecture="amd64")
        assert packages.state(ref).cached is False
        with pytest.raises(packages.PackageUnavailable) as excinfo:
            packages.read(ref)
        assert excinfo.value.reason == "fetch_disabled"

    def test_tampered_package_is_never_served(self, store):
        package, _, _ = store
        ref = packages.reference(architecture="amd64")
        place(ref, bytes(len(package)))
        with pytest.raises(packages.PackageUnavailable):
            packages.read(ref)

    def test_truncated_package_is_never_served(self, store):
        package, _, _ = store
        ref = packages.reference(architecture="amd64")
        place(ref, package[:-1])
        assert packages.state(ref).cached is False
        with pytest.raises(packages.PackageUnavailable):
            packages.read(ref)


class TestUpstreamFetch:
    def _serve(self, monkeypatch, body: bytes):
        captured = {}

        class Response:
            def __init__(self) -> None:
                self._stream = io.BytesIO(body)

            def read(self, size):
                return self._stream.read(size)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class Opener:
            def open(self, request, timeout=None):
                captured["url"] = request.full_url
                captured["timeout"] = timeout
                return Response()

        monkeypatch.setattr(packages.urllib.request, "build_opener", lambda *args: Opener())
        return captured

    def test_downloads_and_caches_a_pinned_package(self, store, monkeypatch):
        package, _, _ = store
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PACKAGE_FETCH_ENABLED", True)
        monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_BASE_URL", "https://releases.example.com/download")
        captured = self._serve(monkeypatch, package)

        ref = packages.reference(architecture="amd64")
        assert packages.read(ref) == package
        assert captured["url"] == (
            "https://releases.example.com/download/v9.9.9/seagull-agent_9.9.9_linux_amd64.tar.gz"
        )
        assert packages.state(ref).cached is True

    def test_rejects_a_body_that_does_not_match_the_pinned_digest(self, store, monkeypatch):
        package, _, _ = store
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PACKAGE_FETCH_ENABLED", True)
        self._serve(monkeypatch, bytes(len(package)))

        ref = packages.reference(architecture="amd64")
        with pytest.raises(packages.PackageUnavailable) as excinfo:
            packages.read(ref)
        assert excinfo.value.reason == "digest_mismatch"
        assert packages.state(ref).cached is False

    def test_rejects_a_body_larger_than_the_pinned_size(self, store, monkeypatch):
        package, _, _ = store
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PACKAGE_FETCH_ENABLED", True)
        self._serve(monkeypatch, package + b"tail")

        ref = packages.reference(architecture="amd64")
        with pytest.raises(packages.PackageUnavailable) as excinfo:
            packages.read(ref)
        assert excinfo.value.reason == "size_mismatch"

    def test_leaves_no_partial_file_behind(self, store, monkeypatch):
        package, _, _ = store
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PACKAGE_FETCH_ENABLED", True)
        self._serve(monkeypatch, package[:-2])

        ref = packages.reference(architecture="amd64")
        with pytest.raises(packages.PackageUnavailable):
            packages.read(ref)
        assert sorted(p.name for p in (packages.store_dir() / ref.version).glob("*.tar.gz")) == []

    def test_insecure_release_source_is_refused(self, store, monkeypatch):
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PACKAGE_FETCH_ENABLED", True)
        monkeypatch.setattr(settings, "SEAGULL_AGENT_RELEASE_BASE_URL", "http://releases.example.com")
        with pytest.raises(packages.PackageUnavailable) as excinfo:
            packages.read(packages.reference(architecture="amd64"))
        assert excinfo.value.reason == "insecure_source"

    def test_redirect_out_of_https_is_refused(self, store, monkeypatch):
        handler = packages._HttpsRedirectHandler()
        with pytest.raises(packages.urllib.error.URLError):
            handler.redirect_request(None, None, 302, "Found", {}, "http://releases.example.com/x.tar.gz")

    def test_unusable_package_directory_is_reported(self, store, monkeypatch, tmp_path):
        blocked = tmp_path / "blocked"
        blocked.write_text("not a directory")
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PACKAGE_FETCH_ENABLED", True)
        monkeypatch.setattr(settings, "SEAGULL_AGENT_PACKAGE_DIR", str(blocked))
        with pytest.raises(packages.PackageUnavailable) as excinfo:
            packages.read(packages.reference(architecture="amd64"))
        assert excinfo.value.reason == "store_unwritable"
