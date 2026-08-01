from __future__ import annotations

import shlex
from typing import Optional
from urllib.parse import urlsplit

from fastapi import HTTPException, status

from app.core.config import settings
from app.features.agents import certs, collectors, packages, profiles, protocol
from app.features.agents.schemas import (
    AgentOnboardingOut,
    AgentPackageStateOut,
    AgentReleaseArtifactOut,
    AgentReleaseOut,
)

INSTALLER_PATH = "/api/agents/installer"


def _forwarded_hostname(value: str) -> str:
    candidate = (value or "").split(",")[0].strip()
    if not candidate:
        return ""
    parsed = urlsplit(f"//{candidate}")
    if parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
        return ""
    try:
        _ = parsed.port
    except ValueError:
        return ""
    return str(parsed.hostname or "").strip()


def _public_host(request=None) -> str:
    configured = (settings.SEAGULL_AGENT_PUBLIC_HOST or "").strip()
    if configured:
        return configured
    if request is not None:
        host = ""
        if settings.SEAGULL_TRUST_PROXY_HEADERS:
            host = _forwarded_hostname(request.headers.get("x-forwarded-host") or "")
        if not host:
            host = str(getattr(request.url, "hostname", "") or "")
        host = host.strip()
        if host:
            return host
    return "localhost"


def _base_url(host: str, port: int, path: str = "") -> str:
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"https://{host}:{int(port)}{path}"


def portal_url(request=None, path: str = "") -> str:
    return _base_url(_public_host(request), settings.SEAGULL_EDGE_HTTPS_PORT, path)


def package_states() -> list[AgentPackageStateOut]:
    out: list[AgentPackageStateOut] = []
    for architecture in settings.SEAGULL_AGENT_SUPPORTED_ARCHITECTURES:
        try:
            current = packages.state(packages.reference(architecture=architecture))
        except packages.PackageError as exc:
            out.append(
                AgentPackageStateOut(
                    architecture=architecture,
                    filename="",
                    sha256="",
                    size_bytes=0,
                    cached=False,
                    error=exc.detail,
                )
            )
            continue
        out.append(
            AgentPackageStateOut(
                architecture=current.architecture,
                filename=current.filename,
                sha256=current.sha256,
                size_bytes=current.size_bytes,
                cached=current.cached,
            )
        )
    return out


def _ca_fingerprint(bundle: Optional[str]) -> Optional[str]:
    if not bundle:
        return None
    return certs.certificate_fingerprint(bundle)


def release() -> AgentReleaseOut:
    version = settings.SEAGULL_AGENT_RELEASE_VERSION.strip()
    tag = f"v{version}"
    base = f"{settings.SEAGULL_AGENT_RELEASE_BASE_URL.rstrip('/')}/{tag}"
    artifacts = []
    for architecture in settings.SEAGULL_AGENT_SUPPORTED_ARCHITECTURES:
        filename = f"seagull-agent_{version}_linux_{architecture}.tar.gz"
        artifacts.append(
            AgentReleaseArtifactOut(
                os="linux",
                architecture=architecture,
                filename=filename,
                download_url=f"{base}/{filename}",
                sbom_url=f"{base}/seagull-agent_{version}_linux_{architecture}.cdx.json",
            )
        )
    return AgentReleaseOut(
        version=version,
        tag=tag,
        channel="stable",
        artifacts=artifacts,
        checksums_url=f"{base}/SHA256SUMS",
        checksums_signature_url=f"{base}/SHA256SUMS.sig",
        checksums_certificate_url=f"{base}/SHA256SUMS.pem",
        protocol_contract_url=f"{base}/seagull-agent-protocol-v1.json",
        compatibility_contract_url=f"{base}/seagull-agent-compatibility.json",
    )


def artifact_for(value: AgentReleaseOut, architecture: str) -> AgentReleaseArtifactOut:
    for artifact in value.artifacts:
        if artifact.architecture == architecture:
            return artifact
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=f"unsupported agent architecture: {architecture}",
    )


def describe(request=None) -> AgentOnboardingOut:
    host = _public_host(request)
    api_url = _base_url(host, settings.SEAGULL_AGENT_MTLS_PORT, "/agent")
    enroll_url = _base_url(host, settings.SEAGULL_AGENT_ENROLL_PORT)
    ca_bundle = certs.server_ca_bundle()
    return AgentOnboardingOut(
        api_url=api_url,
        enroll_url=enroll_url,
        profiles=list(profiles.VALID_PROFILES),
        default_profile=profiles.SENSOR,
        collectors=list(collectors.CATALOG),
        default_collectors=collectors.resolve(None, default=settings.SEAGULL_AGENT_DEFAULT_SOURCES),
        token_ttl_seconds=int(settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS),
        token_max_uses=int(settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES),
        protocol_version=protocol.PROTOCOL_VERSION,
        min_supported_protocol=protocol.MIN_SUPPORTED_PROTOCOL,
        max_supported_protocol=protocol.MAX_SUPPORTED_PROTOCOL,
        server_ca_required=ca_bundle is not None,
        server_ca_fingerprint_sha256=_ca_fingerprint(ca_bundle),
        server_ca_pem=ca_bundle,
        release=release(),
        packages=package_states(),
    )


def install_command(*, agent_id: str, profile: str, sources: Optional[list[str]] = None, request=None) -> str:
    described = describe(request)
    normalized = profiles.normalize(profile) or profiles.SENSOR
    lines = [
        "sudo ./install.sh",
        f"--agent-id {shlex.quote(agent_id)}",
        f"--api-url {shlex.quote(described.api_url)}",
        f"--enroll-url {shlex.quote(described.enroll_url)}",
        f"--profile {shlex.quote(normalized)}",
    ]
    if sources:
        lines.append(f"--sources {shlex.quote(','.join(sources))}")
    lines.append("--prompt-enroll-token")
    if described.server_ca_required:
        lines.append("--ca-file ./server-ca.crt")
    return " \\\n  ".join(lines)


def installer_command(*, filename: str) -> str:
    return f"sudo bash {shlex.quote(filename)}"


def bootstrap_command(*, token: str, filename: str, request=None) -> str:
    url = portal_url(request, INSTALLER_PATH)
    return (
        f"curl --fail --silent --show-error --location "
        f"--header {shlex.quote(f'X-Agent-Bootstrap-Token: {token}')} "
        f"--output {shlex.quote(filename)} {shlex.quote(url)} && "
        f"{installer_command(filename=filename)}"
    )
