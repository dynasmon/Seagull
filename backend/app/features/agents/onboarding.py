from __future__ import annotations

from typing import Optional

from app.core.config import settings
from app.features.agents import certs, profiles, protocol
from app.features.agents.schemas import AgentOnboardingOut


def _public_host(request=None) -> str:
    configured = (settings.SEAGULL_AGENT_PUBLIC_HOST or "").strip()
    if configured:
        return configured
    if request is not None:
        host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
        if not host:
            host = str(getattr(request.url, "hostname", "") or "")
        host = host.split(":")[0].strip()
        if host:
            return host
    return "localhost"


def _base_url(host: str, port: int, path: str = "") -> str:
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"https://{host}:{int(port)}{path}"


def _ca_fingerprint() -> Optional[str]:
    bundle = certs.server_ca_bundle()
    if not bundle:
        return None
    return certs.certificate_fingerprint(bundle)


def describe(request=None) -> AgentOnboardingOut:
    host = _public_host(request)
    api_url = _base_url(host, settings.SEAGULL_AGENT_MTLS_PORT, "/agent")
    enroll_url = _base_url(host, settings.SEAGULL_AGENT_ENROLL_PORT)
    return AgentOnboardingOut(
        api_url=api_url,
        enroll_url=enroll_url,
        profiles=list(profiles.VALID_PROFILES),
        default_profile=profiles.SENSOR,
        token_ttl_seconds=int(settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_TTL_SECONDS),
        token_max_uses=int(settings.SEAGULL_AGENT_BOOTSTRAP_TOKEN_MAX_USES),
        protocol_version=protocol.PROTOCOL_VERSION,
        min_supported_protocol=protocol.MIN_SUPPORTED_PROTOCOL,
        max_supported_protocol=protocol.MAX_SUPPORTED_PROTOCOL,
        server_ca_required=certs.server_ca_bundle() is not None,
        server_ca_fingerprint_sha256=_ca_fingerprint(),
    )


def install_command(*, agent_id: str, profile: str, token: str, request=None) -> str:
    described = describe(request)
    normalized = profiles.normalize(profile) or profiles.SENSOR
    parts = [
        "sudo ./install.sh",
        f"--agent-id {agent_id}",
        f"--api-url {described.api_url}",
        f"--enroll-url {described.enroll_url}",
        f"--profile {normalized}",
        f"--enroll-token {token}",
    ]
    if described.server_ca_required:
        parts.append("--ca-file ./server-ca.crt")
    return " \\\n  ".join(parts)
