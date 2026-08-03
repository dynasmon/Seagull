from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class AgentEnrollIn(BaseModel):
    enrollment_id: Optional[str] = Field(
        default=None,
        min_length=36,
        max_length=36,
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
    )
    agent_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    hostname: Optional[str] = Field(default=None, max_length=255)
    os: Optional[str] = Field(default=None, max_length=128)
    arch: Optional[str] = Field(default=None, max_length=32)
    version: Optional[str] = Field(default=None, max_length=64)
    protocol_version: Optional[int] = Field(default=None, ge=0, le=1000)
    profile: Optional[str] = Field(default=None, max_length=32)
    csr_pem: Optional[str] = Field(default=None, min_length=1, max_length=16384)


class AgentCredentialOut(BaseModel):
    credential: str
    expires_at: datetime
    max_uses: int
    used_uses: int = 0
    renewal_token: Optional[str] = None
    renewal_token_expires_at: Optional[datetime] = None


class AgentEnrollCertificateOut(BaseModel):
    certificate_pem: str
    ca_pem: str
    server_ca_pem: Optional[str] = None
    serial_hex: str
    not_before: datetime
    not_after: datetime


class AgentProtocolOut(BaseModel):
    protocol_version: int
    min_supported: int
    max_supported: int
    event_schema_version: int
    min_event_schema: int
    max_event_schema: int
    server_time: Optional[str] = None


class AgentEnrollOut(BaseModel):
    agent_id: str
    config: Dict[str, Any] = Field(default_factory=dict)
    credential: AgentCredentialOut
    certificate: Optional[AgentEnrollCertificateOut] = None
    protocol: Optional[AgentProtocolOut] = None


class AgentHeartbeatIn(BaseModel):
    status: str = Field(default="ok", max_length=32)
    uptime_seconds: Optional[int] = None
    agent_version: Optional[str] = Field(default=None, max_length=64)
    protocol_version: Optional[int] = Field(default=None, ge=0, le=1000)
    profile: Optional[str] = Field(default=None, max_length=32)
    capabilities: Optional[Dict[str, Any]] = None
    modules: Optional[Dict[str, Any]] = None
    metrics: Optional[Dict[str, Any]] = None


class AgentConfigUpdateIn(BaseModel):
    config: Dict[str, Any] = Field(default_factory=dict)


class AgentPublic(BaseModel):
    agent_id: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime
    last_seen_at: Optional[datetime]
    observed_address: Optional[str] = None
    observed_address_at: Optional[datetime] = None
    is_revoked: bool
    metadata: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)


class AgentDetail(AgentPublic):
    config: Dict[str, Any] = Field(default_factory=dict)


class AgentUpdateIn(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)
    tags: Optional[List[str]] = Field(default=None)
    metadata: Optional[Dict[str, Any]] = Field(default=None)


class AgentCertificateRenewIn(BaseModel):
    csr_pem: str = Field(..., min_length=1, max_length=16384)


class AgentCertificateRenewOut(BaseModel):
    agent_id: str
    certificate_pem: str
    ca_pem: str
    server_ca_pem: Optional[str] = None
    serial_hex: str
    not_before: datetime
    not_after: datetime


class AgentBootstrapTokenCreateIn(BaseModel):
    ttl_seconds: Optional[int] = Field(default=None, ge=60, le=86400)
    max_uses: Optional[int] = Field(default=None, ge=1, le=100)
    description: Optional[str] = Field(default=None, max_length=256)


class AgentBootstrapTokenOut(BaseModel):
    agent_id: str
    bootstrap_token: str
    expires_at: datetime
    max_uses: int


class AgentReleaseArtifactOut(BaseModel):
    os: Literal["linux"]
    architecture: Literal["amd64", "arm64"]
    filename: str
    download_url: str
    sbom_url: str


class AgentReleaseOut(BaseModel):
    version: str
    tag: str
    channel: Literal["stable"]
    artifacts: List[AgentReleaseArtifactOut]
    checksums_url: str
    checksums_signature_url: str
    checksums_certificate_url: str
    protocol_contract_url: str
    compatibility_contract_url: str


class AgentPackageStateOut(BaseModel):
    architecture: Literal["amd64", "arm64"]
    filename: str
    sha256: str
    size_bytes: int
    cached: bool
    error: Optional[str] = None


class AgentOnboardingOut(BaseModel):
    api_url: str
    enroll_url: str
    profiles: List[str] = Field(default_factory=list)
    default_profile: str
    collectors: List[str] = Field(default_factory=list)
    default_collectors: List[str] = Field(default_factory=list)
    token_ttl_seconds: int
    token_max_uses: int
    protocol_version: int
    min_supported_protocol: int
    max_supported_protocol: int
    server_ca_required: bool
    server_ca_fingerprint_sha256: Optional[str] = None
    server_ca_pem: Optional[str] = None
    release: AgentReleaseOut
    packages: List[AgentPackageStateOut] = Field(default_factory=list)


class AgentEnrollmentTicketIn(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    profile: Optional[str] = Field(default=None, max_length=32)
    architecture: Literal["amd64", "arm64"] = "amd64"
    sources: Optional[List[str]] = Field(default=None, max_length=16)
    ttl_seconds: Optional[int] = Field(default=None, ge=60, le=86400)
    description: Optional[str] = Field(default=None, max_length=256)


class AgentEnrollmentTicketOut(BaseModel):
    agent_id: str
    profile: str
    sources: List[str] = Field(default_factory=list)
    bootstrap_token: str
    expires_at: datetime
    max_uses: int
    api_url: str
    enroll_url: str
    architecture: Literal["amd64", "arm64"]
    artifact: AgentReleaseArtifactOut
    release: AgentReleaseOut
    server_ca_required: bool
    server_ca_fingerprint_sha256: Optional[str] = None
    server_ca_pem: Optional[str] = None
    install_command: str
    installer_filename: str
    installer_command: str
    bootstrap_command: str


class AgentPackageSyncOut(BaseModel):
    version: str
    packages: List[AgentPackageStateOut] = Field(default_factory=list)
