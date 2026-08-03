export type AgentPublic = {
  agent_id: string;
  display_name?: string | null;
  description?: string | null;
  tags: string[];
  created_at: string;
  last_seen_at?: string | null;
  observed_address?: string | null;
  observed_address_at?: string | null;
  is_revoked: boolean;
  metadata: Record<string, any>;
  metrics: Record<string, any>;
};

export type AgentDetail = AgentPublic & {
  config: Record<string, any>;
};

export type AgentUpdateIn = {
  display_name?: string | null;
  description?: string | null;
  tags?: string[] | null;
  metadata?: Record<string, any> | null;
};

export type AgentProfile = "sensor" | "managed";
export type AgentArchitecture = "amd64" | "arm64";

export type AgentReleaseArtifact = {
  os: "linux";
  architecture: AgentArchitecture;
  filename: string;
  download_url: string;
  sbom_url: string;
};

export type AgentRelease = {
  version: string;
  tag: string;
  channel: "stable";
  artifacts: AgentReleaseArtifact[];
  checksums_url: string;
  checksums_signature_url: string;
  checksums_certificate_url: string;
  protocol_contract_url: string;
  compatibility_contract_url: string;
};

export type AgentPackageState = {
  architecture: AgentArchitecture;
  filename: string;
  sha256: string;
  size_bytes: number;
  cached: boolean;
  error?: string | null;
};

export type AgentPackageSync = {
  version: string;
  packages: AgentPackageState[];
};

export type AgentOnboardingInfo = {
  api_url: string;
  enroll_url: string;
  profiles: string[];
  default_profile: string;
  collectors: string[];
  default_collectors: string[];
  token_ttl_seconds: number;
  token_max_uses: number;
  protocol_version: number;
  min_supported_protocol: number;
  max_supported_protocol: number;
  server_ca_required: boolean;
  server_ca_fingerprint_sha256?: string | null;
  server_ca_pem?: string | null;
  release: AgentRelease;
  packages: AgentPackageState[];
};

export type AgentEnrollmentTicketIn = {
  agent_id: string;
  profile?: AgentProfile;
  architecture?: AgentArchitecture;
  sources?: string[];
  ttl_seconds?: number;
  description?: string;
};

export type AgentEnrollmentTicket = {
  agent_id: string;
  profile: AgentProfile;
  sources: string[];
  bootstrap_token: string;
  expires_at: string;
  max_uses: number;
  api_url: string;
  enroll_url: string;
  architecture: AgentArchitecture;
  artifact: AgentReleaseArtifact;
  release: AgentRelease;
  server_ca_required: boolean;
  server_ca_fingerprint_sha256?: string | null;
  server_ca_pem?: string | null;
  install_command: string;
  installer_filename: string;
  installer_command: string;
  bootstrap_command: string;
};

export type ResponseActionCreateIn = {
  action_type: string;
  agent_id: string;
  payload?: Record<string, any>;
  expires_at?: string;
};

export type ResponseActionOut = {
  id: number;
  action_type: string;
  agent_id: string;
  status: string;
  payload: Record<string, any>;
  requested_by: string;
  requested_at: string;
  delivered_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  cancelled_at?: string | null;
  cancelled_by?: string | null;
  last_error?: string | null;
  created_at: string;
  updated_at: string;
  expires_at?: string | null;
};

export type ResponseActionResultOut = {
  id: number;
  response_action_id: number;
  agent_id: string;
  status: string;
  result_payload: Record<string, any>;
  error?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
  updated_at: string;
};
