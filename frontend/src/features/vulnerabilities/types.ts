export type VulnFindingComponent = {
  kind: string;
  name: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  ecosystem: string | null;
  manager: string | null;
  purl: string | null;
};

export type VulnFindingExposure = {
  source: string;
  observed: boolean;
  inferred: boolean;
  externally_exposed: boolean;
  package_relevant: boolean;
  surface_score: number;
  service_hints: string[];
  exposed_ports: number[];
};

export type VulnFindingPriority = {
  score: number;
  factors: string[];
};

export type VulnFinding = {
  id: number;
  scan_id: number | null;

  asset_key: string;
  asset_agent_id: string | null;
  reporter_agent_id: string | null;
  target: string | null;
  asset: Record<string, any>;

  source: string;
  external_id: string | null;
  fingerprint: string;

  severity: string;
  severity_rank: number;
  confidence: number;

  title: string;
  description: string | null;
  remediation: string | null;

  cve: string | null;
  cwe: string | null;
  cvss: string | null;

  location: string | null;
  tags: string[];
  evidence: Record<string, any>;

  status: string;
  is_suppressed: boolean;
  observation_state: string;
  operator_disposition: string;

  first_seen_at: string;
  last_seen_at: string;
  occurrences: number;
  updated_at: string;

  component: VulnFindingComponent;
  exposure: VulnFindingExposure;
  asset_display: string;
  asset_context: string[];
  risk_summary: string | null;
  remediation_guidance: string | null;
  repeated_observation: boolean;
  priority: VulnFindingPriority;
};

export type VulnFindingPatchIn = {
  status?: string;
  is_suppressed?: boolean;
  observation_state?: string;
  operator_disposition?: string;
};

export type VulnSummary = {
  generated_at: string;
  total_open: number;
  total_observed: number;
  total_awaiting_verification: number;
  total_resolved: number;
  total_suppressed: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_observation_state: Record<string, number>;
  by_disposition: Record<string, number>;
};

export type VulnRiskItem = {
  id: number;
  asset_key: string;
  asset_agent_id: string | null;
  target: string | null;
  title: string;
  cve: string | null;
  severity: string;
  confidence: number;
  occurrences: number;
  last_seen_at: string;
  remediation: string | null;
  cvss: string | null;
  cvss_score: number;
  has_fix: boolean;
  internet_exposed: boolean;
  exploit_likely: boolean;
  risk_score: number;
  component_name: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  asset_display: string;
  risk_summary: string | null;
  priority_factors: string[];
  exposure_source: string;
  service_hints: string[];
};

export type VulnAssetRisk = {
  asset_key: string;
  asset_agent_id: string | null;
  open_findings: number;
  critical_high: number;
  max_risk: number;
  avg_risk: number;
  last_seen_at: string;
};

export type VulnPosture = {
  generated_at: string;
  active_within_days: number;
  total_open: number;
  critical_open: number;
  high_open: number;
  exploitable_open: number;
  fixable_open: number;
  stale_open: number;
  mean_risk: number;
  p95_risk: number;
  top_risks: VulnRiskItem[];
  top_assets: VulnAssetRisk[];
};

export type VulnScan = {
  id: number;
  scan_uuid: string;
  reporter_agent_id: string | null;
  target: string | null;
  tool: string;
  tool_version: string | null;

  status: string;
  lifecycle_state: string;
  current_phase: string;

  queued_at: string;
  acknowledged_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  last_progress_at: string;
  duration_ms: number | null;

  trigger_source: string;
  error_summary: string | null;

  scope: Record<string, any>;
  config: Record<string, any>;
  stats: Record<string, any>;
  phase_timestamps: Record<string, string>;
  created_at: string;
  updated_at: string;
};

export type VulnManualScanResult = {
  agent_id: string;
  request_token: string;
  trigger_token?: string;
  scan_uuid: string;
  request_state: string;
  status: string;
  lifecycle_state: string;
  current_phase: string;
  queued_at: string;
  scan?: VulnScan;
};
