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

  first_seen_at: string;
  last_seen_at: string;
  occurrences: number;
  updated_at: string;
};

export type VulnFindingPatchIn = {
  status?: string;
  is_suppressed?: boolean;
};

export type VulnSummary = {
  generated_at: string;
  total_open: number;
  total_suppressed: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
};

export type VulnScan = {
  id: number;
  scan_uuid: string;
  reporter_agent_id: string | null;
  target: string | null;
  tool: string;
  tool_version: string | null;
  status: string;
  started_at: string;
  finished_at: string | null;
  scope: Record<string, any>;
  config: Record<string, any>;
  stats: Record<string, any>;
  created_at: string;
  updated_at: string;
};
