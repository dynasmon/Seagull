export type AlertSeverity = "critical" | "high" | "medium" | "low" | "unknown";

export type AlertStatus = "open" | "acknowledged" | "investigating" | "closed";

export type AlertDisposition =
  | "true_positive"
  | "false_positive"
  | "benign"
  | "duplicate"
  | "expected_activity"
  | "unknown";

export type Alert = {
  id: number;
  rule_id: string;
  severity: AlertSeverity | string;
  confidence?: number;
  mitre_tactic?: string | null;
  mitre_technique_id?: string | null;
  mitre_technique?: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  description: string;
  details: Record<string, any> | null;
  created_at: string;
  detector_type?: string | null;
  rule_version?: number | null;
  rule_hash?: string | null;
  ruleset_version?: string | null;
  status: AlertStatus;
  disposition?: AlertDisposition | null;
  priority?: number | null;
  assigned_to?: string | null;
  investigation_id?: number | null;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
  closed_at?: string | null;
  closed_by?: string | null;
  triage_notes?: string | null;
  risk_score?: number | null;
};

export type AlertEvidenceItem = {
  id: number;
  alert_id: number;
  event_id?: number | null;
  evidence_type: string;
  evidence_role: string;
  entity_type?: string | null;
  entity_value?: string | null;
  matched_field?: string | null;
  matched_value?: string | null;
  summary?: string | null;
  raw_context: Record<string, any>;
  created_at: string;
};

export type AlertTriageIn = {
  status?: AlertStatus | null;
  disposition?: AlertDisposition | null;
  priority?: number | null;
  assigned_to?: string | null;
  investigation_id?: number | null;
  triage_notes?: string | null;
  risk_score?: number | null;
};

export type RuleOut = {
  id: string;
  name?: string | null;
  description?: string | null;
  source_file?: string | null;
  pack?: string | null;
  category?: string | null;
  rule_version: number;
  enabled: boolean;
  severity: string;
  type?: string | null;
  window?: string | null;
  cooldown?: string | null;
  has_override: boolean;
  updated_at?: string | null;
  base: Record<string, any>;
  override?: Record<string, any> | null;
  effective: Record<string, any>;
};

export type RuleOverrideIn = {
  enabled?: boolean | null;
  severity?: string | null;
  window?: string | null;
  cooldown?: string | null;
  min_events?: number | null;
  condition?: Record<string, any> | null;
  schedule?: Record<string, any> | null;
  tuning?: Record<string, any> | null;
  suppressions?: Array<Record<string, any>> | null;
  patch?: Record<string, any> | null;
};

export type RuleSchedule = {
  enabled: boolean;
  timezone: string;
  days: string[];
  start: string;
  end: string;
};

export type RuleGovernanceHistory = {
  id: number;
  rule_id: string;
  kind: "tuning" | "suppression" | string;
  action: string;
  created_at: string;
  actor_user_id?: number | null;
  actor_username?: string | null;
  snapshot: Record<string, any>;
};

export type RuleValidationResult = {
  ok: boolean;
  errors: string[];
  effective: Record<string, any> | null;
};
