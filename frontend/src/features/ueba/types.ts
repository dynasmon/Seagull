export type UebaBaselineStatus = "warmup" | "mature" | "stale";
export type UebaFindingStatus = "open" | "closed" | "suppressed";
export type UebaSeverity = "informational" | "low" | "medium" | "high" | "critical";
export type UebaDetectorStatus = "idle" | "healthy" | "degraded" | "failing" | "disabled";
export type UebaRunStatus = "running" | "completed" | "failed";
export type UebaVerdict = "true_positive" | "false_positive" | "benign_acknowledged";
export type UebaMlModelStatus = "unavailable" | "training" | "active" | "stale";

export type UebaBaseline = {
  id: number;
  baseline_key: string;
  detector_id: string;
  detector_version: number;
  agent_id: string | null;
  entity_type: string;
  entity_value: string;
  metric_name: string;
  bucket_key: string;
  status: UebaBaselineStatus;
  sample_count: number;
  warmup_started_at: string;
  matured_at: string | null;
  window_started_at: string;
  window_ended_at: string;
  last_observed_at: string;
  expected_value: number | null;
  dispersion: number | null;
  lower_bound: number | null;
  upper_bound: number | null;
  confidence: number;
  state: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type UebaFindingEvidence = {
  id: number;
  finding_id: number;
  event_id: number | null;
  alert_id: number | null;
  evidence_type: string;
  evidence_role: string;
  observed_at: string;
  entity_type: string | null;
  entity_value: string | null;
  matched_field: string | null;
  matched_value: string | null;
  summary: string | null;
  raw_context: Record<string, unknown>;
  created_at: string;
};

export type UebaFinding = {
  id: number;
  finding_key: string;
  dedup_key: string;
  detector_id: string;
  detector_version: number;
  baseline_id: number | null;
  agent_id: string | null;
  entity_type: string;
  entity_value: string;
  metric_name: string;
  bucket_key: string;
  status: UebaFindingStatus;
  severity: UebaSeverity;
  confidence: number;
  risk_score: number;
  expected_value: number | null;
  observed_value: number | null;
  deviation_score: number | null;
  first_seen_at: string;
  last_seen_at: string;
  window_started_at: string;
  window_ended_at: string;
  cooldown_until: string | null;
  closed_at: string | null;
  occurrence_count: number;
  summary: string;
  reason_codes: string[];
  explanation: Record<string, unknown>;
  alert_id: number | null;
  mitre_tactic: string | null;
  mitre_technique_id: string | null;
  mitre_technique: string | null;
  latest_verdict: UebaVerdict | null;
  latest_verdict_at: string | null;
  latest_verdict_by: string | null;
  created_at: string;
  updated_at: string;
};

export type UebaFeedback = {
  id: number;
  finding_id: number;
  detector_id: string;
  entity_type: string;
  entity_value: string;
  agent_id: string | null;
  verdict: UebaVerdict;
  annotated_by: string;
  annotated_at: string;
  suppression_ttl_seconds: number | null;
  notes: string | null;
  is_override: boolean;
  created_at: string;
};

export type UebaFindingDetail = UebaFinding & {
  baseline: UebaBaseline | null;
  evidence: UebaFindingEvidence[];
  feedback: UebaFeedback[];
};

export type UebaDetectorState = {
  detector_id: string;
  detector_version: number | null;
  enabled: boolean;
  status: UebaDetectorStatus;
  consecutive_failures: number;
  baseline_count: number;
  mature_baseline_count: number;
  open_findings: number;
  last_run_at: string | null;
  last_success_at: string | null;
  last_error_at: string | null;
  last_window_started_at: string | null;
  last_window_ended_at: string | null;
  next_run_at: string | null;
  error_type: string | null;
  error_message: string | null;
  ml_model_status: UebaMlModelStatus;
  ml_model_trained_at: string | null;
  context: Record<string, unknown>;
  updated_at: string;
};

export type UebaDetectorRun = {
  id: number;
  detector_id: string;
  detector_version: number | null;
  started_at: string;
  finished_at: string | null;
  status: UebaRunStatus;
  window_started_at: string | null;
  window_ended_at: string | null;
  scanned_events: number;
  evaluated_entities: number;
  baselines_created: number;
  baselines_updated: number;
  findings_created: number;
  findings_updated: number;
  alerts_created: number;
  suppressions_applied: number;
  duration_ms: number | null;
  error_type: string | null;
  error_message: string | null;
  context: Record<string, unknown>;
};

export type UebaSummary = {
  enabled: boolean;
  generated_at: string;
  total_baselines: number;
  warming_baselines: number;
  mature_baselines: number;
  stale_baselines: number;
  open_findings: number;
  high_or_critical_open_findings: number;
  linked_alerts: number;
  detectors_total: number;
  detectors_healthy: number;
  detectors_degraded: number;
  detectors_failing: number;
  latest_run_at: string | null;
  latest_finding_at: string | null;
  verdicts_last_24h: number;
  false_positive_rate_7d: number;
  suppressed_entities: number;
};

export type UebaFindingTriageBody = {
  status?: UebaFindingStatus | null;
  cooldown_extension_minutes?: number;
  verdict?: UebaVerdict | null;
  notes?: string | null;
  suppression_ttl_seconds?: number | null;
  override?: boolean;
};
