export type CorrelationLifecycleStatus = "open" | "triaged" | "closed" | "suppressed";

export type CorrelationRiskScore = number | null;
export type CorrelationConfidence = number | null;
export type CorrelationEntityType = string | null;
export type CorrelationEntityValue = string | null;
export type CorrelationDedupKey = string;
export type CorrelationContext = Record<string, unknown>;

export type CorrelationMitreTechnique = {
  id: string;
  name?: string | null;
};

export type CorrelationMitreMetadata = {
  tactics: string[];
  techniques: CorrelationMitreTechnique[];
};

export type CorrelationStage = {
  id?: string | null;
  name: string;
  patterns: string[];
  include_patterns: string[];
  exclude_patterns: string[];
  min_count: number;
  after?: string | null;
  within_seconds?: number | null;
  required: boolean;
  maxspan_seconds?: number | null;
};

export type CorrelationRuleStrategy =
  | "threshold"
  | "burst"
  | "sequence"
  | "chain"
  | "cardinality"
  | "temporal_join"
  | "risk_aggregation"
  | "new_entity"
  | "rare_entity"
  | string;

export type CorrelationRule = {
  id: number;
  name: string;
  description?: string | null;
  enabled: boolean;
  severity: string;
  strategy: CorrelationRuleStrategy;
  group_by: string;
  window_seconds: number;
  min_alerts: number;
  include_patterns: string[];
  exclude_patterns: string[];
  stages: CorrelationStage[];
  entity: Record<string, unknown> | null;
  strategy_config: Record<string, unknown> | null;
  risk_config: Record<string, unknown> | null;
  evidence_config: Record<string, unknown> | null;
  lifecycle_config: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
};

export type CorrelationRuleIn = Omit<CorrelationRule, "id" | "created_at" | "updated_at">;

export type CorrelationAlertRef = {
  id: number;
  created_at: string;
  rule_id: string;
  severity: string;
  src_ip?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  description: string;
};

export type CorrelationEvidenceType =
  | "alert"
  | "net_event"
  | "vulnerability"
  | "exposure_finding"
  | "attack_chain_step"
  | "attack_chain_case"
  | string;

export type CorrelationEvidence = {
  id?: number;
  incident_id?: number;
  alert_id?: number | null;
  net_event_id?: number | null;
  evidence_type: CorrelationEvidenceType;
  rule_id?: string | null;
  stage?: string | null;
  timestamp: string;
  src_ip?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  details: CorrelationContext;
};

export type CorrelationDurableIncident = {
  id: number;
  correlation_rule_id?: number | null;
  correlation_rule_name: string;
  status: CorrelationLifecycleStatus | string;
  severity: string;
  risk_score: CorrelationRiskScore;
  confidence: CorrelationConfidence;
  entity_type: CorrelationEntityType;
  entity_value: CorrelationEntityValue;
  group_by: string;
  group_value: string;
  dedup_key: CorrelationDedupKey;
  started_at: string;
  last_seen_at: string;
  closed_at?: string | null;
  alert_count: number;
  unique_rules: string[];
  stage_hits: Record<string, number>;
  created_at: string;
  updated_at: string;
  summary?: string | null;
  context?: CorrelationContext;
};

export type CorrelationIncidentDetail = CorrelationDurableIncident & {
  summary?: string | null;
  context: CorrelationContext;
  evidence: CorrelationEvidence[];
};

export type CorrelationRunIncident = {
  id: string;
  correlation_rule_id: number;
  correlation_rule_name: string;
  severity: string;
  group_by: string;
  group_value: string;
  entity_type: CorrelationEntityType;
  entity_value: CorrelationEntityValue;
  started_at: string;
  ended_at: string;
  alert_count: number;
  unique_rules: string[];
  stage_hits: Record<string, number>;
  risk_score: CorrelationRiskScore;
  confidence: CorrelationConfidence;
  summary?: string | null;
  context: CorrelationContext;
  sample_alerts: CorrelationAlertRef[];
  evidence_items: CorrelationEvidence[];
  db_id?: number | null;
  status: CorrelationLifecycleStatus | string;
};

export type CorrelationRuleRunResult = {
  rules_evaluated: number;
  alerts_scanned: number;
  incidents: CorrelationRunIncident[];
};

export type CorrelationIncidentStatusUpdate = {
  status: CorrelationLifecycleStatus;
  summary?: string | null;
};
