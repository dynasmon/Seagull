export type CorrelationStage = {
  name: string;
  patterns: string[];
  min_count: number;
};

export type CorrelationRule = {
  id: number;
  name: string;
  description?: string | null;
  enabled: boolean;
  severity: string;
  strategy: "burst" | "chain" | string;
  group_by: string;
  window_seconds: number;
  min_alerts: number;
  include_patterns: string[];
  exclude_patterns: string[];
  stages: CorrelationStage[];
  created_at: string;
  updated_at: string;
};

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

export type CorrelationIncident = {
  id: string;
  correlation_rule_id: number;
  correlation_rule_name: string;
  severity: string;
  group_by: string;
  group_value: string;
  started_at: string;
  ended_at: string;
  alert_count: number;
  unique_rules: string[];
  stage_hits: Record<string, number>;
  sample_alerts: CorrelationAlertRef[];
};

export type CorrelationRunOut = {
  rules_evaluated: number;
  alerts_scanned: number;
  incidents: CorrelationIncident[];
};

export type CorrelationRuleIn = Omit<CorrelationRule, "id" | "created_at" | "updated_at">;
