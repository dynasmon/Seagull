export type AlertSeverity = "critical" | "high" | "medium" | "low" | "unknown";

export type Alert = {
  id: number;
  rule_id: string;
  severity: AlertSeverity | string;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  description: string;
  details: Record<string, any> | null;
  created_at: string;
};

export type RuleOut = {
  id: string;
  name?: string | null;
  description?: string | null;
  source_file?: string | null;
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
  patch?: Record<string, any> | null;
};

export type RuleSchedule = {
  enabled: boolean;
  timezone: string;
  days: string[];
  start: string;
  end: string;
};
