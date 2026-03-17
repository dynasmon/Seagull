export type Agent = {
  agent_id: string;
  created_at: string;
  last_seen_at: string;
  is_revoked: boolean;
  metadata: Record<string, any>;
  metrics: Record<string, any>;
};

export type NetEvent = {
  id: number;
  agent_id: string;
  event_type: string;
  schema_version: number;
  timestamp: string;
  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  proto?: string | null;
  bytes?: number | null;
  extra: Record<string, any>;
};

export type Alert = {
  id: number;
  created_at: string;
  rule_id: string;
  severity: string;
  src_ip?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  description: string;
  details: Record<string, any>;
};

export type TimeSeries = {
  series: string[];
  data: Array<Record<string, any>>;
};

export type OverviewKPIs = {
  total_agents: number;
  online_agents: number;
  events_5m: number;
  alerts_60m: number;
  last_event_age_m: number | null;
};

/**
 * A single payload for the Overview page.
 * The goal is to avoid multiple heavy queries on the frontend.
 */
export type OverviewSnapshot = {
  kpis: OverviewKPIs;
  traffic: TimeSeries;
  ssh_failures: TimeSeries;
  alert_severity: TimeSeries;
  ddos: TimeSeries;
  ddos_volume: TimeSeries;
  ports: Array<{ port: number; count: number }>;
  top_sources: Array<{ src_ip: string; count: number }>;
  recent_alerts: Alert[];
  ddos_alerts: Alert[];
  recent_ssh: Array<{ ts: string; src: string; dst: string; user: string; action: string }>;
  raw_events: Array<{
    id: number;
    timestamp: string;
    agent_id: string;
    event_type: string;
    src_ip?: string | null;
    dst_ip?: string | null;
    dst_port?: number | null;
  }>;
};


export type StormStatus = {
  active: boolean;
  phase?: "ok" | "storm" | "shedding" | "draining";
  eps: number;
  ingest_rate_eps?: number;
  process_rate_eps?: number;
  processed_messages_per_sec?: number;
  sample_hot_percent: number;
  sample_warm_percent: number;
  drop_percent: number;
  shed_percent?: number;
  rejected_events?: number;
  rollup_only_events?: number;
  backlog_events: number;
  backlog_messages: number;
  workers_active?: number;
  draining_seconds?: number;
  reason: string;
  since: string | null;
  open_alert_id: number | null;
};

export type StormRecoverResponse = {
  ok: boolean;
  reason?: string;
  deleted_direct_keys?: number;
  deleted_cache_keys?: number;
  clear_backlog_counters?: boolean;
  clear_ui_caches?: boolean;
};
