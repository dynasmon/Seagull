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

export type QuerySource =
  | "clickhouse"
  | "elasticsearch"
  | "postgres"
  | "recent_feed"
  | "rollup_1s"
  | "live_1s";

export type QueryProvenanceMeta = {
  source: QuerySource;
  fallback_chain: string[];
  degraded_reason: string | null;
  source_freshness_seconds: number | null;
  query_latency_ms: number | null;
  cache_hit: boolean;
  approximate: boolean;
  query_window_start: string | null;
  query_window_end: string | null;
};

export type EventHuntResponse = {
  items: NetEvent[];
  next_cursor: string | null;
  has_more: boolean;
  meta: QueryProvenanceMeta;
};

export type EventsViewConfig = {
  agent_id: string; // empty = all
  event_type: string; // empty = all
  window_minutes: number;
  limit: number;
  search: string;
  auto_refresh: boolean;
  refresh_ms: number;
  compact_rows: boolean;
  show_extra: boolean;
};
