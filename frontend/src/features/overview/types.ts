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
