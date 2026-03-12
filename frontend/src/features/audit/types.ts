export type AuditOutcome = "success" | "failure" | "denied" | "error" | string;

export type AuditEvent = {
  id: string;
  operation_id: string | null;
  created_at: string;
  event_type: string;
  action: string;
  outcome: AuditOutcome;
  actor_user_id: number | null;
  actor_username: string | null;
  resource_type: string;
  resource_id: string | null;
  request_id: string | null;
  trace_id: string | null;
  ip: string | null;
  user_agent: string | null;
  method: string | null;
  path: string | null;
  reason: string | null;
  error: string | null;
  changed_fields: string[];
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  context: Record<string, unknown>;
  prev_event_hash: string | null;
  event_hash: string | null;
};

export type AuditQueryOut = {
  items: AuditEvent[];
  has_more: boolean;
};

export type AuditSeverity = "critical" | "high" | "medium" | "low" | "neutral";

export type LoginEvidenceEvent = {
  created_at: string;
  username: string;
  method: string;
  ip: string | null;
  user_agent: string | null;
  succeeded: boolean;
};

export type RuntimeConfigOut = {
  config: Record<string, any>;
};

export type AuditFilters = {
  limit: number;
  eventType: string;
  action: string;
  outcome: string;
  resourceType: string;
  actor: string;
  from: string;
  to: string;
  query: string;
  origin: string;
  sort: "desc" | "asc";
};
