export const PORTAL_REALTIME_TOPICS = [
  "overview",
  "alerts",
  "agents",
] as const;

export type PortalRealtimeTopic = (typeof PORTAL_REALTIME_TOPICS)[number];

export const PORTAL_REALTIME_MODES = [
  "patch",
  "append",
  "replace",
  "invalidate",
] as const;

export type PortalRealtimeMode = (typeof PORTAL_REALTIME_MODES)[number];

export const PORTAL_REALTIME_EVENT_TYPES = [
  "overview.invalidate",
  "overview.patch",
  "storm.status",
  "alert.created",
  "alert.updated",
  "agent.heartbeat",
] as const;

export type PortalRealtimeEventType = (typeof PORTAL_REALTIME_EVENT_TYPES)[number];

export const PORTAL_REALTIME_EVENT_TOPIC: Record<PortalRealtimeEventType, PortalRealtimeTopic> = {
  "overview.invalidate": "overview",
  "overview.patch": "overview",
  "storm.status": "overview",
  "alert.created": "alerts",
  "alert.updated": "alerts",
  "agent.heartbeat": "agents",
};

export const PORTAL_REALTIME_EVENT_MODE: Record<PortalRealtimeEventType, PortalRealtimeMode> = {
  "overview.invalidate": "invalidate",
  "overview.patch": "patch",
  "storm.status": "replace",
  "alert.created": "append",
  "alert.updated": "patch",
  "agent.heartbeat": "patch",
};

export const PORTAL_REALTIME_EVENT_SCOPE: Record<PortalRealtimeEventType, string> = {
  "overview.invalidate": "portal:realtime",
  "overview.patch": "portal:realtime",
  "storm.status": "portal:realtime",
  "alert.created": "portal:admin",
  "alert.updated": "portal:admin",
  "agent.heartbeat": "portal:realtime",
};

export type PortalRealtimeEventPayloadMap = {
  "overview.invalidate": {
    reason?: string;
    source?: string;
    scope?: string;
    phase?: "ok" | "storm" | "shedding" | "draining";
  };
  "overview.patch": {
    events_5m_delta?: number;
    backlog_events?: number;
    backlog_messages?: number;
    protection_active?: boolean;
    phase?: "ok" | "storm" | "shedding" | "draining";
    reason?: string;
  };
  "storm.status": {
    active?: boolean;
    phase?: "ok" | "storm" | "shedding" | "draining";
    eps?: number;
    ingest_rate_eps?: number;
    process_rate_eps?: number;
    processed_messages_per_sec?: number;
    sample_hot_percent?: number;
    sample_warm_percent?: number;
    drop_percent?: number;
    shed_percent?: number;
    rejected_events?: number;
    rollup_only_events?: number;
    backlog_events?: number;
    backlog_messages?: number;
    workers_active?: number;
    draining_seconds?: number;
    reason?: string;
    since?: string | null;
    open_alert_id?: number | null;
    quality_by_event_type?: Array<Record<string, unknown>>;
  };
  "alert.created": {
    alert_id?: number;
    created_at?: string;
    severity?: string;
    rule_id?: string;
    src_ip?: string | null;
    dst_ip?: string | null;
    dst_port?: number | null;
    description?: string;
    confidence?: number;
  };
  "alert.updated": {
    alert_id?: number;
    status?: string;
    updated_at?: string;
    severity?: string;
    rule_id?: string;
  };
  "agent.heartbeat": {
    agent_id?: string;
    status?: string;
    last_seen_at?: string;
    is_revoked?: boolean;
  };
};

export type PortalRealtimeEnvelope<TType extends PortalRealtimeEventType = PortalRealtimeEventType> = {
  version: number;
  topic: PortalRealtimeTopic;
  type: TType;
  cursor: string;
  timestamp: string;
  scope: string;
  mode: PortalRealtimeMode;
  payload: PortalRealtimeEventPayloadMap[TType];
};

export type PortalRealtimeAnyEvent = {
  [K in PortalRealtimeEventType]: PortalRealtimeEnvelope<K>;
}[PortalRealtimeEventType];

export function isPortalRealtimeEventType(value: unknown): value is PortalRealtimeEventType {
  return (
    typeof value === "string" &&
    (PORTAL_REALTIME_EVENT_TYPES as readonly string[]).includes(value)
  );
}

export function isPortalRealtimeTopic(value: unknown): value is PortalRealtimeTopic {
  return (
    typeof value === "string" &&
    (PORTAL_REALTIME_TOPICS as readonly string[]).includes(value)
  );
}

export function isPortalRealtimeMode(value: unknown): value is PortalRealtimeMode {
  return (
    typeof value === "string" &&
    (PORTAL_REALTIME_MODES as readonly string[]).includes(value)
  );
}
