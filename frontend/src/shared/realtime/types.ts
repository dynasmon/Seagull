export const PORTAL_REALTIME_EVENT_TYPES = [
  "overview.invalidate",
  "overview.patch",
  "storm.status",
  "alert.created",
  "alert.updated",
  "agent.heartbeat",
] as const;

export type PortalRealtimeEventType = (typeof PORTAL_REALTIME_EVENT_TYPES)[number];

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
    severity?: string;
    rule_id?: string;
  };
  "alert.updated": {
    alert_id?: number;
    status?: string;
    severity?: string;
  };
  "agent.heartbeat": {
    agent_id?: string;
    status?: string;
    last_seen_at?: string;
  };
};

export type PortalRealtimeEnvelope<TType extends PortalRealtimeEventType = PortalRealtimeEventType> = {
  version: number;
  type: TType;
  timestamp: string;
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
