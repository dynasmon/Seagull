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
  };
  "overview.patch": {
    section?: string;
    patch?: Record<string, unknown>;
  };
  "storm.status": {
    state?: string;
    ingest_rate?: number;
    backlog_events?: number;
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
