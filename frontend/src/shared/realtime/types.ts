export const PORTAL_REALTIME_TOPICS = [
  "overview",
  "alerts",
  "agents",
  "investigations",
  "events",
  "inventory",
  "vulnerabilities",
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
  "ui.overview.invalidate",
  "ui.overview.kpi.patch",
  "ui.overview.storm.patch",
  "ui.alerts.invalidate",
  "ui.alerts.delta.patch",
  "ui.agents.invalidate",
  "ui.agents.presence.patch",
  "ui.investigations.invalidate",
  "ui.investigations.timeline.append",
  "ui.events.invalidate",
  "ui.inventory.invalidate",
  "ui.vulnerabilities.invalidate",
  "overview.invalidate",
  "overview.patch",
  "storm.status",
  "alerts.invalidate",
  "alert.created",
  "alert.updated",
  "agents.invalidate",
  "agent.heartbeat",
] as const;

export type PortalRealtimeEventType = (typeof PORTAL_REALTIME_EVENT_TYPES)[number];

export const PORTAL_REALTIME_EVENT_TOPIC: Record<PortalRealtimeEventType, PortalRealtimeTopic> = {
  "ui.overview.invalidate": "overview",
  "ui.overview.kpi.patch": "overview",
  "ui.overview.storm.patch": "overview",
  "ui.alerts.invalidate": "alerts",
  "ui.alerts.delta.patch": "alerts",
  "ui.agents.invalidate": "agents",
  "ui.agents.presence.patch": "agents",
  "ui.investigations.invalidate": "investigations",
  "ui.investigations.timeline.append": "investigations",
  "ui.events.invalidate": "events",
  "ui.inventory.invalidate": "inventory",
  "ui.vulnerabilities.invalidate": "vulnerabilities",
  "overview.invalidate": "overview",
  "overview.patch": "overview",
  "storm.status": "overview",
  "alerts.invalidate": "alerts",
  "alert.created": "alerts",
  "alert.updated": "alerts",
  "agents.invalidate": "agents",
  "agent.heartbeat": "agents",
};

export const PORTAL_REALTIME_EVENT_MODE: Record<PortalRealtimeEventType, PortalRealtimeMode> = {
  "ui.overview.invalidate": "invalidate",
  "ui.overview.kpi.patch": "patch",
  "ui.overview.storm.patch": "patch",
  "ui.alerts.invalidate": "invalidate",
  "ui.alerts.delta.patch": "patch",
  "ui.agents.invalidate": "invalidate",
  "ui.agents.presence.patch": "patch",
  "ui.investigations.invalidate": "invalidate",
  "ui.investigations.timeline.append": "append",
  "ui.events.invalidate": "invalidate",
  "ui.inventory.invalidate": "invalidate",
  "ui.vulnerabilities.invalidate": "invalidate",
  "overview.invalidate": "invalidate",
  "overview.patch": "patch",
  "storm.status": "replace",
  "alerts.invalidate": "invalidate",
  "alert.created": "append",
  "alert.updated": "patch",
  "agents.invalidate": "invalidate",
  "agent.heartbeat": "patch",
};

export const PORTAL_REALTIME_EVENT_SCOPE: Record<PortalRealtimeEventType, string> = {
  "ui.overview.invalidate": "portal:realtime",
  "ui.overview.kpi.patch": "portal:realtime",
  "ui.overview.storm.patch": "portal:realtime",
  "ui.alerts.invalidate": "portal:admin",
  "ui.alerts.delta.patch": "portal:admin",
  "ui.agents.invalidate": "portal:realtime",
  "ui.agents.presence.patch": "portal:realtime",
  "ui.investigations.invalidate": "portal:realtime",
  "ui.investigations.timeline.append": "portal:realtime",
  "ui.events.invalidate": "portal:realtime",
  "ui.inventory.invalidate": "portal:realtime",
  "ui.vulnerabilities.invalidate": "portal:admin",
  "overview.invalidate": "portal:realtime",
  "overview.patch": "portal:realtime",
  "storm.status": "portal:realtime",
  "alerts.invalidate": "portal:admin",
  "alert.created": "portal:admin",
  "alert.updated": "portal:admin",
  "agents.invalidate": "portal:realtime",
  "agent.heartbeat": "portal:realtime",
};

export type PortalRealtimeEventPayloadMap = {
  "ui.overview.invalidate": {
    reason?: string;
    source?: string;
    scope?: string;
    phase?: "ok" | "storm" | "shedding" | "draining";
    resume_from_cursor?: string;
    resume_to_cursor?: string;
  };
  "ui.overview.kpi.patch": {
    events_5m_delta?: number;
    backlog_events?: number;
    backlog_messages?: number;
    protection_active?: boolean;
    phase?: "ok" | "storm" | "shedding" | "draining";
    reason?: string;
  };
  "ui.overview.storm.patch": {
    active?: boolean;
    protection_active?: boolean;
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
  };
  "ui.alerts.invalidate": {
    reason?: string;
    scope?: string;
    resume_from_cursor?: string;
    resume_to_cursor?: string;
  };
  "ui.alerts.delta.patch": {
    action?: "upsert" | "patch";
    alert?: {
      id?: number;
      created_at?: string;
      updated_at?: string;
      severity?: string;
      rule_id?: string;
      status?: string;
      src_ip?: string | null;
      dst_ip?: string | null;
      dst_port?: number | null;
      description?: string;
      confidence?: number;
    };
    counters?: {
      alerts_60m_delta?: number;
    };
  };
  "ui.agents.invalidate": {
    reason?: string;
    scope?: string;
    resume_from_cursor?: string;
    resume_to_cursor?: string;
  };
  "ui.agents.presence.patch": {
    agent_id?: string;
    status?: string;
    last_seen_at?: string;
    is_revoked?: boolean;
  };
  "ui.investigations.invalidate": {
    reason?: string;
    scope?: string;
    workspace_id?: number;
    resume_from_cursor?: string;
    resume_to_cursor?: string;
  };
  "ui.investigations.timeline.append": {
    workspace_id?: number;
    activity?: {
      id?: string;
      activity_type?: string;
      action?: string;
      actor_username?: string | null;
      created_at?: string;
      outcome?: string;
      target_type?: string | null;
      target_id?: string | null;
      summary?: string;
      changed_fields?: string[];
    };
    workspace_patch?: {
      id?: number;
      updated_at?: string;
      status?: string;
      severity?: string;
      priority?: string;
      triage_state?: string;
      assignee?: string | null;
      updated_by?: string;
      notes_count?: number;
      bookmarks_count?: number;
      evidence_type_counts?: Record<string, number>;
    };
  };
  "ui.events.invalidate": {
    reason?: string;
    scope?: string;
    agent_id?: string;
    batch_size?: number;
    domains?: string[];
    event_types?: string[];
    high_priority?: boolean;
    resume_from_cursor?: string;
    resume_to_cursor?: string;
  };
  "ui.inventory.invalidate": {
    reason?: string;
    scope?: string;
    agent_id?: string;
    snapshot_id?: number;
    resume_from_cursor?: string;
    resume_to_cursor?: string;
  };
  "ui.vulnerabilities.invalidate": {
    reason?: string;
    scope?: string;
    agent_id?: string;
    scan_uuid?: string;
    status?: string;
    resume_from_cursor?: string;
    resume_to_cursor?: string;
  };
  "overview.invalidate": {
    reason?: string;
    source?: string;
    scope?: string;
    phase?: "ok" | "storm" | "shedding" | "draining";
    resume_from_cursor?: string;
    resume_to_cursor?: string;
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
    protection_active?: boolean;
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
  "alerts.invalidate": {
    reason?: string;
    scope?: string;
    resume_from_cursor?: string;
    resume_to_cursor?: string;
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
  "agents.invalidate": {
    reason?: string;
    scope?: string;
    resume_from_cursor?: string;
    resume_to_cursor?: string;
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
