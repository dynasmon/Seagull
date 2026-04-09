import type { Alert, OverviewSnapshot, StormStatus } from "@/features/overview/types";

export type OverviewRealtimePatch = {
  events_5m_delta?: number;
  backlog_events?: number;
  backlog_messages?: number;
  protection_active?: boolean;
  phase?: "ok" | "storm" | "shedding" | "draining";
  reason?: string;
};

export type OverviewRealtimeAlertPayload = {
  alert_id?: number;
  created_at?: string;
  rule_id?: string;
  severity?: string;
  src_ip?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  description?: string;
  confidence?: number;
};

function toSafeInt(value: unknown): number | null {
  const num = Number(value);
  if (!Number.isFinite(num)) return null;
  return Math.trunc(num);
}

function toSafeTsMs(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const ts = Date.parse(value);
  if (!Number.isFinite(ts)) return null;
  return ts;
}

function isDdosRuleId(ruleId: string): boolean {
  if (ruleId === "incident_ddos_correlated_v1") return true;
  return ruleId.startsWith("ddos_") || ruleId.startsWith("dos_") || ruleId.startsWith("l7_");
}

function isDdosLikeSeverity(severity: string): boolean {
  const s = String(severity || "").trim().toLowerCase();
  return s === "critical" || s === "high" || s === "medium";
}

function sortByCreatedAtDesc(rows: Alert[]): Alert[] {
  return rows.slice().sort((a, b) => {
    const bt = toSafeTsMs(b.created_at) ?? 0;
    const at = toSafeTsMs(a.created_at) ?? 0;
    return bt - at;
  });
}

function buildRealtimeAlert(
  payload: OverviewRealtimeAlertPayload | null | undefined,
  eventTimestamp: string,
): Alert | null {
  if (!payload || typeof payload !== "object") return null;
  const alertId = toSafeInt(payload.alert_id);
  if (alertId === null || alertId <= 0) return null;

  const createdAt = typeof payload.created_at === "string" && payload.created_at.trim()
    ? payload.created_at
    : eventTimestamp;

  return {
    id: alertId,
    created_at: createdAt,
    rule_id: String(payload.rule_id || "realtime.alert"),
    severity: String(payload.severity || "medium"),
    src_ip: typeof payload.src_ip === "string" ? payload.src_ip : null,
    dst_ip: typeof payload.dst_ip === "string" ? payload.dst_ip : null,
    dst_port: toSafeInt(payload.dst_port),
    description: String(payload.description || "Realtime alert"),
    details: {},
    confidence: toSafeInt(payload.confidence) ?? undefined,
  };
}

export function applyOverviewRealtimeAlertCreated(
  snapshot: OverviewSnapshot | null,
  payload: OverviewRealtimeAlertPayload | null | undefined,
  eventTimestamp: string,
): OverviewSnapshot | null {
  if (!snapshot) return snapshot;
  const alert = buildRealtimeAlert(payload, eventTimestamp);
  if (!alert) return snapshot;

  const existed = snapshot.recent_alerts.some((row) => intOrZero(row.id) === intOrZero(alert.id));
  const recentAlerts = sortByCreatedAtDesc(
    [alert, ...snapshot.recent_alerts.filter((row) => intOrZero(row.id) !== intOrZero(alert.id))],
  ).slice(0, 25);

  const isDdos = isDdosRuleId(String(alert.rule_id || "")) && isDdosLikeSeverity(String(alert.severity || ""));
  const ddosAlerts = isDdos
    ? sortByCreatedAtDesc(
        [alert, ...snapshot.ddos_alerts.filter((row) => intOrZero(row.id) !== intOrZero(alert.id))],
      ).slice(0, 15)
    : snapshot.ddos_alerts;

  const createdTs = toSafeTsMs(alert.created_at);
  const withinOneHour = createdTs !== null && createdTs >= (Date.now() - 60 * 60 * 1000);
  const nextAlerts60m = (!existed && withinOneHour)
    ? Math.max(0, intOrZero(snapshot.kpis.alerts_60m) + 1)
    : snapshot.kpis.alerts_60m;

  return {
    ...snapshot,
    kpis: {
      ...snapshot.kpis,
      alerts_60m: nextAlerts60m,
    },
    recent_alerts: recentAlerts,
    ddos_alerts: ddosAlerts,
  };
}

export function applyOverviewRealtimeAlertUpdated(
  snapshot: OverviewSnapshot | null,
  payload: OverviewRealtimeAlertPayload | null | undefined,
): OverviewSnapshot | null {
  if (!snapshot || !payload || typeof payload !== "object") return snapshot;
  const alertId = toSafeInt(payload.alert_id);
  if (alertId === null || alertId <= 0) return snapshot;

  const severity = typeof payload.severity === "string" && payload.severity.trim()
    ? payload.severity
    : null;
  const ruleId = typeof payload.rule_id === "string" && payload.rule_id.trim()
    ? payload.rule_id
    : null;

  let changed = false;
  const updateRows = (rows: Alert[]): Alert[] =>
    rows.map((row) => {
      if (intOrZero(row.id) !== alertId) return row;
      changed = true;
      return {
        ...row,
        severity: severity ?? row.severity,
        rule_id: ruleId ?? row.rule_id,
      };
    });

  const recentAlerts = updateRows(snapshot.recent_alerts);
  const ddosAlerts = updateRows(snapshot.ddos_alerts);

  if (!changed) return snapshot;
  return {
    ...snapshot,
    recent_alerts: recentAlerts,
    ddos_alerts: ddosAlerts,
  };
}

export function applyOverviewRealtimePatch(
  snapshot: OverviewSnapshot | null,
  patch: OverviewRealtimePatch | null | undefined,
): OverviewSnapshot | null {
  if (!snapshot || !patch || typeof patch !== "object") return snapshot;

  const eventsDelta = toSafeInt(patch.events_5m_delta) ?? 0;
  const backlogEvents = toSafeInt(patch.backlog_events);
  const backlogMessages = toSafeInt(patch.backlog_messages);
  const protectionActive =
    typeof patch.protection_active === "boolean" ? patch.protection_active : null;

  const nextEvents5m = Math.max(0, intOrZero(snapshot.kpis.events_5m) + eventsDelta);

  return {
    ...snapshot,
    kpis: {
      ...snapshot.kpis,
      events_5m: nextEvents5m,
      last_event_age_m: eventsDelta > 0 ? 0 : snapshot.kpis.last_event_age_m,
    },
    meta: {
      ...snapshot.meta,
      backlog_events:
        backlogEvents === null ? snapshot.meta.backlog_events : Math.max(0, backlogEvents),
      backlog_messages:
        backlogMessages === null ? snapshot.meta.backlog_messages : Math.max(0, backlogMessages),
      protection_active:
        protectionActive === null ? snapshot.meta.protection_active : protectionActive,
    },
  };
}

function intOrZero(value: unknown): number {
  const num = Number(value);
  if (!Number.isFinite(num)) return 0;
  return Math.trunc(num);
}

export function mergeStormStatus(
  current: StormStatus | null,
  incoming: Partial<StormStatus> | null | undefined,
): StormStatus | null {
  if (!incoming || typeof incoming !== "object") return current;

  const base: StormStatus =
    current ?? {
      active: false,
      phase: "ok",
      eps: 0,
      ingest_rate_eps: 0,
      process_rate_eps: 0,
      processed_messages_per_sec: 0,
      sample_hot_percent: 100,
      sample_warm_percent: 0,
      drop_percent: 0,
      shed_percent: 0,
      rejected_events: 0,
      rollup_only_events: 0,
      backlog_events: 0,
      backlog_messages: 0,
      workers_active: 0,
      draining_seconds: 0,
      reason: "ok",
      since: null,
      open_alert_id: null,
      quality_by_event_type: [],
    };

  return {
    ...base,
    ...incoming,
    quality_by_event_type:
      incoming.quality_by_event_type ?? base.quality_by_event_type ?? [],
  };
}

export function nextRealtimeInvalidationDelayMs({
  nowMs,
  lastRefreshAtMs,
  minIntervalMs,
  debounceMs,
}: {
  nowMs: number;
  lastRefreshAtMs: number;
  minIntervalMs: number;
  debounceMs: number;
}): number {
  const elapsed = Math.max(0, nowMs - Math.max(0, lastRefreshAtMs));
  if (elapsed >= minIntervalMs) return Math.max(0, debounceMs);
  return Math.max(0, minIntervalMs - elapsed);
}
