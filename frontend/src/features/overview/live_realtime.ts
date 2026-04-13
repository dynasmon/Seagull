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

export type OverviewRealtimeAlertsDeltaPayload = {
  action?: "upsert" | "patch";
  alert?: {
    id?: number;
    created_at?: string;
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

function mergeAlertsByRecency(newer: Alert[], older: Alert[], limit: number): Alert[] {
  const merged = new Map<number, Alert>();
  for (const row of [...newer, ...older]) {
    const id = intOrZero(row.id);
    if (id <= 0 || merged.has(id)) continue;
    merged.set(id, row);
  }
  return sortByCreatedAtDesc(Array.from(merged.values())).slice(0, Math.max(1, limit));
}

type RawEventRow = OverviewSnapshot["raw_events"][number];

function rawEventTsMs(row: RawEventRow): number {
  return toSafeTsMs(row.timestamp) ?? 0;
}

function mergeRawEvents(newer: RawEventRow[], older: RawEventRow[], limit: number): RawEventRow[] {
  const merged = new Map<string, RawEventRow>();
  for (const row of [...newer, ...older]) {
    const key = `${String(row.timestamp || "")}|${intOrZero(row.id)}`;
    if (!row.timestamp || merged.has(key)) continue;
    merged.set(key, row);
  }
  return Array.from(merged.values())
    .sort((a, b) => {
      const tsDiff = rawEventTsMs(b) - rawEventTsMs(a);
      if (tsDiff !== 0) return tsDiff;
      return intOrZero(b.id) - intOrZero(a.id);
    })
    .slice(0, Math.max(1, limit));
}

function mergeRecentSshRows(
  newer: OverviewSnapshot["recent_ssh"],
  older: OverviewSnapshot["recent_ssh"],
  limit: number,
): OverviewSnapshot["recent_ssh"] {
  const merged = new Map<string, OverviewSnapshot["recent_ssh"][number]>();
  for (const row of [...newer, ...older]) {
    const key = [
      String(row.timestamp || row.ts || ""),
      String(row.id ?? 0),
      String(row.agent_id || ""),
      String(row.src_ip || row.src || ""),
      String(row.dst_ip || row.dst || ""),
      String(row.username || row.user || ""),
      String(row.action || ""),
      String(row.dst_port ?? ""),
      String(row.proto || ""),
    ].join("|");
    if (!key || merged.has(key)) continue;
    merged.set(key, row);
  }
  return Array.from(merged.values())
    .sort((a, b) => {
      const tsDiff = (toSafeTsMs(b.timestamp || b.ts) ?? 0) - (toSafeTsMs(a.timestamp || a.ts) ?? 0);
      if (tsDiff !== 0) return tsDiff;
      return intOrZero(b.id) - intOrZero(a.id);
    })
    .slice(0, Math.max(1, limit));
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
  const confidence = toSafeInt(payload.confidence);

  return {
    id: alertId,
    created_at: createdAt,
    rule_id: String(payload.rule_id || "realtime.alert"),
    severity: String(payload.severity || "medium"),
    src_ip: typeof payload.src_ip === "string" ? payload.src_ip : null,
    dst_ip: typeof payload.dst_ip === "string" ? payload.dst_ip : null,
    dst_port: toSafeInt(payload.dst_port),
    description: String(payload.description || "Realtime alert"),
    details: confidence === null ? {} : { confidence },
  };
}

function buildRealtimeAlertFromDelta(
  payload: OverviewRealtimeAlertsDeltaPayload | null | undefined,
): OverviewRealtimeAlertPayload | null {
  if (!payload || typeof payload !== "object") return null;
  const alert = payload.alert;
  if (!alert || typeof alert !== "object") return null;
  const alertId = toSafeInt(alert.id);
  if (alertId === null || alertId <= 0) return null;

  return {
    alert_id: alertId,
    created_at: typeof alert.created_at === "string" ? alert.created_at : undefined,
    rule_id: typeof alert.rule_id === "string" ? alert.rule_id : undefined,
    severity: typeof alert.severity === "string" ? alert.severity : undefined,
    src_ip: typeof alert.src_ip === "string" ? alert.src_ip : null,
    dst_ip: typeof alert.dst_ip === "string" ? alert.dst_ip : null,
    dst_port: toSafeInt(alert.dst_port),
    description: typeof alert.description === "string" ? alert.description : undefined,
    confidence: toSafeInt(alert.confidence) ?? undefined,
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

export function applyOverviewRealtimeAlertsDelta(
  snapshot: OverviewSnapshot | null,
  payload: OverviewRealtimeAlertsDeltaPayload | null | undefined,
  eventTimestamp: string,
): OverviewSnapshot | null {
  if (!snapshot || !payload || typeof payload !== "object") return snapshot;
  const action = String(payload.action || "patch").trim().toLowerCase();
  const alertProjection = buildRealtimeAlertFromDelta(payload);
  let next: OverviewSnapshot | null = snapshot;

  if (action === "upsert") {
    next = applyOverviewRealtimeAlertCreated(next, alertProjection, eventTimestamp);
  } else {
    next = applyOverviewRealtimeAlertUpdated(next, alertProjection);
  }

  if (!next) return next;

  const delta = toSafeInt(payload.counters?.alerts_60m_delta) ?? 0;
  if (!delta) return next;

  return {
    ...next,
    kpis: {
      ...next.kpis,
      alerts_60m: Math.max(0, intOrZero(next.kpis.alerts_60m) + delta),
    },
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
  const raw = incoming as Record<string, unknown>;

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

  const incomingPhase = typeof raw.phase === "string" ? raw.phase : undefined;
  const activeFromProtection =
    typeof raw.protection_active === "boolean" ? raw.protection_active : undefined;

  let normalizedActive: boolean | undefined =
    typeof raw.active === "boolean" ? raw.active : undefined;
  if (normalizedActive === undefined && activeFromProtection !== undefined) {
    normalizedActive = activeFromProtection;
  }
  if (normalizedActive === undefined && incomingPhase) {
    normalizedActive =
      incomingPhase === "storm" || incomingPhase === "shedding" || incomingPhase === "draining";
  }

  return {
    ...base,
    ...incoming,
    ...(normalizedActive === undefined ? {} : { active: normalizedActive }),
    quality_by_event_type:
      incoming.quality_by_event_type ?? base.quality_by_event_type ?? [],
  };
}


export function applyStormStatusToOverviewSnapshot(
  snapshot: OverviewSnapshot | null,
  incoming: Partial<StormStatus> | null | undefined,
): OverviewSnapshot | null {
  if (!snapshot || !incoming || typeof incoming !== "object") return snapshot;

  const raw = incoming as Record<string, unknown>;
  const backlogEvents = toSafeInt(raw.backlog_events);
  const backlogMessages = toSafeInt(raw.backlog_messages);
  const incomingPhase = typeof raw.phase === "string" ? raw.phase : undefined;
  const active =
    typeof raw.active === "boolean"
      ? raw.active
      : typeof raw.protection_active === "boolean"
        ? raw.protection_active
        : incomingPhase === "storm" || incomingPhase === "shedding" || incomingPhase === "draining";

  const nextMeta = {
    ...snapshot.meta,
    backlog_events: backlogEvents === null ? snapshot.meta.backlog_events : Math.max(0, backlogEvents),
    backlog_messages: backlogMessages === null ? snapshot.meta.backlog_messages : Math.max(0, backlogMessages),
    protection_active: typeof active === "boolean" ? active : snapshot.meta.protection_active,
    draining: incomingPhase === "draining" ? true : incomingPhase === "ok" ? false : snapshot.meta.draining,
  };

  if (
    nextMeta.backlog_events === snapshot.meta.backlog_events &&
    nextMeta.backlog_messages === snapshot.meta.backlog_messages &&
    nextMeta.protection_active === snapshot.meta.protection_active &&
    nextMeta.draining === snapshot.meta.draining
  ) {
    return snapshot;
  }

  return {
    ...snapshot,
    meta: nextMeta,
  };
}

export function reconcileFetchedOverviewSnapshot(
  current: OverviewSnapshot | null,
  incoming: OverviewSnapshot,
  opts?: {
    preserveLiveFields?: boolean;
  },
): OverviewSnapshot {
  if (!current) return incoming;

  const preserveLiveFields = Boolean(opts?.preserveLiveFields);
  const incomingIsLite = Boolean(incoming.meta?.lite);
  // Only lite snapshots should inherit heavy sections from the current state.
  // Full snapshots must refresh heavy sections (recent SSH/raw events/alerts),
  // otherwise frequent realtime KPI patches can freeze those panels forever.
  const keepHeavySections = incomingIsLite;

  const next: OverviewSnapshot = keepHeavySections
    ? {
        ...incoming,
        ports: incomingIsLite ? current.ports : incoming.ports,
        top_sources: incomingIsLite ? current.top_sources : incoming.top_sources,
        recent_alerts: incomingIsLite ? current.recent_alerts : incoming.recent_alerts,
        ddos_alerts: incomingIsLite ? current.ddos_alerts : incoming.ddos_alerts,
        recent_ssh: incomingIsLite ? current.recent_ssh : incoming.recent_ssh,
        raw_events: incomingIsLite ? current.raw_events : incoming.raw_events,
      }
    : incoming;

  if (!preserveLiveFields) return next;

  return {
    ...next,
    kpis: {
      ...next.kpis,
      events_5m: intOrZero(current.kpis.events_5m),
      alerts_60m: Math.max(intOrZero(current.kpis.alerts_60m), intOrZero(next.kpis.alerts_60m)),
      last_event_age_m: current.kpis.last_event_age_m,
    },
    meta: {
      ...next.meta,
      backlog_events: intOrZero(current.meta.backlog_events),
      backlog_messages: intOrZero(current.meta.backlog_messages),
      protection_active: Boolean(current.meta.protection_active),
      draining: Boolean(current.meta.draining),
    },
    recent_alerts: mergeAlertsByRecency(current.recent_alerts, next.recent_alerts, 25),
    ddos_alerts: mergeAlertsByRecency(current.ddos_alerts, next.ddos_alerts, 15),
    recent_ssh: mergeRecentSshRows(current.recent_ssh, next.recent_ssh, 20),
    raw_events: mergeRawEvents(current.raw_events, next.raw_events, 30),
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
