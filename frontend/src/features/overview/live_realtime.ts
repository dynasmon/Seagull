import type { OverviewSnapshot, StormStatus } from "@/features/overview/types";

export type OverviewRealtimePatch = {
  events_5m_delta?: number;
  backlog_events?: number;
  backlog_messages?: number;
  protection_active?: boolean;
  phase?: "ok" | "storm" | "shedding" | "draining";
  reason?: string;
};

function toSafeInt(value: unknown): number | null {
  const num = Number(value);
  if (!Number.isFinite(num)) return null;
  return Math.trunc(num);
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
