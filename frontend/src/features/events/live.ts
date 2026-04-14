import type { RealtimeConnectionSnapshot, RealtimeConnectionStatus, RealtimeTransportKind } from "@/shared/realtime";
import type { PortalRealtimeEventPayloadMap } from "@/shared/realtime";

import { isDdosEvent } from "./lib/ddos";
import type { NetEvent } from "./types";

export type CompactLiveEventRow = NonNullable<PortalRealtimeEventPayloadMap["ui.events.stream.append"]["events"]>[number];

export type EventStreamLiveFilters = {
  agent_id: string;
  event_type: string;
  search: string;
  window_minutes: number;
};

export function compactRowToEvent(row: CompactLiveEventRow | null | undefined): NetEvent | null {
  if (!row || !row.timestamp || !row.agent_id || !row.event_type) return null;
  const id = Number(row.id ?? 0);
  if (!Number.isFinite(id) || id <= 0) return null;
  return {
    id,
    agent_id: String(row.agent_id),
    event_type: String(row.event_type),
    schema_version: Number(row.schema_version ?? 1) || 1,
    timestamp: String(row.timestamp),
    src_ip: row.src_ip ?? null,
    dst_ip: row.dst_ip ?? null,
    src_port: typeof row.src_port === "number" ? row.src_port : null,
    dst_port: typeof row.dst_port === "number" ? row.dst_port : null,
    proto: row.proto ?? null,
    bytes: typeof row.bytes === "number" ? row.bytes : null,
    extra: row.extra && typeof row.extra === "object" ? (row.extra as Record<string, any>) : {},
  };
}

export function mergeLiveEvents(primary: NetEvent[], secondary: NetEvent[], maxItems?: number): NetEvent[] {
  const merged = new Map<string, NetEvent>();
  for (const row of [...primary, ...secondary]) {
    const key = `${String(row.timestamp || "")}|${Number(row.id) || 0}`;
    if (!row.timestamp || merged.has(key)) continue;
    merged.set(key, row);
  }
  const out = Array.from(merged.values()).sort((a, b) => {
    const tsDiff = new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    if (tsDiff !== 0) return tsDiff;
    return (Number(b.id) || 0) - (Number(a.id) || 0);
  });
  if (typeof maxItems === "number" && maxItems > 0 && out.length > maxItems) {
    return out.slice(0, maxItems);
  }
  return out;
}

function matchesSearch(row: NetEvent, search: string): boolean {
  const token = String(search || "").trim().toLowerCase();
  if (!token) return true;
  const haystack = [
    row.agent_id,
    row.event_type,
    row.src_ip ?? "",
    row.dst_ip ?? "",
    row.proto ?? "",
    JSON.stringify(row.extra ?? {}),
  ]
    .join(" ")
    .toLowerCase();
  return haystack.includes(token);
}

export function matchesEventStreamFilters(
  row: NetEvent,
  filters: EventStreamLiveFilters,
  opts: {
    ddosScope?: boolean;
    pinnedEventType?: string;
  } = {},
): boolean {
  if (opts.ddosScope && !isDdosEvent(row)) return false;
  if (filters.agent_id && row.agent_id !== filters.agent_id) return false;
  const requiredType = opts.ddosScope ? "" : (opts.pinnedEventType || filters.event_type || "");
  if (requiredType && row.event_type !== requiredType) return false;
  if (!matchesSearch(row, filters.search)) return false;

  const cutoffMs = Date.now() - Math.max(1, Number(filters.window_minutes || 60)) * 60_000;
  const rowMs = Date.parse(row.timestamp || "");
  if (Number.isFinite(rowMs) && rowMs < cutoffMs) return false;
  return true;
}

export type LiveSurfaceStatus = {
  label: "live" | "reconnecting" | "degraded" | "fallback polling";
  tone: "success" | "warning" | "muted";
  transport: RealtimeTransportKind | null;
};

export function describeLiveSurface(
  connection: Pick<RealtimeConnectionSnapshot, "status" | "transport" | "isFallbackTransport">,
  args: {
    degraded?: boolean;
    fallbackPolling?: boolean;
  } = {},
): LiveSurfaceStatus {
  if (args.fallbackPolling || connection.status !== "open") {
    if (connection.status === "connecting" || connection.status === "retrying") {
      return { label: "reconnecting", tone: "warning", transport: connection.transport };
    }
    return { label: "fallback polling", tone: "muted", transport: connection.transport };
  }
  if (args.degraded || connection.transport !== "ws" || connection.isFallbackTransport) {
    return { label: "degraded", tone: "warning", transport: connection.transport };
  }
  return { label: "live", tone: "success", transport: connection.transport };
}

export function isRealtimeReconnecting(status: RealtimeConnectionStatus): boolean {
  return status === "connecting" || status === "retrying";
}
