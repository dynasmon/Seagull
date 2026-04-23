import { apiGet } from "@/shared/lib/http";
import type { ApiGetOptions } from "@/shared/lib/http";
import type { Agent, Alert, NetEvent, OverviewSnapshot, StormStatus } from "./types";

export function getAgents() {
  return apiGet<Agent[]>("/api/agents");
}

export function getRecentEvents(params?: { limit?: number; agent_id?: string; event_type?: string }) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 1000));
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.event_type) q.set("event_type", params.event_type);
  return apiGet<NetEvent[]>(`/api/events/recent?${q.toString()}`);
}

export function getRecentAlerts(limit = 100) {
  return apiGet<Alert[]>(`/api/alerts/recent?limit=${limit}`);
}

export function getPortStats(limit = 10) {
  return apiGet<Array<{ port: number; count: number }>>(`/api/events/stats/ports?limit=${limit}`);
}

// Aggregated snapshot for the Overview page (Grafana-like refresh).
// This endpoint is intentionally lightweight and optimized for frequent polling.
export function getOverview(
  params?: { window_minutes?: number; start_ts?: string; end_ts?: string; agent_id?: string; lite?: boolean },
  opts?: ApiGetOptions
) {
  const q = new URLSearchParams();
  if (params?.window_minutes) q.set("window_minutes", String(params.window_minutes));
  if (params?.start_ts) q.set("start_ts", params.start_ts);
  if (params?.end_ts) q.set("end_ts", params.end_ts);
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.lite) q.set("lite", "true");
  const qs = q.toString();
  return apiGet<OverviewSnapshot>(`/api/overview${qs ? `?${qs}` : ""}`, opts);
}


export function getStormStatus(opts?: ApiGetOptions) {
  return apiGet<StormStatus>("/api/ingest/storm/status", opts);
}
