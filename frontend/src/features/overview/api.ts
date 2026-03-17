import { apiGet, apiPost } from "@/shared/lib/http";
import type { Agent, Alert, NetEvent, OverviewSnapshot, StormRecoverResponse, StormStatus } from "./types";

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
export function getOverview(params?: { window_minutes?: number; agent_id?: string; lite?: boolean }) {
  const q = new URLSearchParams();
  if (params?.window_minutes) q.set("window_minutes", String(params.window_minutes));
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.lite) q.set("lite", "true");
  const qs = q.toString();
  return apiGet<OverviewSnapshot>(`/api/overview${qs ? `?${qs}` : ""}`);
}


export function getStormStatus() {
  return apiGet<StormStatus>("/api/ingest/storm/status");
}

export function recoverStormRuntime(params?: { clear_backlog_counters?: boolean; clear_ui_caches?: boolean }) {
  const q = new URLSearchParams();
  if (typeof params?.clear_backlog_counters === "boolean") q.set("clear_backlog_counters", String(params.clear_backlog_counters));
  if (typeof params?.clear_ui_caches === "boolean") q.set("clear_ui_caches", String(params.clear_ui_caches));
  const qs = q.toString();
  return apiPost<StormRecoverResponse>(`/api/ingest/storm/recover${qs ? `?${qs}` : ""}`);
}
