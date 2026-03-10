import { apiGet } from "@/shared/lib/http";
import type { MetricsSnapshot, SystemStatusResponse } from "./types";

export function getBackendHealth() {
  return apiGet<{ status: string }>("/api/health", { cacheMs: 0, force: true });
}

export function getMetricsSnapshot() {
  return apiGet<MetricsSnapshot>("/api/metrics", { cacheMs: 0, force: true });
}

export function getSystemStatus() {
  return apiGet<SystemStatusResponse>("/api/admin/system-status", { cacheMs: 0, force: true });
}
