import { apiGet } from "@/shared/lib/http";
import type { ApiGetOptions } from "@/shared/lib/http";

import type { CatalogueResponse, ObservabilityStatus, QueryEnvelope } from "./types";

const BASE = "/api/observability";

export type RangeParams = {
  start: number;
  end: number;
  step?: number;
  window?: string;
};

export function getObservabilityStatus(opts?: ApiGetOptions) {
  return apiGet<ObservabilityStatus>(`${BASE}/status`, opts);
}

export function getObservabilityCatalogue(opts?: ApiGetOptions) {
  return apiGet<CatalogueResponse>(`${BASE}/catalogue`, opts);
}

export function getInstantQuery(key: string, params: { window?: string } = {}, opts?: ApiGetOptions) {
  const q = new URLSearchParams();
  if (params.window) q.set("window", params.window);
  const suffix = q.toString() ? `?${q.toString()}` : "";
  return apiGet<QueryEnvelope>(`${BASE}/query/${encodeURIComponent(key)}${suffix}`, opts);
}

export function getRangeQuery(key: string, params: RangeParams, opts?: ApiGetOptions) {
  const q = new URLSearchParams();
  q.set("start", String(params.start));
  q.set("end", String(params.end));
  if (typeof params.step === "number" && params.step > 0) q.set("step", String(params.step));
  if (params.window) q.set("window", params.window);
  return apiGet<QueryEnvelope>(`${BASE}/query/${encodeURIComponent(key)}/range?${q.toString()}`, opts);
}
