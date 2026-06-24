import { apiGet } from "@/shared/lib/http";
import type { ApiGetOptions } from "@/shared/lib/http";

import type { ThreatGeoResponse } from "./types";

export function getThreatGeo(
  params?: { since_minutes?: number; limit?: number; severity?: string | null },
  opts?: ApiGetOptions,
) {
  const q = new URLSearchParams();
  q.set("since_minutes", String(params?.since_minutes ?? 60 * 24));
  q.set("limit", String(params?.limit ?? 200));
  const severity = (params?.severity ?? "").trim();
  if (severity) q.set("severity", severity);

  return apiGet<ThreatGeoResponse>(`/api/threat-map/geo?${q.toString()}`, opts);
}
