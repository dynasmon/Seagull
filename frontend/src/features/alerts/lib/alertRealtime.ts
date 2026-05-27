import type { PortalRealtimeEventPayloadMap } from "@/shared/realtime";

import type { Alert } from "../types";

export function buildAlertFromRealtimeDelta(
  payload: PortalRealtimeEventPayloadMap["ui.alerts.delta.patch"],
  fallbackTimestamp: string,
): Alert | null {
  const projected = payload?.alert;
  const id = Number(projected?.id ?? 0);
  if (!Number.isFinite(id) || id <= 0) return null;

  const createdAt = String(projected?.created_at || fallbackTimestamp || new Date().toISOString());
  return {
    id: Math.trunc(id),
    rule_id: String(projected?.rule_id || "realtime.alert"),
    severity: String(projected?.severity || "medium"),
    confidence: typeof projected?.confidence === "number" ? projected.confidence : undefined,
    src_ip: typeof projected?.src_ip === "string" ? projected.src_ip : null,
    dst_ip: typeof projected?.dst_ip === "string" ? projected.dst_ip : null,
    dst_port: typeof projected?.dst_port === "number" ? projected.dst_port : null,
    description: String(projected?.description || "Realtime alert"),
    details: null,
    created_at: createdAt,
    status: "open" as const,
  };
}
