import { getFlowIpContext } from "@/shared/lib/ipClassification";

import type { Alert } from "../types";

const PREFERRED_ORDER = [
  "event_type",
  "agent_id",
  "hostname",
  "username",
  "process_name",
  "process_path",
  "command",
  "action",
  "proto",
  "src_port",
  "dst_port",
  "dns_qname",
  "http_host",
  "http_method",
  "tls_sni",
  "ja4",
  "ja3",
  "severity",
  "score",
];

export function toDetailEntries(details: Record<string, any> | null | undefined): Array<{ key: string; value: string }> {
  if (!details || typeof details !== "object") return [];

  const keys = Object.keys(details);
  keys.sort((a, b) => {
    const ai = PREFERRED_ORDER.indexOf(a);
    const bi = PREFERRED_ORDER.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });

  const out: Array<{ key: string; value: string }> = [];
  for (const key of keys) {
    const value = (details as Record<string, unknown>)[key];
    if (value === null || value === undefined || value === "") continue;
    if (Array.isArray(value) || typeof value === "object") continue;
    out.push({ key, value: String(value) });
    if (out.length >= 24) break;
  }
  return out;
}

export function toDetailNested(details: Record<string, any> | null | undefined): Array<{ key: string; value: any }> {
  if (!details || typeof details !== "object") return [];
  const out: Array<{ key: string; value: any }> = [];
  for (const [k, v] of Object.entries(details)) {
    if (!v || (typeof v !== "object" && !Array.isArray(v))) continue;
    out.push({ key: k, value: v });
    if (out.length >= 8) break;
  }
  return out;
}

export function alertIpContext(alert: Alert, side: "src" | "dst") {
  const details = alert.details && typeof alert.details === "object" ? alert.details : null;
  return getFlowIpContext(details?.ip_context, side);
}
