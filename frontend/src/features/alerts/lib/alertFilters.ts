import type { Alert } from "../types";

export function mergeUniqueById(newer: Alert[], older: Alert[]): Alert[] {
  const out: Alert[] = [];
  const seen = new Set<number>();

  for (const a of newer) {
    if (!a || typeof a.id !== "number") continue;
    if (seen.has(a.id)) continue;
    seen.add(a.id);
    out.push(a);
  }
  for (const a of older) {
    if (!a || typeof a.id !== "number") continue;
    if (seen.has(a.id)) continue;
    seen.add(a.id);
    out.push(a);
  }
  return out;
}

export function filterAlerts(alerts: Alert[], search: string): Alert[] {
  const qq = (search || "").trim().toLowerCase();
  if (!qq) return alerts;

  return (alerts || []).filter((a) => {
    const hay = [a.rule_id, a.src_ip, a.dst_ip, a.description, a.mitre_tactic, a.mitre_technique_id, a.mitre_technique]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return hay.includes(qq);
  });
}
