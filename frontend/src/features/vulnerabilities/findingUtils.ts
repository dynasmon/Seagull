import type { VulnFinding } from "./types";

export function sevVariant(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

export function observationVariant(state: string) {
  const s = String(state || "").toLowerCase();
  if (s === "observed") return "info";
  if (s === "awaiting_verification") return "high";
  return "neutral";
}

export function dispositionVariant(disposition: string) {
  const s = String(disposition || "").toLowerCase();
  if (s === "accepted_risk") return "low";
  if (s === "suppressed") return "neutral";
  return "neutral";
}

export function findingAssetLabel(f: VulnFinding): string {
  return String(f.asset_display || f.target || f.asset_key || "-");
}

export function findingComponentLabel(f: VulnFinding): string {
  const name = String(f.component?.name || "").trim();
  if (name) return name;
  if (f.location) return String(f.location);
  return f.title;
}

export function findingInstalledVersion(f: VulnFinding): string | null {
  const value = String(f.component?.installed_version || "").trim();
  return value || null;
}

export function findingFixedVersion(f: VulnFinding): string | null {
  const value = String(f.component?.fixed_version || "").trim();
  return value || null;
}

export function findingExposureLabel(f: VulnFinding): string {
  if (f.exposure?.observed) return "Observed external exposure";
  if (f.exposure?.inferred) return "Inferred network exposure";
  return "No external signal";
}

export function findingObservationLabel(f: VulnFinding): string {
  const state = String(f.observation_state || "").toLowerCase();
  if (state === "awaiting_verification") return "Pending verification";
  if (state === "resolved") return "No longer observed";
  return "Still observed";
}

export function findingDispositionLabel(f: VulnFinding): string {
  const value = String(f.operator_disposition || "").toLowerCase();
  if (value === "accepted_risk") return "Accepted";
  if (value === "suppressed") return "Suppressed";
  return "Active";
}

export function sortFindingsByPriority(items: VulnFinding[]): VulnFinding[] {
  const copy = [...items];
  copy.sort((a, b) => {
    const scoreDiff = Number(b.priority?.score || 0) - Number(a.priority?.score || 0);
    if (scoreDiff !== 0) return scoreDiff;
    const seenDiff = Date.parse(b.last_seen_at || "") - Date.parse(a.last_seen_at || "");
    if (seenDiff !== 0) return seenDiff;
    return b.id - a.id;
  });
  return copy;
}

export function mergeFindingsById(current: VulnFinding[], incoming: VulnFinding[]): VulnFinding[] {
  const byId = new Map<number, VulnFinding>();
  for (const item of current) {
    if (!item || typeof item.id !== "number") continue;
    byId.set(item.id, item);
  }
  for (const item of incoming) {
    if (!item || typeof item.id !== "number") continue;
    byId.set(item.id, item);
  }
  return Array.from(byId.values());
}
