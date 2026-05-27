import { ALL_DAYS } from "../constants";

export function safeJsonString(v: any): string {
  try {
    return JSON.stringify(v ?? {}, null, 2);
  } catch {
    return "{}";
  }
}

export function parseJsonObject(s: string, label: string): { ok: true; value: any } | { ok: false; error: string } {
  const t = (s ?? "").trim();
  if (!t) return { ok: true, value: {} };
  try {
    const v = JSON.parse(t);
    if (v === null || typeof v !== "object" || Array.isArray(v)) {
      return { ok: false, error: `${label} must be a JSON object.` };
    }
    return { ok: true, value: v };
  } catch (e: any) {
    return { ok: false, error: e?.message || "Invalid JSON" };
  }
}

export function parseJsonArray(s: string, label: string): { ok: true; value: any[] } | { ok: false; error: string } {
  const t = (s ?? "").trim();
  if (!t) return { ok: true, value: [] };
  try {
    const v = JSON.parse(t);
    if (!Array.isArray(v)) {
      return { ok: false, error: `${label} must be a JSON array.` };
    }
    return { ok: true, value: v };
  } catch (e: any) {
    return { ok: false, error: e?.message || "Invalid JSON" };
  }
}

export function normalizeDays(days: any): string[] {
  const arr = Array.isArray(days) ? days : typeof days === "string" ? [days] : [];
  return arr
    .map((d) => String(d).trim().toLowerCase().slice(0, 3))
    .filter(Boolean);
}

export function initialDaysObj(): Record<string, boolean> {
  const o: Record<string, boolean> = {};
  for (const d of ALL_DAYS) o[d] = true;
  return o;
}
