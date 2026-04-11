import { clampInt } from "@/shared/lib/filters";

export function getStringParam(sp: URLSearchParams, key: string, fallback = ""): string {
  const raw = sp.get(key);
  if (raw === null) return fallback;
  return raw.trim();
}

export function getIntParam(
  sp: URLSearchParams,
  key: string,
  opts: { min: number; max: number; fallback: number }
): number {
  return clampInt(sp.get(key), opts.min, opts.max, opts.fallback);
}

export function getBoolParam(sp: URLSearchParams, key: string, fallback = false): boolean {
  const raw = (sp.get(key) || "").trim().toLowerCase();
  if (!raw) return fallback;
  return raw === "1" || raw === "true" || raw === "yes";
}

export function setOptionalParam(sp: URLSearchParams, key: string, value: string | number | boolean | null | undefined) {
  if (value === null || value === undefined) {
    sp.delete(key);
    return;
  }
  const v = typeof value === "boolean" ? (value ? "1" : "0") : String(value).trim();
  if (!v) sp.delete(key);
  else sp.set(key, v);
}
