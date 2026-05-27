export function normAgentId(v?: string | null) {
  const s = (v || "").trim();
  return s ? s : "__all";
}

export function parsePositiveInt(v?: string | null): number | null {
  const raw = String(v || "").trim();
  if (!raw) return null;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.trunc(n);
}

export function parseWarnings(extra: Record<string, any> | undefined | null): string[] {
  const e = extra || {};
  const w = e.warnings ?? e.warning;
  if (!w) return [];
  if (Array.isArray(w)) return w.map((x) => String(x)).filter(Boolean);
  if (typeof w === "string") return [w];
  return [JSON.stringify(w)];
}

export function countish(value: any): number | null {
  if (Array.isArray(value)) return value.length;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (value && typeof value === "object") return Object.keys(value).length;
  return null;
}

export function normalizeTagsInput(value: string): string[] {
  const raw = value
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const t of raw) {
    const k = t.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(t);
  }
  return out;
}

export function safeJsonParse(value: string): { ok: true; data: any } | { ok: false; error: string } {
  try {
    const v = JSON.parse(value);
    if (v === null || typeof v !== "object" || Array.isArray(v)) {
      return { ok: false, error: "Config must be a JSON object." };
    }
    return { ok: true, data: v };
  } catch (e: any) {
    return { ok: false, error: e?.message || "Invalid JSON" };
  }
}
