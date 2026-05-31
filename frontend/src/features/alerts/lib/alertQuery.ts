import { DEFAULTS, LS_KEY } from "../constants";
import type { ViewCfg } from "../constants";

export function clampInt(v: any, min: number, max: number, fallback: number): number {
  const n = Number.parseInt(String(v ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

export function safeLoadView(): ViewCfg {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<ViewCfg>;
    return {
      ...DEFAULTS,
      ...parsed,
      severity: String(parsed.severity ?? DEFAULTS.severity),
      status: String((parsed as Partial<ViewCfg>).status ?? DEFAULTS.status),
      rule_id: String(parsed.rule_id ?? "").trim(),
      search: String(parsed.search ?? ""),
      page_size: clampInt(parsed.page_size, 10, 200, DEFAULTS.page_size),
      infinite_scroll: Boolean(parsed.infinite_scroll),
      wrap_json: Boolean(parsed.wrap_json),
      density: parsed.density === "comfortable" ? "comfortable" : "compact",
    };
  } catch {
    return DEFAULTS;
  }
}

export function persistView(v: ViewCfg): void {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(v));
  } catch {
    // no-op
  }
}
