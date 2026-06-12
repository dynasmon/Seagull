import type { NetEvent } from "@/features/events/types";

// Grafana-like fixed panel heights.
export const H_PANEL_MD = 420;
export const H_PANEL_TALL = 860;

export const DEFAULT_WINDOW_MINUTES = 60;
export const DEFAULT_EVENTS_LIMIT = 500;

export type EventsCfg = {
  event_type: string; // empty = all
  search: string;
  window_minutes: number;
  limit: number;
};

export type DdosConfigDraft = {
  enabled: boolean;
  iface: string;
  window: string;
  eval_every: string;
  cooldown: string;
  sustain_windows: number;
  min_confidence: number;
  min_pps: number;
  min_bps: number;
  max_batch: number;
  backpressure_high_watermark: number;
  backpressure_sample_every: number;
  enable_l7: boolean;
  min_http_rps: number;
  min_tls_hs_rps: number;
};

export const DEFAULT_DDOS_DRAFT: DdosConfigDraft = {
  enabled: true,
  iface: "",
  window: "1s",
  eval_every: "1s",
  cooldown: "30s",
  sustain_windows: 3,
  min_confidence: 70,
  min_pps: 3000,
  min_bps: 500000,
  max_batch: 200,
  backpressure_high_watermark: 160,
  backpressure_sample_every: 4,
  enable_l7: true,
  min_http_rps: 200,
  min_tls_hs_rps: 200
};

export function fmtDateTime(d: Date) {
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

export function safeJsonParse(text: string): { ok: true; value: any } | { ok: false; error: string } {
  try {
    const v = JSON.parse(text);
    return { ok: true, value: v };
  } catch (e: any) {
    return { ok: false, error: e?.message || "Invalid JSON" };
  }
}

export function normalizeTags(raw: string): string[] {
  return raw
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .filter((v, idx, arr) => arr.indexOf(v) === idx);
}

export function isOnline(lastSeenAt?: string | null): boolean {
  if (!lastSeenAt) return false;
  const t = new Date(lastSeenAt).getTime();
  if (!Number.isFinite(t)) return false;
  return Date.now() - t <= 5 * 60_000;
}

export function parseIso(iso?: string | null) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return t;
}

export function fmtLastSeen(lastSeenAt?: string | null) {
  const t = parseIso(lastSeenAt);
  if (!t) return "never";
  const delta = Date.now() - t;
  if (delta < 15_000) return "just now";
  const sec = Math.floor(delta / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

export function fmtMaybeIso(value?: string | null): string {
  if (!value) return "-";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return String(value);
  return fmtDateTime(dt);
}

export function fmtDuration(startIso?: string | null, endIso?: string | null): string {
  if (!startIso) return "-";
  const start = Date.parse(startIso);
  if (!Number.isFinite(start)) return "-";
  const end = endIso ? Date.parse(endIso) : Date.now();
  if (!Number.isFinite(end) || end < start) return "-";
  const sec = Math.floor((end - start) / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  const remSec = sec % 60;
  if (min < 60) return remSec ? `${min}m ${remSec}s` : `${min}m`;
  const hr = Math.floor(min / 60);
  const remMin = min % 60;
  return remMin ? `${hr}h ${remMin}m` : `${hr}h`;
}

export function prettyJson(v: any) {
  try {
    return JSON.stringify(v ?? {}, null, 2);
  } catch {
    return "{}";
  }
}

export function pickTimingKeys(config: Record<string, any>): string[] {
  const keys: string[] = [];
  const re = /(interval|window|timeout|ttl|period|rate|cooldown|delay|heartbeat)/i;
  for (const k of Object.keys(config || {})) {
    const v = (config as any)[k];
    if (!re.test(k)) continue;
    if (typeof v === "number" && Number.isFinite(v)) keys.push(k);
  }
  return keys.sort().slice(0, 12);
}

export function safeNumber(v: any, fallback: number) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return n;
}

export function normalizePositiveInt(v: any, fallback: number, min = 1) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.trunc(n));
}

export function normalizePositiveFloat(v: any, fallback: number, min = 0) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, n);
}

export function getDdosConfig(cfg: Record<string, any>): DdosConfigDraft {
  const dd = ((cfg?.modules || {}) as any)?.ddos || {};
  return {
    enabled: typeof dd.enabled === "boolean" ? dd.enabled : DEFAULT_DDOS_DRAFT.enabled,
    iface: typeof dd.iface === "string" ? dd.iface : DEFAULT_DDOS_DRAFT.iface,
    window: typeof dd.window === "string" ? dd.window : DEFAULT_DDOS_DRAFT.window,
    eval_every: typeof dd.eval_every === "string" ? dd.eval_every : DEFAULT_DDOS_DRAFT.eval_every,
    cooldown: typeof dd.cooldown === "string" ? dd.cooldown : DEFAULT_DDOS_DRAFT.cooldown,
    sustain_windows: normalizePositiveInt(dd.sustain_windows, DEFAULT_DDOS_DRAFT.sustain_windows),
    min_confidence: normalizePositiveInt(dd.min_confidence, DEFAULT_DDOS_DRAFT.min_confidence),
    min_pps: normalizePositiveFloat(dd.min_pps, DEFAULT_DDOS_DRAFT.min_pps),
    min_bps: normalizePositiveFloat(dd.min_bps, DEFAULT_DDOS_DRAFT.min_bps),
    max_batch: normalizePositiveInt(dd.max_batch, DEFAULT_DDOS_DRAFT.max_batch),
    backpressure_high_watermark: normalizePositiveInt(
      dd.backpressure_high_watermark,
      DEFAULT_DDOS_DRAFT.backpressure_high_watermark
    ),
    backpressure_sample_every: normalizePositiveInt(
      dd.backpressure_sample_every,
      DEFAULT_DDOS_DRAFT.backpressure_sample_every
    ),
    enable_l7: typeof dd.enable_l7 === "boolean" ? dd.enable_l7 : DEFAULT_DDOS_DRAFT.enable_l7,
    min_http_rps: normalizePositiveFloat(dd.min_http_rps, DEFAULT_DDOS_DRAFT.min_http_rps),
    min_tls_hs_rps: normalizePositiveFloat(dd.min_tls_hs_rps, DEFAULT_DDOS_DRAFT.min_tls_hs_rps)
  };
}

export function withDdosConfig(baseCfg: Record<string, any>, dd: DdosConfigDraft): Record<string, any> {
  const next = { ...(baseCfg || {}) };
  const modules = { ...((next.modules as Record<string, any>) || {}) };
  modules.ddos = {
    enabled: !!dd.enabled,
    iface: (dd.iface || "").trim(),
    window: (dd.window || DEFAULT_DDOS_DRAFT.window).trim(),
    eval_every: (dd.eval_every || DEFAULT_DDOS_DRAFT.eval_every).trim(),
    cooldown: (dd.cooldown || DEFAULT_DDOS_DRAFT.cooldown).trim(),
    sustain_windows: normalizePositiveInt(dd.sustain_windows, DEFAULT_DDOS_DRAFT.sustain_windows),
    min_confidence: normalizePositiveInt(dd.min_confidence, DEFAULT_DDOS_DRAFT.min_confidence),
    min_pps: normalizePositiveFloat(dd.min_pps, DEFAULT_DDOS_DRAFT.min_pps),
    min_bps: normalizePositiveFloat(dd.min_bps, DEFAULT_DDOS_DRAFT.min_bps),
    max_batch: normalizePositiveInt(dd.max_batch, DEFAULT_DDOS_DRAFT.max_batch),
    backpressure_high_watermark: normalizePositiveInt(
      dd.backpressure_high_watermark,
      DEFAULT_DDOS_DRAFT.backpressure_high_watermark
    ),
    backpressure_sample_every: normalizePositiveInt(
      dd.backpressure_sample_every,
      DEFAULT_DDOS_DRAFT.backpressure_sample_every
    ),
    enable_l7: !!dd.enable_l7,
    min_http_rps: normalizePositiveFloat(dd.min_http_rps, DEFAULT_DDOS_DRAFT.min_http_rps),
    min_tls_hs_rps: normalizePositiveFloat(dd.min_tls_hs_rps, DEFAULT_DDOS_DRAFT.min_tls_hs_rps)
  };
  next.modules = modules;
  return next;
}

export function eventMatchesSearch(e: NetEvent, query: string) {
  const q = (query || "").trim().toLowerCase();
  if (!q) return true;

  const parts: string[] = [];
  parts.push(e.event_type || "");
  parts.push(e.agent_id || "");
  parts.push(e.src_ip || "");
  parts.push(e.dst_ip || "");
  if (typeof e.dst_port === "number") parts.push(String(e.dst_port));
  if (typeof (e as any).src_port === "number") parts.push(String((e as any).src_port));

  try {
    parts.push(JSON.stringify((e as any).extra || {}));
  } catch {
    // no-op
  }

  const hay = parts.join(" ").toLowerCase();
  return hay.includes(q);
}

export function buildTopCounts(values: string[], limit: number) {
  const map = new Map<string, number>();
  for (const v of values) {
    const k = (v || "").trim();
    if (!k) continue;
    map.set(k, (map.get(k) || 0) + 1);
  }
  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, Math.max(1, limit))
    .map(([key, count]) => ({ key, count }));
}
