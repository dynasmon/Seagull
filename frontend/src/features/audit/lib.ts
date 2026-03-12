import type { AuditEvent, AuditFilters, AuditSeverity } from "./types";

const CHANGE_RESOURCES = new Set(["alert_rule", "attack_chain_allowlist", "user", "platform_setting"]);

export function toLocalDateTimeInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
}

export function localInputToIso(v: string): string | undefined {
  const s = (v || "").trim();
  if (!s) return undefined;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

export function fmtDateTime(v: string | null | undefined): string {
  if (!v) return "-";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return String(v);
  return d.toLocaleString();
}

export function eventSeverity(ev: AuditEvent): AuditSeverity {
  const out = String(ev.outcome || "").toLowerCase();
  if (out === "failure" || out === "denied" || out === "error") return "critical";

  const action = String(ev.action || "").toLowerCase();
  if (action.includes("delete") || action.includes("revoke") || action.includes("disable")) return "high";
  if (action.includes("update") || action.includes("patch") || action.includes("create")) return "medium";
  if (out === "success" || out === "ok") return "low";
  return "neutral";
}

export function summarizeEvent(ev: AuditEvent): string {
  const bits: string[] = [];
  if (ev.reason) bits.push(`reason: ${ev.reason}`);
  if (ev.error) bits.push(`error: ${ev.error}`);
  if (ev.path) bits.push(`${(ev.method || "").toUpperCase()} ${ev.path}`.trim());

  if (bits.length === 0 && ev.changed_fields?.length) {
    bits.push(`changed: ${ev.changed_fields.slice(0, 4).join(", ")}`);
  }

  if (bits.length === 0) {
    const ctx = ev.context || {};
    const key = Object.keys(ctx)[0];
    if (key) bits.push(`${key}: ${String((ctx as any)[key])}`);
  }

  return bits[0] || "No summary available.";
}

export function eventMatchesText(ev: AuditEvent, query: string, origin: string): boolean {
  const q = (query || "").trim().toLowerCase();
  const o = (origin || "").trim().toLowerCase();

  if (o) {
    const ip = String(ev.ip || "").toLowerCase();
    const ua = String(ev.user_agent || "").toLowerCase();
    if (!ip.includes(o) && !ua.includes(o)) return false;
  }

  if (!q) return true;

  const hay = [
    ev.id,
    ev.operation_id,
    ev.event_type,
    ev.action,
    ev.outcome,
    ev.actor_username,
    ev.resource_type,
    ev.resource_id,
    ev.request_id,
    ev.trace_id,
    ev.ip,
    ev.user_agent,
    ev.method,
    ev.path,
    ev.reason,
    ev.error,
    safeCompactJson(ev.context),
    safeCompactJson(ev.before),
    safeCompactJson(ev.after),
    (ev.changed_fields || []).join(" "),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return hay.includes(q);
}

export function isChangeEvent(ev: AuditEvent): boolean {
  return CHANGE_RESOURCES.has(String(ev.resource_type || ""));
}

export function sortEvents(rows: AuditEvent[], sort: AuditFilters["sort"]): AuditEvent[] {
  const out = [...rows];
  out.sort((a, b) => {
    const da = new Date(a.created_at).getTime() || 0;
    const db = new Date(b.created_at).getTime() || 0;
    return sort === "asc" ? da - db : db - da;
  });
  return out;
}

export function nextUntilCursor(rows: AuditEvent[]): string | undefined {
  if (!rows || rows.length === 0) return undefined;
  const minTs = rows
    .map((r) => new Date(r.created_at).getTime())
    .filter((n) => Number.isFinite(n))
    .reduce((min, n) => Math.min(min, n), Number.POSITIVE_INFINITY);

  if (!Number.isFinite(minTs)) return undefined;
  return new Date(minTs - 1).toISOString();
}

export function canViewAudit(role: string | null | undefined): boolean {
  return String(role || "").toLowerCase() === "admin";
}

function safeCompactJson(v: unknown): string {
  try {
    return JSON.stringify(v ?? {});
  } catch {
    return "";
  }
}
