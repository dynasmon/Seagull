import type { CSSProperties, ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import EmptyState from "@/shared/components/EmptyState";
import Drawer from "@/shared/components/Drawer";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";
import { getErrorMessage } from "@/shared/lib/errors";

import { useAgentsCatalog } from "@/app/providers";
import { useAuth } from "@/features/auth/context";

import { getOverview } from "@/features/overview/api";
import { SimpleTimeSeries } from "@/features/overview/components/Charts";
import type { OverviewSnapshot } from "@/features/overview/types";

import { getRecentEvents } from "@/features/events/api";
import EventsTable from "@/features/events/components/EventsTable";
import EventDetailsPanel from "@/features/events/components/EventDetailsPanel";
import type { NetEvent } from "@/features/events/types";

import DdosDeepDive from "@/features/events/views/ddos/DdosDeepDive";

import { createResponseAction, disableAgent, enableAgent, getAgent, setAgentConfig, updateAgent } from "./api";
import type { AgentDetail, AgentPublic, AgentUpdateIn, ResponseActionOut } from "./types";

// Grafana-like fixed panel heights.
const H_PANEL_MD = 420;
const H_PANEL_TALL = 860;

const DEFAULT_WINDOW_MINUTES = 60;
const DEFAULT_EVENTS_LIMIT = 500;
const DEFAULT_POLL_MS = 5000;
const RESPONSE_ACTION_TYPES = [
  {
    key: "collect_triage_bundle",
    label: "Collect triage bundle",
    hint: "Collect host and runtime triage data from the selected agent.",
    effect: "The agent receives an operator-initiated collection request and starts execution when it polls pending actions.",
    expectedResult: "Execution status and result payload are reported back through the response action result channel.",
    auditNote: "This operation is auditable as an administrative response action request."
  }
] as const;

type EventsCfg = {
  event_type: string; // empty = all
  search: string;
  window_minutes: number;
  limit: number;
};

type DdosConfigDraft = {
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

const DEFAULT_DDOS_DRAFT: DdosConfigDraft = {
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

function fmtDateTime(d: Date) {
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function toIsoOrNullFromLocalInput(value: string): string | null {
  const raw = (value || "").trim();
  if (!raw) return null;
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return null;
  return dt.toISOString();
}

function toLocalDateTimeInput(d: Date): string {
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
}

function safeJsonParse(text: string): { ok: true; value: any } | { ok: false; error: string } {
  try {
    const v = JSON.parse(text);
    return { ok: true, value: v };
  } catch (e: any) {
    return { ok: false, error: e?.message || "Invalid JSON" };
  }
}

function normalizeTags(raw: string): string[] {
  return raw
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .filter((v, idx, arr) => arr.indexOf(v) === idx);
}

function isOnline(lastSeenAt?: string | null): boolean {
  if (!lastSeenAt) return false;
  const t = new Date(lastSeenAt).getTime();
  if (!Number.isFinite(t)) return false;
  return Date.now() - t <= 5 * 60_000;
}

function parseIso(iso?: string | null) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return t;
}

function fmtLastSeen(lastSeenAt?: string | null) {
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

function fmtMaybeIso(value?: string | null): string {
  if (!value) return "-";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return String(value);
  return fmtDateTime(dt);
}

function Dot({ state }: { state: "online" | "offline" | "disabled" }) {
  const klass =
    state === "disabled"
      ? "bg-muted-foreground/60"
      : state === "online"
        ? "bg-emerald-400/90"
        : "bg-amber-400/90";
  return <span className={cx("h-2.5 w-2.5 rounded-full", klass)} />;
}

function Switch({
  checked,
  onChange,
  disabled,
  label
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  label: string;
}) {
  return (
    <div className={cx("flex items-center justify-between gap-3", disabled && "opacity-60")}>
      <span className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
        {label}
      </span>

      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cx(
          "relative inline-flex h-6 w-11 items-center rounded-full border border-border/60",
          "bg-background/40 transition-colors",
          "focus:outline-none focus:ring-2 focus:ring-primary/30",
          "disabled:cursor-not-allowed",
          checked && "bg-primary/15"
        )}
      >
        <span
          className={cx(
            "inline-block h-5 w-5 transform rounded-full bg-foreground/80",
            "transition-transform",
            checked ? "translate-x-5" : "translate-x-1"
          )}
        />
      </button>
    </div>
  );
}

function Panel({
  title,
  right,
  children,
  scrollY = false,
  className = "",
  style
}: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  scrollY?: boolean;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div
      className={cx(
        "rounded-lg border border-border/60 bg-background/60 backdrop-blur-sm flex flex-col shadow-sm overflow-hidden min-w-0",
        className
      )}
      style={style}
    >
      <div className="flex items-center justify-between border-b border-border/60 bg-muted/10 px-4 py-3 shrink-0">
        <h3 className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-primary/90">{title}</h3>
        {right && <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">{right}</div>}
      </div>
      <div className={cx("p-4 flex-1 min-h-0 min-w-0", scrollY ? "overflow-y-auto" : "overflow-hidden")}>{children}</div>
    </div>
  );
}

function StatTile({
  label,
  value,
  hint,
  tone = "default"
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "good" | "warn";
}) {
  const raw = String(value);
  const isLong = raw.length > 18;
  const isMid = raw.length > 12;
  const valueSize = isLong ? "text-sm" : isMid ? "text-lg" : "text-3xl";

  const valueClass = tone === "warn" ? "text-red-400" : tone === "good" ? "text-green-400" : "text-foreground";

  return (
    <div className="rounded-lg border border-border/60 bg-background/50 backdrop-blur-sm px-4 py-4 shadow-sm min-w-0">
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1 font-mono">{label}</div>
      <div className={cx("font-mono font-bold tracking-tight leading-none truncate", valueSize, valueClass)} title={raw}>
        {raw}
      </div>
      {hint && <div className="text-[10px] text-muted-foreground font-mono opacity-70 mt-2">{hint}</div>}
    </div>
  );
}

function inputClassName(disabled?: boolean) {
  return cx(
    "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-sm text-foreground outline-none",
    "placeholder:text-muted-foreground/60",
    "focus:ring-2 focus:ring-primary/30",
    disabled && "opacity-60 cursor-not-allowed"
  );
}

function textAreaClassName(disabled?: boolean) {
  return cx(
    "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-sm text-foreground outline-none",
    "placeholder:text-muted-foreground/60",
    "focus:ring-2 focus:ring-primary/30",
    "font-mono text-[12px]",
    disabled && "opacity-60 cursor-not-allowed"
  );
}

function FieldLabel({ children }: { children: ReactNode }) {
  return (
    <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
      {children}
    </div>
  );
}

function prettyJson(v: any) {
  try {
    return JSON.stringify(v ?? {}, null, 2);
  } catch {
    return "{}";
  }
}

function pickTimingKeys(config: Record<string, any>): string[] {
  const keys: string[] = [];
  const re = /(interval|window|timeout|ttl|period|rate|cooldown|delay|heartbeat)/i;
  for (const k of Object.keys(config || {})) {
    const v = (config as any)[k];
    if (!re.test(k)) continue;
    if (typeof v === "number" && Number.isFinite(v)) keys.push(k);
  }
  return keys.sort().slice(0, 12);
}

function safeNumber(v: any, fallback: number) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return n;
}

function normalizePositiveInt(v: any, fallback: number, min = 1) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.trunc(n));
}

function normalizePositiveFloat(v: any, fallback: number, min = 0) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, n);
}

function getDdosConfig(cfg: Record<string, any>): DdosConfigDraft {
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

function withDdosConfig(baseCfg: Record<string, any>, dd: DdosConfigDraft): Record<string, any> {
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

function eventMatchesSearch(e: NetEvent, query: string) {
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

function buildTopCounts(values: string[], limit: number) {
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

export default function AgentsPage() {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const { agents, selectedAgentId, setSelectedAgentId, refresh } = useAgentsCatalog();
  const [searchParams, setSearchParams] = useSearchParams();

  const [agentQuery, setAgentQuery] = useState("");
  const [configOpen, setConfigOpen] = useState(false);
  const [responseActionOpen, setResponseActionOpen] = useState(false);

  const agentsSorted = useMemo(() => {
    return [...(agents || [])].sort((a, b) => {
      const ad = a.display_name || a.agent_id;
      const bd = b.display_name || b.agent_id;
      return ad.localeCompare(bd);
    });
  }, [agents]);

  const agentsFiltered = useMemo(() => {
    const q = agentQuery.trim().toLowerCase();
    if (!q) return agentsSorted;
    return agentsSorted.filter((a) => {
      const parts = [a.display_name, a.agent_id, ...(a.tags || [])].filter(Boolean).join(" ").toLowerCase();
      return parts.includes(q);
    });
  }, [agentsSorted, agentQuery]);

  const selectAgent = (agentId: string) => {
    const next = new URLSearchParams(searchParams);
    if (agentId) next.set("agent_id", agentId);
    else next.delete("agent_id");
    setSearchParams(next, { replace: true });
    setSelectedAgentId(agentId);
    setConfigOpen(false);
    setResponseActionOpen(false);
  };

  const resetResponseActionForm = useCallback(
    (agentId: string) => {
      setResponseActionAgentId(agentId);
      setResponseActionType(RESPONSE_ACTION_TYPES[0].key);
      setResponseActionPayloadText("{}");
      setResponseActionAdvancedOpen(false);
      setResponseActionExpiresAt("");
      setResponseActionError(null);
      setResponseActionCreated(null);
      setResponseActionBusy(false);
    },
    []
  );

  const [agent, setAgent] = useState<AgentDetail | null>(null);
  const [agentError, setAgentError] = useState<string | null>(null);

  const [snapshot, setSnapshot] = useState<OverviewSnapshot | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<NetEvent | null>(null);

  const [snapshotError, setSnapshotError] = useState<string | null>(null);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [eventsLoading, setEventsLoading] = useState(false);

  const [autoRefresh, setAutoRefresh] = useState(true);
  const [pollMs, setPollMs] = useState(DEFAULT_POLL_MS);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

  const [eventsCfg, setEventsCfg] = useState<EventsCfg>(() => ({
    event_type: "",
    search: "",
    window_minutes: DEFAULT_WINDOW_MINUTES,
    limit: DEFAULT_EVENTS_LIMIT
  }));

  const eventsCfgRef = useRef<EventsCfg>(eventsCfg);
  useEffect(() => {
    eventsCfgRef.current = eventsCfg;
  }, [eventsCfg]);

  const [draftName, setDraftName] = useState("");
  const [draftDesc, setDraftDesc] = useState("");
  const [draftTags, setDraftTags] = useState("");
  const [draftMetaText, setDraftMetaText] = useState("{}");

  const [configText, setConfigText] = useState("{}");
  const [configObj, setConfigObj] = useState<Record<string, any>>({});
  const [configParseError, setConfigParseError] = useState<string | null>(null);
  const [ddosDraft, setDdosDraft] = useState<DdosConfigDraft>(DEFAULT_DDOS_DRAFT);

  const [saveBusy, setSaveBusy] = useState(false);
  const [configBusy, setConfigBusy] = useState(false);
  const [toggleBusy, setToggleBusy] = useState(false);
  const [responseActionBusy, setResponseActionBusy] = useState(false);

  const [responseActionAgentId, setResponseActionAgentId] = useState("");
  const [responseActionType, setResponseActionType] = useState<string>(RESPONSE_ACTION_TYPES[0].key);
  const [responseActionPayloadText, setResponseActionPayloadText] = useState("{}");
  const [responseActionAdvancedOpen, setResponseActionAdvancedOpen] = useState(false);
  const [responseActionExpiresAt, setResponseActionExpiresAt] = useState("");
  const [responseActionError, setResponseActionError] = useState<string | null>(null);
  const [responseActionCreated, setResponseActionCreated] = useState<ResponseActionOut | null>(null);
  const [recentResponseActions, setRecentResponseActions] = useState<ResponseActionOut[]>([]);

  const inFlightSnapshot = useRef(false);
  const inFlightEvents = useRef(false);

  const lastUrlId = useRef<string | null>(null);

  useEffect(() => {
    const q = (searchParams.get("agent_id") || "").trim();

    // Apply only when the URL actually changes.
    if (lastUrlId.current === q) return;
    lastUrlId.current = q;

    setSelectedAgentId(q);
  }, [searchParams, setSelectedAgentId]);

  const selectedAgentRow = useMemo<AgentPublic | null>(() => {
    if (!selectedAgentId) return null;
    return agents.find((a) => a.agent_id === selectedAgentId) || null;
  }, [agents, selectedAgentId]);

  useEffect(() => {
    if (!responseActionOpen) return;
    resetResponseActionForm(selectedAgentId || "");
  }, [responseActionOpen, selectedAgentId, resetResponseActionForm]);

  const loadAgent = useCallback(async (agentId: string) => {
    try {
      const a = await getAgent(agentId);
      setAgent(a);
      setAgentError(null);

      setDraftName(a.display_name || "");
      setDraftDesc(a.description || "");
      setDraftTags((a.tags || []).join(", "));
      setDraftMetaText(prettyJson(a.metadata || {}));

      setConfigObj(a.config || {});
      setConfigText(prettyJson(a.config || {}));
      setDdosDraft(getDdosConfig(a.config || {}));
      setConfigParseError(null);
    } catch (e: any) {
      setAgentError(getErrorMessage(e, "Failed to load agent details"));
      setAgent(null);
    }
  }, []);

  const loadSnapshot = useCallback(async (agentId: string, cfg: EventsCfg) => {
    if (inFlightSnapshot.current) return;
    inFlightSnapshot.current = true;

    try {
      const win = Math.max(1, safeNumber(cfg.window_minutes, DEFAULT_WINDOW_MINUTES));
      const snap = await getOverview({ window_minutes: win, agent_id: agentId });
      setSnapshot(snap);
      setSnapshotError(null);
      setLastUpdatedAt(new Date());
    } catch (e: any) {
      setSnapshotError(getErrorMessage(e, "Failed to load overview"));
    } finally {
      inFlightSnapshot.current = false;
    }
  }, []);

  const loadEvents = useCallback(async (agentId: string, cfg: EventsCfg) => {
    if (inFlightEvents.current) return;
    inFlightEvents.current = true;

    setEventsLoading(true);
    try {
      const lim = Math.max(50, Math.min(5000, safeNumber(cfg.limit, DEFAULT_EVENTS_LIMIT)));
      const ev = await getRecentEvents({ limit: lim, agent_id: agentId });

      setEvents(ev);
      setSelectedEvent((prev) => {
        if (!prev) return ev[0] || null;
        const still = ev.find((x) => x.id === prev.id);
        return still || ev[0] || null;
      });

      setEventsError(null);
      setLastUpdatedAt(new Date());
    } catch (e: any) {
      setEventsError(getErrorMessage(e, "Failed to load events"));
      setEvents([]);
      setSelectedEvent(null);
    } finally {
      setEventsLoading(false);
      inFlightEvents.current = false;
    }
  }, []);

  useEffect(() => {
    if (!selectedAgentId) {
      setAgent(null);
      setSnapshot(null);
      setEvents([]);
      setSelectedEvent(null);
      setSnapshotError(null);
      setEventsError(null);
      return;
    }

    setSelectedEvent(null);
    loadAgent(selectedAgentId);

    const cfg = eventsCfgRef.current;
    loadSnapshot(selectedAgentId, cfg);
    loadEvents(selectedAgentId, cfg);
    refresh();
  }, [selectedAgentId, loadAgent, loadSnapshot, loadEvents, refresh]);

  useEffect(() => {
    if (!selectedAgentId) return;

    const t = window.setTimeout(() => {
      const cfg = eventsCfgRef.current;
      loadSnapshot(selectedAgentId, cfg);
      loadEvents(selectedAgentId, cfg);
    }, 300);

    return () => window.clearTimeout(t);
  }, [selectedAgentId, eventsCfg.window_minutes, eventsCfg.limit, loadSnapshot, loadEvents]);

  useEffect(() => {
    if (!selectedAgentId) return;
    if (!autoRefresh) return;

    const t = window.setInterval(() => {
      const cfg = eventsCfgRef.current;
      loadSnapshot(selectedAgentId, cfg);
      loadEvents(selectedAgentId, cfg);
      refresh();
    }, Math.max(2000, pollMs));

    return () => window.clearInterval(t);
  }, [selectedAgentId, autoRefresh, pollMs, loadSnapshot, loadEvents, refresh]);

  const timingKeys = useMemo(() => pickTimingKeys(configObj), [configObj]);

  const dirty = useMemo(() => {
    if (!agent) return false;
    const desiredTags = normalizeTags(draftTags);
    const currentTags = (agent.tags || []).slice().sort();
    const desiredSorted = desiredTags.slice().sort();

    const meta = safeJsonParse(draftMetaText);
    const metaObj = meta.ok && typeof meta.value === "object" && meta.value ? meta.value : null;

    const nameChanged = (agent.display_name || "") !== draftName;
    const descChanged = (agent.description || "") !== draftDesc;
    const tagsChanged = JSON.stringify(currentTags) !== JSON.stringify(desiredSorted);
    const metaChanged = metaObj ? JSON.stringify(agent.metadata || {}) !== JSON.stringify(metaObj) : false;

    return nameChanged || descChanged || tagsChanged || metaChanged;
  }, [agent, draftName, draftDesc, draftTags, draftMetaText]);

  const canSaveAgent = useMemo(() => {
    if (!agent) return false;
    const meta = safeJsonParse(draftMetaText);
    if (!meta.ok) return false;
    if (meta.ok && (meta.value === null || typeof meta.value !== "object" || Array.isArray(meta.value))) return false;
    return dirty && !saveBusy;
  }, [agent, draftMetaText, dirty, saveBusy]);

  const onSaveAgent = async () => {
    if (!agent) return;

    const meta = safeJsonParse(draftMetaText);
    if (!meta.ok) {
      setAgentError(`Metadata JSON: ${meta.error}`);
      return;
    }
    if (meta.value === null || typeof meta.value !== "object" || Array.isArray(meta.value)) {
      setAgentError("Metadata must be a JSON object");
      return;
    }

    const patch: AgentUpdateIn = {
      display_name: draftName.trim() || null,
      description: draftDesc.trim() || null,
      tags: normalizeTags(draftTags),
      metadata: meta.value
    };

    setSaveBusy(true);
    try {
      const updated = await updateAgent(agent.agent_id, patch);
      setAgent(updated);
      setAgentError(null);
      refresh();
    } catch (e: any) {
      setAgentError(getErrorMessage(e, "Failed to update agent"));
    } finally {
      setSaveBusy(false);
    }
  };

  const onToggleRevoked = async () => {
    if (!agent) return;
    setToggleBusy(true);
    try {
      const updated = agent.is_revoked ? await enableAgent(agent.agent_id) : await disableAgent(agent.agent_id);
      setAgent(updated);
      setAgentError(null);
      refresh();
    } catch (e: any) {
      setAgentError(getErrorMessage(e, "Failed to update agent state"));
    } finally {
      setToggleBusy(false);
    }
  };

  const pushAgentConfig = async (nextConfig: Record<string, any>) => {
    if (!agent) return;
    setConfigBusy(true);
    try {
      const updated = await setAgentConfig(agent.agent_id, nextConfig);
      setAgent(updated);
      setConfigObj(updated.config || {});
      setConfigText(prettyJson(updated.config || {}));
      setDdosDraft(getDdosConfig(updated.config || {}));
      setConfigParseError(null);
      setAgentError(null);
    } catch (e: any) {
      setAgentError(getErrorMessage(e, "Failed to push config"));
    } finally {
      setConfigBusy(false);
    }
  };

  const onApplyConfig = async () => {
    if (!agent) return;

    const parsed = safeJsonParse(configText);
    if (!parsed.ok) {
      setConfigParseError(parsed.error);
      return;
    }
    if (parsed.value === null || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
      setConfigParseError("Config must be a JSON object");
      return;
    }

    await pushAgentConfig(parsed.value as Record<string, any>);
  };

  const onApplyDdosConfig = async () => {
    if (!agent) return;
    const next = withDdosConfig(configObj || {}, ddosDraft);
    setConfigObj(next);
    setConfigText(prettyJson(next));
    setConfigParseError(null);
    await pushAgentConfig(next);
  };

  const onConfigTextChange = (v: string) => {
    setConfigText(v);
    const parsed = safeJsonParse(v);
    if (!parsed.ok) {
      setConfigParseError(parsed.error);
      return;
    }
    if (parsed.value === null || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
      setConfigParseError("Config must be a JSON object");
      return;
    }
    setConfigParseError(null);
    const next = parsed.value as Record<string, any>;
    setConfigObj(next);
    setDdosDraft(getDdosConfig(next));
  };

  const onUpdateTiming = (key: string, value: number) => {
    const next = { ...(configObj || {}) };
    next[key] = value;
    setConfigObj(next);
    setConfigText(prettyJson(next));
    setDdosDraft(getDdosConfig(next));
    setConfigParseError(null);
  };

  const responseActionDefinition = useMemo(() => {
    return RESPONSE_ACTION_TYPES.find((x) => x.key === responseActionType) || RESPONSE_ACTION_TYPES[0];
  }, [responseActionType]);

  const responseActionAgentRow = useMemo(() => {
    return agents.find((a) => a.agent_id === responseActionAgentId) || null;
  }, [agents, responseActionAgentId]);

  const responseActionPayload = useMemo(() => {
    if (!responseActionAdvancedOpen) return { error: null, payload: {} as Record<string, any> };
    const parsed = safeJsonParse(responseActionPayloadText);
    if (!parsed.ok) return { error: parsed.error, payload: null as Record<string, any> | null };
    if (parsed.value === null || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
      return { error: "Payload must be a JSON object", payload: null as Record<string, any> | null };
    }
    return { error: null, payload: parsed.value as Record<string, any> };
  }, [responseActionAdvancedOpen, responseActionPayloadText]);

  const responseActionPayloadError = responseActionPayload.error;

  const responseActionExpiresIso = useMemo(() => {
    return toIsoOrNullFromLocalInput(responseActionExpiresAt);
  }, [responseActionExpiresAt]);

  const responseActionExpirationInvalid = useMemo(() => {
    return Boolean(responseActionExpiresAt.trim()) && !responseActionExpiresIso;
  }, [responseActionExpiresAt, responseActionExpiresIso]);

  const responseActionExpirationInPast = useMemo(() => {
    if (!responseActionExpiresIso) return false;
    return Date.parse(responseActionExpiresIso) <= Date.now();
  }, [responseActionExpiresIso]);

  const responseActionRecentForAgent = useMemo(() => {
    const id = responseActionAgentId.trim();
    if (!id) return [];
    return recentResponseActions.filter((x) => x.agent_id === id).slice(0, 5);
  }, [recentResponseActions, responseActionAgentId]);

  const responseActionAgentStatus = useMemo(() => {
    if (!responseActionAgentRow) return "Unknown";
    if (responseActionAgentRow.is_revoked) return "Disabled";
    return isOnline(responseActionAgentRow.last_seen_at) ? "Online" : "Offline";
  }, [responseActionAgentRow]);

  const responseActionExpiresLabel = useMemo(() => {
    if (!responseActionExpiresIso) return "Not set";
    const dt = new Date(responseActionExpiresIso);
    if (Number.isNaN(dt.getTime())) return "Invalid";
    return dt.toLocaleString();
  }, [responseActionExpiresIso]);

  const canSubmitResponseAction = useMemo(() => {
    if (!isAdmin) return false;
    if (responseActionBusy) return false;
    if (!responseActionAgentId.trim()) return false;
    if (!responseActionType.trim()) return false;
    if (responseActionPayloadError) return false;
    if (responseActionExpirationInvalid || responseActionExpirationInPast) return false;
    return true;
  }, [
    isAdmin,
    responseActionBusy,
    responseActionAgentId,
    responseActionType,
    responseActionPayloadError,
    responseActionExpirationInvalid,
    responseActionExpirationInPast
  ]);

  const openResponseActionDrawer = () => {
    resetResponseActionForm(selectedAgentId || "");
    setResponseActionOpen(true);
  };

  const closeResponseActionDrawer = () => {
    setResponseActionOpen(false);
    resetResponseActionForm(selectedAgentId || "");
  };

  const setResponseActionExpiryOffset = (minutes: number) => {
    const dt = new Date(Date.now() + minutes * 60_000);
    setResponseActionExpiresAt(toLocalDateTimeInput(dt));
    setResponseActionError(null);
    setResponseActionCreated(null);
  };

  const onSubmitResponseAction = async () => {
    const agentId = responseActionAgentId.trim();
    if (!agentId) {
      setResponseActionError("Agent is required");
      return;
    }
    if (!responseActionType.trim()) {
      setResponseActionError("Action type is required");
      return;
    }
    if (responseActionPayload.error || !responseActionPayload.payload) {
      setResponseActionError(responseActionPayload.error || "Payload must be a JSON object");
      return;
    }

    if (responseActionExpirationInvalid) {
      setResponseActionError("Expiration must be a valid date and time");
      return;
    }
    if (responseActionExpirationInPast) {
      setResponseActionError("Expiration must be in the future");
      return;
    }

    setResponseActionBusy(true);
    setResponseActionError(null);
    setResponseActionCreated(null);
    try {
      const out = await createResponseAction({
        action_type: responseActionType.trim(),
        agent_id: agentId,
        payload: responseActionPayload.payload,
        expires_at: responseActionExpiresIso || undefined
      });
      setResponseActionCreated(out);
      setRecentResponseActions((prev) => [out, ...prev.filter((x) => x.id !== out.id)].slice(0, 12));
      refresh();
    } catch (e: any) {
      setResponseActionError(getErrorMessage(e, "Failed to create response action"));
    } finally {
      setResponseActionBusy(false);
    }
  };

  const topStats = useMemo(() => {
    const last = selectedAgentRow?.last_seen_at ? new Date(selectedAgentRow.last_seen_at) : null;
    const online = isOnline(selectedAgentRow?.last_seen_at);
    const status = selectedAgentRow?.is_revoked ? "Disabled" : online ? "Online" : "Offline";
    return {
      status,
      online,
      lastSeen: last ? fmtDateTime(last) : "-"
    };
  }, [selectedAgentRow]);

  const charts = useMemo(() => {
    if (!snapshot) {
      return {
        traffic: null as null | { series: string[]; data: Array<Record<string, any>> },
        ssh: null as null | { series: string[]; data: Array<Record<string, any>> },
        ddos: null as null | { series: string[]; data: Array<Record<string, any>> },
        sev: null as null | { series: string[]; data: Array<Record<string, any>> }
      };
    }
    return {
      traffic: snapshot.traffic,
      ssh: snapshot.ssh_failures,
      ddos: snapshot.ddos,
      sev: snapshot.alert_severity
    };
  }, [snapshot]);

  const eventsRate = useMemo(() => {
    if (!snapshot) return "-";
    return String(snapshot.kpis.events_5m);
  }, [snapshot]);

  const alerts60m = useMemo(() => {
    if (!snapshot) return "-";
    return String(snapshot.kpis.alerts_60m);
  }, [snapshot]);

  const lastEventAge = useMemo(() => {
    if (!snapshot) return "-";
    const v = snapshot.kpis.last_event_age_m;
    if (v === null || v === undefined) return "-";
    if (typeof v !== "number" || !Number.isFinite(v)) return "-";
    return `${Math.round(v)}m`;
  }, [snapshot]);


  const windowedEvents = useMemo(() => {
    const mins = Math.max(1, safeNumber(eventsCfg.window_minutes, DEFAULT_WINDOW_MINUTES));
    const cutoff = Date.now() - mins * 60_000;

    return (events || []).filter((e) => {
      const t = new Date(e.timestamp).getTime();
      if (!Number.isFinite(t)) return true;
      return t >= cutoff;
    });
  }, [events, eventsCfg.window_minutes]);

  const availableTypes = useMemo(() => {
    const set = new Set<string>();
    for (const e of windowedEvents) set.add(e.event_type);
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [windowedEvents]);

  const explorerBase = useMemo(() => {
    const q = (eventsCfg.search || "").trim();
    if (!q) return windowedEvents;
    return windowedEvents.filter((e) => eventMatchesSearch(e, q));
  }, [windowedEvents, eventsCfg.search]);

  const topTypes = useMemo(() => {
    return buildTopCounts(explorerBase.map((e) => e.event_type), 12);
  }, [explorerBase]);

  const filteredEvents = useMemo(() => {
    const type = (eventsCfg.event_type || "").trim();
    const q = (eventsCfg.search || "").trim();
    return windowedEvents.filter((e) => {
      if (type && e.event_type !== type) return false;
      if (q && !eventMatchesSearch(e, q)) return false;
      return true;
    });
  }, [windowedEvents, eventsCfg.event_type, eventsCfg.search]);

  const ddosMode = (eventsCfg.event_type || "").trim() === "dos_attack";
  const ddosEvents = useMemo(() => filteredEvents.filter((e) => e.event_type === "dos_attack"), [filteredEvents]);

  // --- RENDER ---

  if (!selectedAgentId) {
    return (
      <div className="space-y-6">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-1">
            <h1 className="text-xl font-semibold">Agents</h1>
            <div className="text-sm text-muted-foreground">Select an agent to inspect telemetry and configure settings.</div>
          </div>

          <button
            type="button"
            onClick={refresh}
            className={cx(
              "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
              "hover:bg-primary/5"
            )}
          >
            Refresh catalog
          </button>
        </div>

        <div className="grid gap-6 xl:grid-cols-12 min-w-0">
          <div className="xl:col-span-4 min-w-0">
            <Panel title="Agents" right={`${agentsFiltered.length}/${agentsSorted.length}`} scrollY style={{ height: H_PANEL_TALL }}>
              <div className="space-y-3">
                <input
                  value={agentQuery}
                  onChange={(e) => setAgentQuery(e.target.value)}
                  placeholder="Search agents (name, id, tags)…"
                  className={inputClassName(false)}
                />

                <div className="space-y-2">
                  {agentsFiltered.length === 0 ? (
                    <EmptyState title="No matches" hint="Try a different search query." />
                  ) : (
                    agentsFiltered.map((a) => {
                      const disabled = Boolean(a.is_revoked);
                      const online = !disabled && isOnline(a.last_seen_at);
                      const state = disabled ? "disabled" : online ? "online" : "offline";
                      return (
                        <button
                          key={a.agent_id}
                          type="button"
                          onClick={() => selectAgent(a.agent_id)}
                          className={cx(
                            "w-full text-left rounded-md border border-border/60 bg-background/20 px-3 py-2",
                            "hover:bg-muted/10",
                            "focus:outline-none focus:ring-2 focus:ring-primary/30"
                          )}
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-3 min-w-0">
                              <Dot state={state} />
                              <div className="min-w-0">
                                <div className="text-sm font-mono truncate">{a.display_name || a.agent_id}</div>
                                <div className="text-[10px] font-mono text-muted-foreground truncate">{a.agent_id}</div>
                              </div>
                            </div>
                            <div className="text-[10px] font-mono text-muted-foreground whitespace-nowrap">
                              {fmtLastSeen(a.last_seen_at)}
                            </div>
                          </div>
                          {a.tags && a.tags.length ? (
                            <div className="mt-2 flex flex-wrap gap-1">
                              {a.tags.slice(0, 5).map((t) => (
                                <span
                                  key={t}
                                  className="rounded border border-border/60 bg-background/30 px-2 py-0.5 text-[10px] font-mono text-muted-foreground"
                                >
                                  {t}
                                </span>
                              ))}
                              {a.tags.length > 5 ? (
                                <span className="rounded border border-border/60 bg-background/30 px-2 py-0.5 text-[10px] font-mono text-muted-foreground">
                                  +{a.tags.length - 5}
                                </span>
                              ) : null}
                            </div>
                          ) : null}
                        </button>
                      );
                    })
                  )}
                </div>
              </div>
            </Panel>
          </div>

          <div className="xl:col-span-8 min-w-0">
            <div className="min-h-[60vh] flex flex-col items-center justify-center border border-dashed border-border/60 bg-background/20 rounded-lg">
              <EmptyState
                title="Select an agent"
                hint="Pick an agent from the list on the left. You can configure it using the drawer once selected."
              />
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <span className="text-muted-foreground font-normal">Agent /</span>
            <span>{agent?.display_name || selectedAgentId}</span>
          </h1>
          <div className="text-sm text-muted-foreground font-mono text-[11px] opacity-70">ID: {selectedAgentId}</div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => {
              const cfg = eventsCfgRef.current;
              loadAgent(selectedAgentId);
              loadSnapshot(selectedAgentId, cfg);
              loadEvents(selectedAgentId, cfg);
              refresh();
            }}
            className={cx(
              "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
              "hover:bg-primary/5"
            )}
          >
            Refresh
          </button>

          <div className="border border-border/60 bg-background/40 px-3 py-2 flex items-center gap-3">
            <Switch checked={autoRefresh} onChange={setAutoRefresh} label="Auto refresh" />
          </div>

          <select
            className={cx(
              "border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
              "focus:ring-2 focus:ring-primary/30"
            )}
            value={String(pollMs)}
            onChange={(e) => setPollMs(Number(e.target.value))}
            disabled={!autoRefresh}
          >
            <option value={2000}>2s</option>
            <option value={5000}>5s</option>
            <option value={10000}>10s</option>
            <option value={30000}>30s</option>
          </select>

          {lastUpdatedAt && (
            <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">
              Updated {fmtDateTime(lastUpdatedAt)}
            </div>
          )}
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-12 min-w-0">
        {/* LEFT COLUMN: AGENTS LIST + QUICK ACTIONS */}
        <div className="xl:col-span-4 space-y-6 min-w-0">
          <Panel title="Agents" right={`${agentsFiltered.length}/${agentsSorted.length}`} scrollY style={{ height: H_PANEL_TALL }}>
            <div className="space-y-3">
              <input
                value={agentQuery}
                onChange={(e) => setAgentQuery(e.target.value)}
                placeholder="Search agents (name, id, tags)…"
                className={inputClassName(false)}
              />

              <button
                type="button"
                onClick={() => setConfigOpen(true)}
                className={cx(
                  "w-full border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                  "hover:bg-primary/5"
                )}
              >
                Configure selected agent
              </button>

              <div className="space-y-2">
                {agentsFiltered.length === 0 ? (
                  <EmptyState title="No matches" hint="Try a different search query." />
                ) : (
                  agentsFiltered.map((a) => {
                    const disabled = Boolean(a.is_revoked);
                    const online = !disabled && isOnline(a.last_seen_at);
                    const state = disabled ? "disabled" : online ? "online" : "offline";
                    const active = a.agent_id === selectedAgentId;

                    return (
                      <button
                        key={a.agent_id}
                        type="button"
                        onClick={() => selectAgent(a.agent_id)}
                        className={cx(
                          "w-full text-left rounded-md border border-border/60 px-3 py-2",
                          active ? "bg-primary/10" : "bg-background/20",
                          "hover:bg-muted/10",
                          "focus:outline-none focus:ring-2 focus:ring-primary/30"
                        )}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex items-center gap-3 min-w-0">
                            <Dot state={state} />
                            <div className="min-w-0">
                              <div className="text-sm font-mono truncate">{a.display_name || a.agent_id}</div>
                              <div className="text-[10px] font-mono text-muted-foreground truncate">{a.agent_id}</div>
                            </div>
                          </div>
                          <div className="text-[10px] font-mono text-muted-foreground whitespace-nowrap">
                            {fmtLastSeen(a.last_seen_at)}
                          </div>
                        </div>
                        {a.tags && a.tags.length ? (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {a.tags.slice(0, 4).map((t) => (
                              <span
                                key={t}
                                className="rounded border border-border/60 bg-background/30 px-2 py-0.5 text-[10px] font-mono text-muted-foreground"
                              >
                                {t}
                              </span>
                            ))}
                            {a.tags.length > 4 ? (
                              <span className="rounded border border-border/60 bg-background/30 px-2 py-0.5 text-[10px] font-mono text-muted-foreground">
                                +{a.tags.length - 4}
                              </span>
                            ) : null}
                          </div>
                        ) : null}
                      </button>
                    );
                  })
                )}
              </div>
            </div>
          </Panel>

          <Panel title="Actions" right={agent?.is_revoked ? "Disabled" : "Enabled"} style={{ height: 220 }}>
            {!agent ? (
              <EmptyState title="Agent not loaded" hint="Try refresh or check API connectivity." />
            ) : (
              <div className="h-full flex flex-col justify-between gap-4">
                <div className="space-y-1">
                  <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
                    Selected
                  </div>
                  <div className="text-sm font-mono truncate">{agent.display_name || agent.agent_id}</div>
                  <div className="text-[10px] font-mono text-muted-foreground truncate">{agent.agent_id}</div>
                </div>

                <div className="flex flex-col gap-2">
                  <button
                    type="button"
                    onClick={() => setConfigOpen(true)}
                    className={cx(
                      "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                      "hover:bg-primary/5"
                    )}
                  >
                    Open configuration
                  </button>

                  {isAdmin && (
                    <button
                      type="button"
                      onClick={openResponseActionDrawer}
                      className={cx(
                        "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                        "hover:bg-primary/5"
                      )}
                    >
                      Queue response action
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={onToggleRevoked}
                    disabled={toggleBusy}
                    className={cx(
                      "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                      "hover:bg-primary/5",
                      toggleBusy && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    {toggleBusy ? "Working..." : agent.is_revoked ? "Enable agent" : "Disable agent"}
                  </button>
                </div>

                {agentError && <div className="text-[11px] text-red-400">{agentError}</div>}
              </div>
            )}
          </Panel>
        </div>

        {/* RIGHT COLUMN: TELEMETRY + EVENTS WORKBENCH */}
        <div className="xl:col-span-8 space-y-6 min-w-0">
          <Panel
            title="At a glance"
            right={topStats.online ? "Online" : selectedAgentRow?.is_revoked ? "Disabled" : ""}
            style={{ height: 220 }}
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 min-w-0">
              <StatTile
                label="Status"
                value={topStats.status}
                tone={topStats.online ? "good" : selectedAgentRow?.is_revoked ? "warn" : "default"}
              />
              <StatTile label="Last seen" value={topStats.lastSeen} />
              <StatTile label="Events / 5m" value={eventsRate} />
              <StatTile label="Alerts / 60m" value={alerts60m} tone={Number(alerts60m) > 0 ? "warn" : "default"} />
              <StatTile label="Last event age" value={lastEventAge} />
            </div>
          </Panel>

          {snapshotError && (
            <div className="border border-border/60 bg-background/40 p-3 text-[11px] text-red-400">
              Overview: {snapshotError}
            </div>
          )}

          <div className="grid gap-6 lg:grid-cols-2 min-w-0">
            <Panel title="Traffic" style={{ height: H_PANEL_MD }}>
              {!charts.traffic ? (
                <Loading label="Loading chart..." />
              ) : (
                <div className="h-full w-full min-w-0 overflow-hidden">
                  <SimpleTimeSeries data={charts.traffic.data} seriesKeys={charts.traffic.series} height={Math.max(180, H_PANEL_MD - 120)} allowHorizontalScroll={false} />
                </div>
              )}
            </Panel>

            <Panel title="SSH failures" style={{ height: H_PANEL_MD }}>
              {!charts.ssh ? (
                <Loading label="Loading chart..." />
              ) : (
                <div className="h-full w-full min-w-0 overflow-hidden">
                  <SimpleTimeSeries data={charts.ssh.data} seriesKeys={charts.ssh.series} height={Math.max(180, H_PANEL_MD - 120)} allowHorizontalScroll={false} />
                </div>
              )}
            </Panel>

            <Panel title="DDoS" style={{ height: H_PANEL_MD }}>
              {!charts.ddos ? (
                <Loading label="Loading chart..." />
              ) : (
                <div className="h-full w-full min-w-0 overflow-hidden">
                  <SimpleTimeSeries data={charts.ddos.data} seriesKeys={charts.ddos.series} height={Math.max(180, H_PANEL_MD - 120)} allowHorizontalScroll={false} />
                </div>
              )}
            </Panel>

            <Panel title="Alert severity" style={{ height: H_PANEL_MD }}>
              {!charts.sev ? (
                <Loading label="Loading chart..." />
              ) : (
                <div className="h-full w-full min-w-0 overflow-hidden">
                  <SimpleTimeSeries data={charts.sev.data} seriesKeys={charts.sev.series} height={Math.max(180, H_PANEL_MD - 120)} allowHorizontalScroll={false} />
                </div>
              )}
            </Panel>
          </div>


        </div>
      </div>

      {/* EVENTS WORKBENCH (full-width) */}
      <div className="grid gap-6 xl:grid-cols-12 min-w-0">
            {/* LEFT: Filters/Explorer/Details (wider) */}
            <div className="xl:col-span-4 space-y-6 min-h-0 min-w-0">
              <Panel title="Event filters" scrollY style={{ height: 420 }}>
                <div className="space-y-3">
                  <div>
                    <FieldLabel>Event type</FieldLabel>
                    <select
                      className={cx(
                        "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
                        "focus:ring-2 focus:ring-primary/30"
                      )}
                      value={eventsCfg.event_type}
                      onChange={(e) => setEventsCfg((p) => ({ ...p, event_type: e.target.value }))}
                    >
                      <option value="">All types</option>
                      {availableTypes.map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <FieldLabel>Search</FieldLabel>
                    <input
                      className={inputClassName(false)}
                      value={eventsCfg.search}
                      onChange={(e) => setEventsCfg((p) => ({ ...p, search: e.target.value }))}
                      placeholder="ip, user, rule, port, vector..."
                    />
                    <div className="mt-1 text-[11px] text-muted-foreground">
                      Client-side search over event fields + extra JSON.
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <FieldLabel>Window (min)</FieldLabel>
                      <DraftNumberInput
                        value={eventsCfg.window_minutes}
                        min={1}
                        max={10080}
                        fallback={DEFAULT_WINDOW_MINUTES}
                        onCommit={(v) => setEventsCfg((p) => ({ ...p, window_minutes: v }))}
                        className={inputClassName(false)}
                        title="Lookback window (minutes)"
                      />
                    </div>

                    <div>
                      <FieldLabel>Limit</FieldLabel>
                      <DraftNumberInput
                        value={eventsCfg.limit}
                        min={50}
                        max={5000}
                        fallback={DEFAULT_EVENTS_LIMIT}
                        onCommit={(v) => setEventsCfg((p) => ({ ...p, limit: v }))}
                        className={inputClassName(false)}
                        title="Max events to fetch"
                      />
                    </div>
                  </div>

                  <div className="flex items-center justify-between gap-3 pt-2">
                    <button
                      type="button"
                      onClick={() => setEventsCfg((p) => ({ ...p, event_type: "", search: "" }))}
                      className={cx(
                        "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                        "hover:bg-primary/5"
                      )}
                    >
                      Clear filters
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        const cfg = eventsCfgRef.current;
                        loadSnapshot(selectedAgentId, cfg);
                        loadEvents(selectedAgentId, cfg);
                      }}
                      className={cx(
                        "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                        "hover:bg-primary/5",
                        eventsLoading && "opacity-60 cursor-not-allowed"
                      )}
                      disabled={eventsLoading}
                    >
                      {eventsLoading ? "Loading..." : "Reload events"}
                    </button>
                  </div>
                </div>
              </Panel>

              <Panel title="Explorer" scrollY style={{ height: 360 }}>
                <div className="space-y-1">
                  <button
                    type="button"
                    className={cx(
                      "w-full text-left px-3 py-2 rounded-md border border-border/60 bg-background/30",
                      "hover:bg-muted/10",
                      !eventsCfg.event_type && "bg-primary/10"
                    )}
                    onClick={() => setEventsCfg((p) => ({ ...p, event_type: "" }))}
                  >
                    <div className="flex items-center justify-between">
                      <div className="text-sm font-mono">All types</div>
                      <div className="text-[10px] font-mono text-muted-foreground">{explorerBase.length}</div>
                    </div>
                  </button>

                  {topTypes.map((x) => {
                    const active = eventsCfg.event_type === x.key;
                    return (
                      <button
                        key={x.key}
                        type="button"
                        className={cx(
                          "w-full text-left px-3 py-2 rounded-md border border-border/60 bg-background/20",
                          "hover:bg-muted/10",
                          active && "bg-primary/10"
                        )}
                        onClick={() => setEventsCfg((p) => ({ ...p, event_type: x.key }))}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="text-sm font-mono truncate">{x.key}</div>
                          <div className="text-[10px] font-mono text-muted-foreground">{x.count}</div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </Panel>

              <Panel title="Event details" scrollY style={{ height: H_PANEL_TALL }}>
                <EventDetailsPanel event={selectedEvent} />
              </Panel>
            </div>

            {/* RIGHT: Deep Dive + Stream (wider) */}
            <div className="xl:col-span-8 space-y-6 min-h-0 min-w-0">
              {ddosMode && (
                <Panel
                  title="DDoS Deep Dive"
                  right={ddosEvents.length ? `${ddosEvents.length} events` : ""}
                  scrollY
                  style={{ height: H_PANEL_TALL }}
                >
                  {ddosEvents.length === 0 ? (
                    <EmptyState title="No DDoS events" hint="No dos_attack telemetry matches the current filters/window." />
                  ) : (
                    <DdosDeepDive events={ddosEvents} selectedId={selectedEvent?.id ?? null} onSelect={(e) => setSelectedEvent(e)} />
                  )}
                </Panel>
              )}

              <Panel title="Event stream" right={eventsError ? "Error" : `${filteredEvents.length} events`} scrollY style={{ height: H_PANEL_TALL }}>
                {eventsError ? (
                  <EmptyState title="Events error" hint={eventsError} />
                ) : eventsLoading && filteredEvents.length === 0 ? (
                  <Loading label="Loading events..." />
                ) : filteredEvents.length === 0 ? (
                  <EmptyState title="No events" hint="No events match the current filters/window." />
                ) : (
                  <div className="h-full min-w-0">
                    <EventsTable rows={filteredEvents} selectedId={selectedEvent?.id ?? null} compact showExtra onSelect={(e) => setSelectedEvent(e)} />
                  </div>
                )}
              </Panel>
            </div>
      </div>

      <Drawer
        open={responseActionOpen}
        onClose={closeResponseActionDrawer}
        title={`Response action • ${responseActionAgentRow?.display_name || responseActionAgentId || "Select target"}`}
        description="Operator workflow for audited agent-side response execution."
        widthClassName="w-[860px]"
      >
        {!isAdmin ? (
          <EmptyState title="Access denied" hint="Only administrators can queue response actions." />
        ) : (
          <div className="space-y-4">
            <div className="rounded-lg border border-border/60 bg-background/40 p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
                    Operator workflow
                  </div>
                  <div className="text-base font-semibold">Queue agent response action</div>
                  <div className="text-[12px] text-muted-foreground">
                    Confirm target and intent before submitting. The request is queued for the selected agent.
                  </div>
                </div>
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                  operator {user?.username || "-"}
                </div>
              </div>

              <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Target</div>
                  <div className="mt-1 text-[12px] font-mono truncate">
                    {responseActionAgentRow?.display_name || responseActionAgentId || "Not selected"}
                  </div>
                </div>
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Agent id</div>
                  <div className="mt-1 text-[12px] font-mono truncate">{responseActionAgentId || "-"}</div>
                </div>
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Status</div>
                  <div className="mt-1 flex items-center gap-2 text-[12px] font-mono">
                    <Dot
                      state={
                        responseActionAgentRow?.is_revoked
                          ? "disabled"
                          : isOnline(responseActionAgentRow?.last_seen_at)
                            ? "online"
                            : "offline"
                      }
                    />
                    <span>{responseActionAgentStatus}</span>
                  </div>
                </div>
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Last seen</div>
                  <div className="mt-1 text-[12px] font-mono">
                    {responseActionAgentRow ? fmtLastSeen(responseActionAgentRow.last_seen_at) : "-"}
                  </div>
                </div>
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Tags</div>
                  <div className="mt-1 text-[12px] font-mono truncate" title={(responseActionAgentRow?.tags || []).join(", ")}>
                    {(responseActionAgentRow?.tags || []).slice(0, 2).join(", ") || "-"}
                    {(responseActionAgentRow?.tags || []).length > 2 ? ` +${(responseActionAgentRow?.tags || []).length - 2}` : ""}
                  </div>
                </div>
              </div>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <Panel title="Target & scheduling">
                <div className="space-y-4">
                  <div>
                    <FieldLabel>Target agent</FieldLabel>
                    <select
                      className={inputClassName(responseActionBusy)}
                      value={responseActionAgentId}
                      onChange={(e) => {
                        setResponseActionAgentId(e.target.value);
                        setResponseActionError(null);
                        setResponseActionCreated(null);
                      }}
                      disabled={responseActionBusy}
                    >
                      <option value="">Select an agent</option>
                      {agentsSorted.map((a) => (
                        <option key={a.agent_id} value={a.agent_id}>
                          {(a.display_name || a.agent_id) + " (" + a.agent_id + ")"}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <FieldLabel>Expiration (optional)</FieldLabel>
                    <input
                      type="datetime-local"
                      className={inputClassName(responseActionBusy)}
                      value={responseActionExpiresAt}
                      onChange={(e) => {
                        setResponseActionExpiresAt(e.target.value);
                        setResponseActionError(null);
                        setResponseActionCreated(null);
                      }}
                      disabled={responseActionBusy}
                    />
                    <div className="mt-2 flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => setResponseActionExpiryOffset(15)}
                        disabled={responseActionBusy}
                        className={cx(
                          "rounded border border-border/60 bg-background/30 px-2 py-1 text-[10px] font-mono uppercase tracking-widest",
                          "hover:bg-muted/10",
                          responseActionBusy && "opacity-60 cursor-not-allowed"
                        )}
                      >
                        +15m
                      </button>
                      <button
                        type="button"
                        onClick={() => setResponseActionExpiryOffset(60)}
                        disabled={responseActionBusy}
                        className={cx(
                          "rounded border border-border/60 bg-background/30 px-2 py-1 text-[10px] font-mono uppercase tracking-widest",
                          "hover:bg-muted/10",
                          responseActionBusy && "opacity-60 cursor-not-allowed"
                        )}
                      >
                        +1h
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setResponseActionExpiresAt("");
                          setResponseActionError(null);
                          setResponseActionCreated(null);
                        }}
                        disabled={responseActionBusy}
                        className={cx(
                          "rounded border border-border/60 bg-background/30 px-2 py-1 text-[10px] font-mono uppercase tracking-widest",
                          "hover:bg-muted/10",
                          responseActionBusy && "opacity-60 cursor-not-allowed"
                        )}
                      >
                        Clear
                      </button>
                    </div>
                    {responseActionExpirationInvalid && (
                      <div className="mt-1 text-[11px] text-red-400">Expiration must be a valid date and time.</div>
                    )}
                    {responseActionExpirationInPast && (
                      <div className="mt-1 text-[11px] text-red-400">Expiration must be in the future.</div>
                    )}
                  </div>
                </div>
              </Panel>

              <Panel title="Action">
                <div className="space-y-4">
                  <div>
                    <FieldLabel>Action type</FieldLabel>
                    <select
                      className={inputClassName(responseActionBusy)}
                      value={responseActionType}
                      onChange={(e) => {
                        setResponseActionType(e.target.value);
                        setResponseActionError(null);
                        setResponseActionCreated(null);
                      }}
                      disabled={responseActionBusy}
                    >
                      {RESPONSE_ACTION_TYPES.map((x) => (
                        <option key={x.key} value={x.key}>
                          {x.label}
                        </option>
                      ))}
                    </select>
                    <div className="mt-1 text-[11px] text-muted-foreground">{responseActionDefinition.hint}</div>
                  </div>

                  <div className="rounded border border-border/60 bg-background/30 p-3 space-y-2">
                    <div>
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Expected effect</div>
                      <div className="mt-1 text-[12px] text-muted-foreground">{responseActionDefinition.effect}</div>
                    </div>
                    <div>
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Expected result</div>
                      <div className="mt-1 text-[12px] text-muted-foreground">{responseActionDefinition.expectedResult}</div>
                    </div>
                    <div>
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Audit</div>
                      <div className="mt-1 text-[12px] text-muted-foreground">{responseActionDefinition.auditNote}</div>
                    </div>
                  </div>
                </div>
              </Panel>
            </div>

            <Panel title="Payload" right={responseActionAdvancedOpen ? "Advanced mode" : "Guided mode"}>
              <div className="space-y-3">
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2 text-[12px] text-muted-foreground">
                  This action does not require additional payload fields in standard mode.
                </div>

                <button
                  type="button"
                  onClick={() => {
                    setResponseActionAdvancedOpen((prev) => !prev);
                    setResponseActionError(null);
                    setResponseActionCreated(null);
                  }}
                  disabled={responseActionBusy}
                  className={cx(
                    "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                    "hover:bg-primary/5",
                    responseActionBusy && "opacity-60 cursor-not-allowed"
                  )}
                >
                  {responseActionAdvancedOpen ? "Hide advanced payload" : "Show advanced payload JSON"}
                </button>

                {responseActionAdvancedOpen && (
                  <div>
                    <textarea
                      className={textAreaClassName(responseActionBusy)}
                      rows={7}
                      value={responseActionPayloadText}
                      onChange={(e) => {
                        setResponseActionPayloadText(e.target.value);
                        setResponseActionError(null);
                        setResponseActionCreated(null);
                      }}
                      disabled={responseActionBusy}
                    />
                    {responseActionPayloadError && (
                      <div className="mt-1 text-[11px] text-red-400">Payload: {responseActionPayloadError}</div>
                    )}
                  </div>
                )}
              </div>
            </Panel>

            <Panel title="Execution summary" right="Review before queueing">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Agent</div>
                  <div className="mt-1 text-[12px] font-mono">{responseActionAgentId || "Not selected"}</div>
                </div>
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Action</div>
                  <div className="mt-1 text-[12px] font-mono">{responseActionDefinition.label}</div>
                </div>
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Expiration</div>
                  <div className="mt-1 text-[12px] font-mono">{responseActionExpiresLabel}</div>
                </div>
                <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Payload keys</div>
                  <div className="mt-1 text-[12px] font-mono">{Object.keys(responseActionPayload.payload || {}).length}</div>
                </div>
              </div>
            </Panel>

            <Panel title="Recent queued in this session" right={responseActionRecentForAgent.length ? String(responseActionRecentForAgent.length) : "None"}>
              {responseActionRecentForAgent.length === 0 ? (
                <div className="text-[12px] text-muted-foreground">No response actions queued for this agent in this session yet.</div>
              ) : (
                <div className="space-y-2">
                  {responseActionRecentForAgent.map((x) => (
                    <div key={x.id} className="rounded border border-border/60 bg-background/30 px-3 py-2">
                      <div className="flex items-center justify-between gap-2">
                        <div className="text-[12px] font-mono">#{x.id} {x.action_type}</div>
                        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{x.status}</div>
                      </div>
                      <div className="mt-1 text-[11px] text-muted-foreground">requested {fmtMaybeIso(x.requested_at)}</div>
                    </div>
                  ))}
                </div>
              )}
            </Panel>

            {responseActionError && (
              <div className="rounded-lg border border-red-400/50 bg-red-500/10 px-4 py-3 text-[12px] text-red-300">
                {responseActionError}
              </div>
            )}

            {responseActionCreated && (
              <div className="rounded-lg border border-emerald-400/50 bg-emerald-500/10 px-4 py-3 text-[12px] text-emerald-300">
                Response action #{responseActionCreated.id} queued for {responseActionCreated.agent_id} with status {responseActionCreated.status}.
              </div>
            )}

            <div className="rounded-lg border border-border/60 bg-background/40 px-4 py-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="text-[11px] text-muted-foreground">
                  Verify target and action intent before queueing.
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    onClick={closeResponseActionDrawer}
                    disabled={responseActionBusy}
                    className={cx(
                      "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                      "hover:bg-primary/5",
                      responseActionBusy && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={onSubmitResponseAction}
                    disabled={!canSubmitResponseAction}
                    className={cx(
                      "border border-primary/60 bg-primary/20 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest text-foreground",
                      "hover:bg-primary/30",
                      (!canSubmitResponseAction || responseActionBusy) && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    {responseActionBusy ? "Queueing..." : "Queue response action"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </Drawer>

      <Drawer
        open={configOpen}
        onClose={() => setConfigOpen(false)}
        title={`Agent settings • ${agent?.display_name || selectedAgentId}`}
        description="Identity + configuration. Capture-module tuning is applied on next agent restart."
        widthClassName="w-[1200px]"
      >
        {!agent ? (
          <div className="space-y-4">
            <EmptyState title="Agent not loaded" hint="Try refresh or check API connectivity." />
          </div>
        ) : (
          <div className="space-y-6">
            <div className="grid gap-6 lg:grid-cols-2">
              <Panel title="Identity">
                <div className="space-y-4">
                  <div>
                    <FieldLabel>Display name</FieldLabel>
                    <input
                      className={inputClassName(saveBusy)}
                      value={draftName}
                      onChange={(e) => setDraftName(e.target.value)}
                      placeholder="e.g., Web Server - PROD"
                      disabled={saveBusy}
                    />
                  </div>

                  <div>
                    <FieldLabel>Description</FieldLabel>
                    <input
                      className={inputClassName(saveBusy)}
                      value={draftDesc}
                      onChange={(e) => setDraftDesc(e.target.value)}
                      placeholder="Short context about what this agent protects"
                      disabled={saveBusy}
                    />
                  </div>

                  <div>
                    <FieldLabel>Tags</FieldLabel>
                    <input
                      className={inputClassName(saveBusy)}
                      value={draftTags}
                      onChange={(e) => setDraftTags(e.target.value)}
                      placeholder="prod, web, ssh, dmz"
                      disabled={saveBusy}
                    />
                    <div className="mt-1 text-[11px] text-muted-foreground">Comma-separated.</div>
                  </div>

                  <div>
                    <FieldLabel>Metadata (JSON)</FieldLabel>
                    <textarea
                      className={textAreaClassName(saveBusy)}
                      rows={6}
                      value={draftMetaText}
                      onChange={(e) => setDraftMetaText(e.target.value)}
                      disabled={saveBusy}
                    />
                  </div>

                  <div className="flex flex-wrap items-center gap-3 pt-1">
                    <button
                      type="button"
                      onClick={onSaveAgent}
                      disabled={!canSaveAgent}
                      className={cx(
                        "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                        "hover:bg-primary/5",
                        (!canSaveAgent || saveBusy) && "opacity-60 cursor-not-allowed"
                      )}
                    >
                      {saveBusy ? "Saving..." : "Save"}
                    </button>
                  </div>
                </div>
              </Panel>

              <Panel title="State" right={agent.is_revoked ? "Disabled" : isOnline(agent.last_seen_at) ? "Online" : "Offline"}>
                <div className="space-y-4">
                  <div className="flex items-center justify-between gap-3">
                    <div className="space-y-1 min-w-0">
                      <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Agent</div>
                      <div className="text-sm font-mono truncate">{agent.display_name || agent.agent_id}</div>
                      <div className="text-[10px] font-mono text-muted-foreground truncate">{agent.agent_id}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Dot state={agent.is_revoked ? "disabled" : isOnline(agent.last_seen_at) ? "online" : "offline"} />
                      <div className="text-[10px] font-mono text-muted-foreground whitespace-nowrap">{fmtLastSeen(agent.last_seen_at)}</div>
                    </div>
                  </div>

                  <div className="border border-border/60 bg-background/20 p-3 rounded-md">
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Actions</div>
                    <div className="mt-3 flex flex-col gap-2">
                      <button
                        type="button"
                        onClick={onToggleRevoked}
                        disabled={toggleBusy}
                        className={cx(
                          "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                          "hover:bg-primary/5",
                          toggleBusy && "opacity-60 cursor-not-allowed"
                        )}
                      >
                        {toggleBusy ? "Working..." : agent.is_revoked ? "Enable agent" : "Disable agent"}
                      </button>
                    </div>
                  </div>

                  {agentError && <div className="text-[11px] text-red-400">{agentError}</div>}
                </div>
              </Panel>
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <Panel title="DDoS / Backpressure">
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <Switch
                      checked={ddosDraft.enabled}
                      onChange={(v) => setDdosDraft((s) => ({ ...s, enabled: v }))}
                      disabled={configBusy}
                      label="DDoS module"
                    />
                    <Switch
                      checked={ddosDraft.enable_l7}
                      onChange={(v) => setDdosDraft((s) => ({ ...s, enable_l7: v }))}
                      disabled={configBusy}
                      label="L7 detection"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <FieldLabel>Interface</FieldLabel>
                      <input
                        className={inputClassName(configBusy)}
                        value={ddosDraft.iface}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, iface: e.target.value }))}
                        placeholder="any / eth0"
                        disabled={configBusy}
                      />
                    </div>
                    <div>
                      <FieldLabel>Window</FieldLabel>
                      <input
                        className={inputClassName(configBusy)}
                        value={ddosDraft.window}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, window: e.target.value }))}
                        placeholder="1s"
                        disabled={configBusy}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <FieldLabel>Eval Every</FieldLabel>
                      <input
                        className={inputClassName(configBusy)}
                        value={ddosDraft.eval_every}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, eval_every: e.target.value }))}
                        placeholder="1s"
                        disabled={configBusy}
                      />
                    </div>
                    <div>
                      <FieldLabel>Cooldown</FieldLabel>
                      <input
                        className={inputClassName(configBusy)}
                        value={ddosDraft.cooldown}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, cooldown: e.target.value }))}
                        placeholder="30s"
                        disabled={configBusy}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-3">
                    <div>
                      <FieldLabel>Sustain</FieldLabel>
                      <input
                        type="number"
                        className={inputClassName(configBusy)}
                        value={String(ddosDraft.sustain_windows)}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, sustain_windows: Number(e.target.value) || 1 }))}
                        disabled={configBusy}
                      />
                    </div>
                    <div>
                      <FieldLabel>Min Confidence</FieldLabel>
                      <input
                        type="number"
                        className={inputClassName(configBusy)}
                        value={String(ddosDraft.min_confidence)}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, min_confidence: Number(e.target.value) || 1 }))}
                        disabled={configBusy}
                      />
                    </div>
                    <div>
                      <FieldLabel>Max Batch</FieldLabel>
                      <input
                        type="number"
                        className={inputClassName(configBusy)}
                        value={String(ddosDraft.max_batch)}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, max_batch: Number(e.target.value) || 1 }))}
                        disabled={configBusy}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <FieldLabel>Min PPS</FieldLabel>
                      <input
                        type="number"
                        className={inputClassName(configBusy)}
                        value={String(ddosDraft.min_pps)}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, min_pps: Number(e.target.value) || 0 }))}
                        disabled={configBusy}
                      />
                    </div>
                    <div>
                      <FieldLabel>Min BPS</FieldLabel>
                      <input
                        type="number"
                        className={inputClassName(configBusy)}
                        value={String(ddosDraft.min_bps)}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, min_bps: Number(e.target.value) || 0 }))}
                        disabled={configBusy}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <FieldLabel>Min HTTP RPS</FieldLabel>
                      <input
                        type="number"
                        className={inputClassName(configBusy)}
                        value={String(ddosDraft.min_http_rps)}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, min_http_rps: Number(e.target.value) || 0 }))}
                        disabled={configBusy}
                      />
                    </div>
                    <div>
                      <FieldLabel>Min TLS HS RPS</FieldLabel>
                      <input
                        type="number"
                        className={inputClassName(configBusy)}
                        value={String(ddosDraft.min_tls_hs_rps)}
                        onChange={(e) => setDdosDraft((s) => ({ ...s, min_tls_hs_rps: Number(e.target.value) || 0 }))}
                        disabled={configBusy}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <FieldLabel>BP High Watermark</FieldLabel>
                      <input
                        type="number"
                        className={inputClassName(configBusy)}
                        value={String(ddosDraft.backpressure_high_watermark)}
                        onChange={(e) =>
                          setDdosDraft((s) => ({ ...s, backpressure_high_watermark: Number(e.target.value) || 1 }))
                        }
                        disabled={configBusy}
                      />
                    </div>
                    <div>
                      <FieldLabel>BP Sample Every</FieldLabel>
                      <input
                        type="number"
                        className={inputClassName(configBusy)}
                        value={String(ddosDraft.backpressure_sample_every)}
                        onChange={(e) =>
                          setDdosDraft((s) => ({ ...s, backpressure_sample_every: Number(e.target.value) || 1 }))
                        }
                        disabled={configBusy}
                      />
                    </div>
                  </div>

                  <div className="text-[11px] text-muted-foreground">
                    These settings are saved in agent config (`modules.ddos`) and replace the need to edit `.env` for DDoS tuning.
                    Restart the agent container to apply capture-level changes.
                  </div>

                  <button
                    type="button"
                    onClick={onApplyDdosConfig}
                    disabled={configBusy}
                    className={cx(
                      "w-full border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                      "hover:bg-primary/5",
                      configBusy && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    {configBusy ? "Saving..." : "Save DDoS settings"}
                  </button>
                </div>
              </Panel>

              <Panel title="Timings" right={timingKeys.length ? `${timingKeys.length} keys` : "-"}>
                {timingKeys.length === 0 ? (
                  <EmptyState title="No timing keys" hint="This agent config does not expose timing-related fields." />
                ) : (
                  <div className="grid gap-3 sm:grid-cols-2">
                    {timingKeys.map((k) => (
                      <div key={k}>
                        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{k}</div>
                        <input
                          type="number"
                          className={inputClassName(configBusy)}
                          value={String((configObj as any)[k] ?? "")}
                          onChange={(e) => onUpdateTiming(k, Number(e.target.value))}
                          disabled={configBusy}
                        />
                      </div>
                    ))}
                  </div>
                )}
              </Panel>

              <Panel title="Raw config" right={configParseError ? "Invalid" : "JSON"}>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <FieldLabel>Config (JSON)</FieldLabel>
                    <button
                      type="button"
                      onClick={() => {
                        const parsed = safeJsonParse(configText);
                        if (parsed.ok) setConfigText(prettyJson(parsed.value));
                      }}
                      className="text-[10px] text-primary hover:underline"
                    >
                      Format
                    </button>
                  </div>

                  <textarea
                    className={textAreaClassName(configBusy)}
                    rows={14}
                    value={configText}
                    onChange={(e) => onConfigTextChange(e.target.value)}
                    disabled={configBusy}
                  />

                  {configParseError && <div className="text-[11px] text-red-400">Config: {configParseError}</div>}

                  <button
                    type="button"
                    onClick={onApplyConfig}
                    disabled={configBusy || Boolean(configParseError)}
                    className={cx(
                      "w-full border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                      "hover:bg-primary/5",
                      (configBusy || Boolean(configParseError)) && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    {configBusy ? "Pushing..." : "Push config"}
                  </button>
                </div>
              </Panel>
            </div>
          </div>
        )}
      </Drawer>

    </div>
  );
}
