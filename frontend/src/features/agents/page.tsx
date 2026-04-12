import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import EmptyState from "@/shared/components/EmptyState";
import Drawer from "@/shared/components/Drawer";
import { useDataTablePreferences } from "@/shared/hooks/useDataTablePreferences";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationFactCard,
  InvestigationMetaStrip,
  InvestigationRawJsonPanel,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  InvestigationTabs,
  copyTextToClipboard,
} from "@/shared/components/investigation";
import { cx } from "@/shared/lib/cx";
import { isAbortError } from "@/shared/lib/http";
import { getErrorMessage } from "@/shared/lib/errors";
import PinToWorkspaceDrawer from "@/features/investigations/PinToWorkspaceDrawer";
import { pinResponseResultToWorkspace } from "@/features/investigations/api";

import { useAgentsCatalog } from "@/app/providers";
import { useAuth } from "@/features/auth/context";

import { getOverview } from "@/features/overview/api";
import type { OverviewSnapshot } from "@/features/overview/types";

import { getRecentEvents } from "@/features/events/api";
import type { NetEvent } from "@/features/events/types";
import AgentActionsPanel from "@/features/agents/components/AgentActionsPanel";
import AgentAtGlancePanel from "@/features/agents/components/AgentAtGlancePanel";
import AgentEventsWorkbench from "@/features/agents/components/AgentEventsWorkbench";
import AgentFleetPanel from "@/features/agents/components/AgentFleetPanel";
import AgentTelemetrySnapshot from "@/features/agents/components/AgentTelemetrySnapshot";
import { Dot, FieldLabel, Panel, Switch } from "@/features/agents/components/AgentsPageShared";
import { inputClassName, textAreaClassName } from "@/features/agents/components/AgentFormClassNames";

import {
  cancelResponseAction,
  createResponseAction,
  disableAgent,
  enableAgent,
  getAgent,
  getResponseAction,
  getResponseActionResult,
  listResponseActions,
  setAgentConfig,
  updateAgent
} from "./api";
import type { AgentDetail, AgentPublic, AgentUpdateIn, ResponseActionOut, ResponseActionResultOut } from "./types";

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
  },
  {
    key: "refresh_runtime_config",
    label: "Refresh runtime config",
    hint: "Pull and apply the latest runtime config from the control plane immediately.",
    effect: "The agent performs an immediate config pull outside the regular config ticker.",
    expectedResult: "Result returns whether the runtime config changed, how many keys were pulled, and the resulting config hash.",
    auditNote: "This operation is auditable as an administrative response action request."
  },
  {
    key: "trigger_inventory_snapshot",
    label: "Trigger inventory snapshot",
    hint: "Collect a lightweight host/runtime inventory snapshot from the selected agent.",
    effect: "The agent captures a focused inventory payload without waiting for another collector cadence.",
    expectedResult: "Result includes runtime, host interfaces, process list, and network connection snapshot.",
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

function fmtDuration(startIso?: string | null, endIso?: string | null): string {
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

function parsePositiveInt(v: string | null): number | null {
  const raw = String(v || "").trim();
  if (!raw) return null;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.trunc(n);
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
  const agentTablePrefs = useDataTablePreferences({
    storageKey: "nw_agents_tables_v2",
    defaultPageSize: 100,
    minPageSize: 25,
    maxPageSize: 200,
    defaultCompact: true,
  });
  const compactRows = agentTablePrefs.compact;

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
      setResponseActionMode("create");
      setResponseActionTab("create");
      setResponseActionSelectedId(null);
      setResponseActionHistory([]);
      setResponseActionHistoryLoading(false);
      setResponseActionHistoryError(null);
      setResponseActionLive(null);
      setResponseActionLiveLoading(false);
      setResponseActionLiveError(null);
      setResponseActionResult(null);
      setResponseActionResultLoading(false);
      setResponseActionResultError(null);
      setResponseActionResultRawOpen(false);
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
  const [responseActionMode, setResponseActionMode] = useState<"create" | "investigate">("create");
  const [responseActionTab, setResponseActionTab] = useState<"create" | "execution" | "result">("create");
  const [responseActionSelectedId, setResponseActionSelectedId] = useState<number | null>(null);
  const [responseActionHistory, setResponseActionHistory] = useState<ResponseActionOut[]>([]);
  const [responseActionHistoryLoading, setResponseActionHistoryLoading] = useState(false);
  const [responseActionHistoryError, setResponseActionHistoryError] = useState<string | null>(null);
  const [responseActionLive, setResponseActionLive] = useState<ResponseActionOut | null>(null);
  const [responseActionLiveLoading, setResponseActionLiveLoading] = useState(false);
  const [responseActionLiveError, setResponseActionLiveError] = useState<string | null>(null);
  const [responseActionResult, setResponseActionResult] = useState<ResponseActionResultOut | null>(null);
  const [responseActionResultLoading, setResponseActionResultLoading] = useState(false);
  const [responseActionResultError, setResponseActionResultError] = useState<string | null>(null);
  const [responseActionResultRawOpen, setResponseActionResultRawOpen] = useState(false);
  const [pinResponseResultId, setPinResponseResultId] = useState<number | null>(null);

  const snapshotSeqRef = useRef(0);
  const eventsSeqRef = useRef(0);
  const snapshotAbortRef = useRef<AbortController | null>(null);
  const eventsAbortRef = useRef<AbortController | null>(null);

  const lastUrlId = useRef<string | null>(null);
  const responseUrlHandledRef = useRef<string | null>(null);

  useEffect(() => {
    const q = (searchParams.get("agent_id") || "").trim();

    // Apply only when the URL actually changes.
    if (lastUrlId.current !== q) {
      lastUrlId.current = q;
      setSelectedAgentId(q);
    }

    const responseActionId = parsePositiveInt(searchParams.get("response_action_id"));
    const responseTab = (searchParams.get("response_tab") || "").trim().toLowerCase();
    const shouldOpenResponse = String(searchParams.get("open_response_action") || "").trim() === "1" || !!responseActionId;
    const responseKey = `${q}:${responseActionId || ""}:${responseTab}:${shouldOpenResponse ? "1" : "0"}`;
    if (!shouldOpenResponse) return;
    if (responseUrlHandledRef.current === responseKey) return;
    responseUrlHandledRef.current = responseKey;

    resetResponseActionForm(q || "");
    setResponseActionOpen(true);
    if (responseActionId) setResponseActionSelectedId(responseActionId);
    if (responseTab === "result" || responseTab === "execution" || responseTab === "create") {
      setResponseActionTab(responseTab);
      setResponseActionMode(responseTab === "create" ? "create" : "investigate");
    } else if (responseActionId) {
      setResponseActionTab("result");
      setResponseActionMode("investigate");
    }
  }, [searchParams, setSelectedAgentId, resetResponseActionForm]);

  const selectedAgentRow = useMemo<AgentPublic | null>(() => {
    if (!selectedAgentId) return null;
    return agents.find((a) => a.agent_id === selectedAgentId) || null;
  }, [agents, selectedAgentId]);

  useEffect(() => {
    if (!responseActionOpen) return;
    if (responseActionSelectedId) return;
    resetResponseActionForm(selectedAgentId || "");
  }, [responseActionOpen, selectedAgentId, responseActionSelectedId, resetResponseActionForm]);

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
    const mySeq = ++snapshotSeqRef.current;
    snapshotAbortRef.current?.abort();
    const controller = new AbortController();
    snapshotAbortRef.current = controller;

    try {
      const win = Math.max(1, safeNumber(cfg.window_minutes, DEFAULT_WINDOW_MINUTES));
      const snap = await getOverview(
        { window_minutes: win, agent_id: agentId },
        { signal: controller.signal, timeoutMs: 12000 }
      );
      if (snapshotSeqRef.current !== mySeq) return;
      setSnapshot(snap);
      setSnapshotError(null);
      setLastUpdatedAt(new Date());
    } catch (e: any) {
      if (isAbortError(e)) return;
      if (snapshotSeqRef.current !== mySeq) return;
      setSnapshotError(getErrorMessage(e, "Failed to load overview"));
    } finally {
      if (snapshotAbortRef.current === controller) {
        snapshotAbortRef.current = null;
      }
    }
  }, []);

  const loadEvents = useCallback(async (agentId: string, cfg: EventsCfg) => {
    const mySeq = ++eventsSeqRef.current;
    eventsAbortRef.current?.abort();
    const controller = new AbortController();
    eventsAbortRef.current = controller;

    setEventsLoading(true);
    try {
      const lim = Math.max(50, Math.min(5000, safeNumber(cfg.limit, DEFAULT_EVENTS_LIMIT)));
      const win = Math.max(1, safeNumber(cfg.window_minutes, DEFAULT_WINDOW_MINUTES));
      const eventType = (cfg.event_type || "").trim() || undefined;
      const ev = await getRecentEvents(
        { limit: lim, agent_id: agentId, event_type: eventType, since_minutes: win },
        { signal: controller.signal, timeoutMs: 12000 }
      );
      if (eventsSeqRef.current !== mySeq) return;

      setEvents(ev);
      setSelectedEvent((prev) => {
        if (!prev) return ev[0] || null;
        const still = ev.find((x) => x.id === prev.id);
        return still || ev[0] || null;
      });

      setEventsError(null);
      setLastUpdatedAt(new Date());
    } catch (e: any) {
      if (isAbortError(e)) return;
      if (eventsSeqRef.current !== mySeq) return;
      setEventsError(getErrorMessage(e, "Failed to load events"));
      setEvents([]);
      setSelectedEvent(null);
    } finally {
      if (eventsSeqRef.current === mySeq) {
        setEventsLoading(false);
      }
      if (eventsAbortRef.current === controller) {
        eventsAbortRef.current = null;
      }
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
    return () => {
      snapshotAbortRef.current?.abort();
      eventsAbortRef.current?.abort();
    };
  }, []);

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

  const responseActionSelected = useMemo(() => {
    if (!responseActionSelectedId) return null;
    return responseActionHistory.find((x) => x.id === responseActionSelectedId) || responseActionLive || null;
  }, [responseActionSelectedId, responseActionHistory, responseActionLive]);

  const responseActionLiveView = useMemo(() => {
    return responseActionLive || responseActionSelected;
  }, [responseActionLive, responseActionSelected]);

  const responseActionCanCancel = useMemo(() => {
    const s = (responseActionLiveView?.status || "").trim().toLowerCase();
    return s === "pending" || s === "delivered";
  }, [responseActionLiveView]);

  const loadResponseActionHistory = useCallback(
    async (agentId: string) => {
      if (!agentId.trim()) {
        setResponseActionHistory([]);
        setResponseActionHistoryError(null);
        return;
      }
      setResponseActionHistoryLoading(true);
      try {
        const rows = await listResponseActions({ agent_id: agentId.trim(), limit: 25 });
        setResponseActionHistory(rows);
        setResponseActionHistoryError(null);
        setResponseActionSelectedId((prev) => {
          if (prev) return prev;
          return rows[0]?.id ?? null;
        });
      } catch (e: any) {
        setResponseActionHistoryError(getErrorMessage(e, "Failed to load response actions"));
        setResponseActionHistory([]);
      } finally {
        setResponseActionHistoryLoading(false);
      }
    },
    []
  );

  const loadResponseActionLive = useCallback(async (actionId: number) => {
    if (!Number.isFinite(actionId) || actionId <= 0) return;
    setResponseActionLiveLoading(true);
    try {
      const out = await getResponseAction(actionId);
      setResponseActionLive(out);
      setResponseActionLiveError(null);
      setResponseActionHistory((prev) => {
        const next = prev.filter((x) => x.id !== out.id);
        return [out, ...next].slice(0, 25);
      });
    } catch (e: any) {
      setResponseActionLiveError(getErrorMessage(e, "Failed to load response action"));
      setResponseActionLive(null);
    } finally {
      setResponseActionLiveLoading(false);
    }
  }, []);

  const loadResponseActionResult = useCallback(async (actionId: number) => {
    if (!Number.isFinite(actionId) || actionId <= 0) return;
    setResponseActionResultLoading(true);
    try {
      const out = await getResponseActionResult(actionId);
      setResponseActionResult(out);
      setResponseActionResultError(null);
    } catch (e: any) {
      setResponseActionResult(null);
      if (Number((e as any)?.status) === 404) {
        setResponseActionResultError(null);
      } else {
        setResponseActionResultError(getErrorMessage(e, "Response action result is not available"));
      }
    } finally {
      setResponseActionResultLoading(false);
    }
  }, []);

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

  const onSelectResponseAction = (actionId: number, nextTab: "execution" | "result" = "execution") => {
    if (!Number.isFinite(actionId) || actionId <= 0) {
      setResponseActionSelectedId(null);
      return;
    }
    setResponseActionSelectedId(actionId);
    setResponseActionError(null);
    setResponseActionResultRawOpen(false);
    setResponseActionMode("investigate");
    setResponseActionTab(nextTab);
  };

  const onCancelSelectedResponseAction = async () => {
    if (!responseActionSelectedId) return;
    setResponseActionBusy(true);
    setResponseActionError(null);
    try {
      const out = await cancelResponseAction(responseActionSelectedId);
      setResponseActionLive(out);
      await loadResponseActionHistory(responseActionAgentId);
    } catch (e: any) {
      setResponseActionError(getErrorMessage(e, "Failed to cancel response action"));
    } finally {
      setResponseActionBusy(false);
    }
  };

  const onCopyResponseResultJson = async () => {
    const payload = responseActionResult?.result_payload || {};
    const ok = await copyTextToClipboard(JSON.stringify(payload, null, 2));
    if (!ok) {
      setResponseActionError("Failed to copy result JSON");
    }
  };

  const onDownloadResponseResultJson = () => {
    const payload = responseActionResult?.result_payload || {};
    const actionId = responseActionSelectedId || 0;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `response-action-${actionId}-result.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
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
      setResponseActionSelectedId(out.id);
      setResponseActionMode("investigate");
      setResponseActionTab("execution");
      setResponseActionLive(out);
      await loadResponseActionHistory(agentId);
      await loadResponseActionResult(out.id);
      refresh();
    } catch (e: any) {
      setResponseActionError(getErrorMessage(e, "Failed to create response action"));
    } finally {
      setResponseActionBusy(false);
    }
  };

  useEffect(() => {
    if (!responseActionOpen || !isAdmin) return;
    loadResponseActionHistory(responseActionAgentId || "");
  }, [responseActionOpen, isAdmin, responseActionAgentId, loadResponseActionHistory]);

  useEffect(() => {
    if (!responseActionOpen || !responseActionSelectedId) return;
    loadResponseActionLive(responseActionSelectedId);
    loadResponseActionResult(responseActionSelectedId);
  }, [responseActionOpen, responseActionSelectedId, loadResponseActionLive, loadResponseActionResult]);

  useEffect(() => {
    if (!responseActionOpen || !responseActionSelectedId) return;
    const liveStatus = (responseActionLive?.status || "").trim().toLowerCase();
    if (liveStatus && !["pending", "delivered", "running"].includes(liveStatus)) return;

    const t = window.setInterval(() => {
      loadResponseActionLive(responseActionSelectedId);
      loadResponseActionResult(responseActionSelectedId);
    }, 4000);
    return () => window.clearInterval(t);
  }, [responseActionOpen, responseActionSelectedId, responseActionLive?.status, loadResponseActionLive, loadResponseActionResult]);

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
            <AgentFleetPanel
              agentsFiltered={agentsFiltered}
              agentsSorted={agentsSorted}
              selectedAgentId={selectedAgentId}
              agentQuery={agentQuery}
              onAgentQueryChange={setAgentQuery}
              onSelectAgent={selectAgent}
              fmtLastSeen={fmtLastSeen}
              isOnline={isOnline}
              compact={compactRows}
              height={H_PANEL_TALL}
            />
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
            onClick={() => agentTablePrefs.setCompact(!compactRows)}
            className={cx(
              "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
              compactRows ? "text-foreground" : "text-muted-foreground",
              "hover:bg-primary/5"
            )}
          >
            {compactRows ? "Compact rows" : "Comfortable rows"}
          </button>
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
        <div className="xl:col-span-4 space-y-6 min-w-0">
          <AgentFleetPanel
            agentsFiltered={agentsFiltered}
            agentsSorted={agentsSorted}
            selectedAgentId={selectedAgentId}
            agentQuery={agentQuery}
            onAgentQueryChange={setAgentQuery}
            onSelectAgent={selectAgent}
            onOpenConfig={() => setConfigOpen(true)}
            fmtLastSeen={fmtLastSeen}
            isOnline={isOnline}
            compact={compactRows}
            showConfigButton
            height={H_PANEL_TALL}
          />
          <AgentActionsPanel
            agent={agent}
            isAdmin={isAdmin}
            toggleBusy={toggleBusy}
            agentError={agentError}
            onOpenConfig={() => setConfigOpen(true)}
            onOpenResponseAction={openResponseActionDrawer}
            onToggleRevoked={onToggleRevoked}
          />
        </div>

        <div className="xl:col-span-8 space-y-6 min-w-0">
          <AgentAtGlancePanel
            topStats={topStats}
            eventsRate={eventsRate}
            alerts60m={alerts60m}
            lastEventAge={lastEventAge}
            disabled={Boolean(selectedAgentRow?.is_revoked)}
          />

          {snapshotError && (
            <div className="border border-border/60 bg-background/40 p-3 text-[11px] text-red-400">
              Overview: {snapshotError}
            </div>
          )}

          <AgentTelemetrySnapshot height={H_PANEL_MD} charts={charts} />
        </div>
      </div>

      <AgentEventsWorkbench
        selectedAgentId={selectedAgentId}
        eventsCfg={eventsCfg}
        setEventsCfg={setEventsCfg}
        availableTypes={availableTypes}
        topTypes={topTypes}
        explorerBaseCount={explorerBase.length}
        filteredEvents={filteredEvents}
        selectedEvent={selectedEvent}
        onSelectEvent={setSelectedEvent}
        eventsLoading={eventsLoading}
        eventsError={eventsError}
        onReload={() => {
          const cfg = eventsCfgRef.current;
          loadSnapshot(selectedAgentId, cfg);
          loadEvents(selectedAgentId, cfg);
        }}
        defaultWindowMinutes={DEFAULT_WINDOW_MINUTES}
        defaultEventsLimit={DEFAULT_EVENTS_LIMIT}
        ddosMode={ddosMode}
        ddosEvents={ddosEvents}
        panelHeight={H_PANEL_TALL}
        streamHeight={H_PANEL_TALL}
        compact={compactRows}
      />

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
          <InvestigationShell>
            <InvestigationMetaStrip
              items={[
                { label: "Operator", value: user?.username || "-", variant: "neutral" },
                { label: "Target", value: responseActionAgentRow?.display_name || responseActionAgentId || "not selected", variant: "info" },
                { label: "Agent ID", value: responseActionAgentId || "-" },
                { label: "Agent status", value: responseActionAgentStatus, variant: responseActionAgentStatus === "Online" ? "low" : "neutral" },
                { label: "Last seen", value: responseActionAgentRow ? fmtLastSeen(responseActionAgentRow.last_seen_at) : "-" },
              ]}
            />

            <InvestigationActionBar>
              <InvestigationActionButton
                onClick={() => {
                  setResponseActionMode("create");
                  setResponseActionTab("create");
                }}
                tone={responseActionMode === "create" ? "primary" : "default"}
              >
                Create action
              </InvestigationActionButton>
              <InvestigationActionButton
                onClick={() => {
                  setResponseActionMode("investigate");
                  if (responseActionTab === "create") {
                    setResponseActionTab(responseActionSelectedId ? "result" : "execution");
                  }
                }}
                tone={responseActionMode === "investigate" ? "primary" : "default"}
              >
                Investigate results
              </InvestigationActionButton>
              <InvestigationActionButton
                onClick={() => {
                  if (responseActionSelectedId) {
                    loadResponseActionLive(responseActionSelectedId);
                    loadResponseActionResult(responseActionSelectedId);
                  }
                  loadResponseActionHistory(responseActionAgentId);
                }}
              >
                Refresh action data
              </InvestigationActionButton>
              <InvestigationActionButton
                onClick={() => {
                  if (!responseActionResult) return;
                  setPinResponseResultId(responseActionResult.id);
                }}
                disabled={!responseActionResult}
                tone="primary"
              >
                Pin selected result
              </InvestigationActionButton>
            </InvestigationActionBar>

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

            {responseActionMode === "create" ? (
              <div className="space-y-4">
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
                      Payload is optional. Guided mode sends defaults from the server-side action schema.
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

                <div className="rounded-lg border border-border/60 bg-background/40 px-4 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="text-[11px] text-muted-foreground">Queue this request to start the execution lifecycle.</div>
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
                        Close
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
            ) : null}

            {responseActionMode === "investigate" ? (
              <>
                <InvestigationSection title="Investigation focus" subtitle="Inspect execution timeline and returned evidence.">
                  <InvestigationSummaryGrid>
                    <InvestigationFactCard
                      label="Selected action"
                      value={responseActionSelectedId ? `#${responseActionSelectedId}` : "-"}
                      mono
                    />
                    <InvestigationFactCard
                      label="Action type"
                      value={responseActionLiveView?.action_type || responseActionResult?.status || "-"}
                      mono
                    />
                    <InvestigationFactCard
                      label="Execution state"
                      value={responseActionLiveView?.status || responseActionResult?.status || "-"}
                      mono
                    />
                    <InvestigationFactCard
                      label="Requested at"
                      value={fmtMaybeIso(responseActionLiveView?.requested_at || null)}
                      mono
                    />
                    <InvestigationFactCard
                      label="Duration"
                      value={
                        responseActionResult
                          ? fmtDuration(responseActionResult.started_at, responseActionResult.finished_at)
                          : responseActionLiveView
                            ? fmtDuration(responseActionLiveView.started_at, responseActionLiveView.finished_at)
                            : "-"
                      }
                      mono
                    />
                    <InvestigationFactCard
                      label="Result payload keys"
                      value={String(Object.keys(responseActionResult?.result_payload || {}).length)}
                      mono
                    />
                  </InvestigationSummaryGrid>
                </InvestigationSection>

                <InvestigationTabs
                  value={responseActionTab === "result" ? "result" : "execution"}
                  onChange={(next) => {
                    setResponseActionTab(next);
                  }}
                  tabs={[
                    { key: "execution", label: "Execution" },
                    { key: "result", label: "Result" },
                  ]}
                />

                {responseActionTab === "execution" && (
              <div className="space-y-4">
                <Panel title="Live execution status" right={responseActionLiveLoading ? "Refreshing" : ""}>
                  <div className="space-y-4">
                    <div className="flex flex-wrap items-center gap-3">
                      <div className="min-w-[220px]">
                        <FieldLabel>Action instance</FieldLabel>
                        <select
                          className={inputClassName(responseActionBusy)}
                          value={responseActionSelectedId ? String(responseActionSelectedId) : ""}
                          onChange={(e) => onSelectResponseAction(Number(e.target.value) || 0, "execution")}
                          disabled={responseActionBusy || responseActionHistoryLoading || responseActionHistory.length === 0}
                        >
                          <option value="">Select action</option>
                          {responseActionHistory.map((x) => (
                            <option key={x.id} value={x.id}>
                              #{x.id} · {x.status}
                            </option>
                          ))}
                        </select>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          if (responseActionSelectedId) {
                            loadResponseActionLive(responseActionSelectedId);
                            loadResponseActionResult(responseActionSelectedId);
                          }
                          loadResponseActionHistory(responseActionAgentId);
                        }}
                        className={cx(
                          "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                          "hover:bg-primary/5"
                        )}
                      >
                        Refresh status
                      </button>
                    </div>

                    {responseActionLiveError && <div className="text-[11px] text-red-400">{responseActionLiveError}</div>}

                    {!responseActionLiveView ? (
                      <EmptyState title="No action selected" hint="Queue an action or select one from history." />
                    ) : (
                      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                        <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Current status</div>
                          <div className="mt-1 text-[12px] font-mono">{responseActionLiveView.status}</div>
                        </div>
                        <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Requested by</div>
                          <div className="mt-1 text-[12px] font-mono">{responseActionLiveView.requested_by || "-"}</div>
                        </div>
                        <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Requested at</div>
                          <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionLiveView.requested_at)}</div>
                        </div>
                        <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Delivered at</div>
                          <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionLiveView.delivered_at)}</div>
                        </div>
                        <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Started at</div>
                          <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionLiveView.started_at)}</div>
                        </div>
                        <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Finished at</div>
                          <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionLiveView.finished_at)}</div>
                        </div>
                        <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Duration</div>
                          <div className="mt-1 text-[12px] font-mono">
                            {fmtDuration(responseActionLiveView.started_at, responseActionLiveView.finished_at)}
                          </div>
                        </div>
                        <div className="rounded border border-border/60 bg-background/30 px-3 py-2 sm:col-span-2">
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Last error</div>
                          <div className="mt-1 text-[12px] font-mono break-words">{responseActionLiveView.last_error || "-"}</div>
                        </div>
                      </div>
                    )}

                    <div className="flex flex-wrap items-center gap-3">
                      <button
                        type="button"
                        onClick={onCancelSelectedResponseAction}
                        disabled={!responseActionSelectedId || !responseActionCanCancel || responseActionBusy}
                        className={cx(
                          "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                          "hover:bg-primary/5",
                          (!responseActionSelectedId || !responseActionCanCancel || responseActionBusy) && "opacity-60 cursor-not-allowed"
                        )}
                      >
                        {responseActionBusy ? "Working..." : "Cancel action"}
                      </button>
                      <button
                        type="button"
                        onClick={() => setResponseActionTab("result")}
                        disabled={!responseActionSelectedId}
                        className={cx(
                          "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                          "hover:bg-primary/5",
                          !responseActionSelectedId && "opacity-60 cursor-not-allowed"
                        )}
                      >
                        Open result viewer
                      </button>
                    </div>
                  </div>
                </Panel>
              </div>
                )}

                {responseActionTab === "result" && (
              <div className="space-y-4">
                <Panel title="Result viewer" right={responseActionResultLoading ? "Loading" : ""}>
                  <div className="space-y-4">
                    <div className="flex flex-wrap items-center gap-3">
                      <div className="min-w-[220px]">
                        <FieldLabel>Action instance</FieldLabel>
                        <select
                          className={inputClassName(responseActionBusy)}
                          value={responseActionSelectedId ? String(responseActionSelectedId) : ""}
                          onChange={(e) => onSelectResponseAction(Number(e.target.value) || 0)}
                          disabled={responseActionBusy || responseActionHistory.length === 0}
                        >
                          <option value="">Select action</option>
                          {responseActionHistory.map((x) => (
                            <option key={x.id} value={x.id}>
                              #{x.id} · {x.status}
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>

                    {responseActionResultError && <div className="text-[11px] text-red-400">{responseActionResultError}</div>}

                    {!responseActionResult ? (
                      <EmptyState title="Result unavailable" hint="This action has not reported a result yet." />
                    ) : (
                      <div className="space-y-3">
                        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                          <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Status</div>
                            <div className="mt-1 text-[12px] font-mono">{responseActionResult.status}</div>
                          </div>
                          <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Started</div>
                            <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionResult.started_at)}</div>
                          </div>
                          <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Finished</div>
                            <div className="mt-1 text-[12px] font-mono">{fmtMaybeIso(responseActionResult.finished_at)}</div>
                          </div>
                          <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Duration</div>
                            <div className="mt-1 text-[12px] font-mono">{fmtDuration(responseActionResult.started_at, responseActionResult.finished_at)}</div>
                          </div>
                        </div>

                        <div className="rounded border border-border/60 bg-background/30 px-3 py-2">
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Error</div>
                          <div className="mt-1 text-[12px] font-mono break-words">{responseActionResult.error || "-"}</div>
                        </div>

                        <div className="flex flex-wrap items-center gap-3">
                          <button
                            type="button"
                            onClick={onCopyResponseResultJson}
                            className={cx(
                              "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                              "hover:bg-primary/5"
                            )}
                          >
                            Copy JSON
                          </button>
                          <button
                            type="button"
                            onClick={onDownloadResponseResultJson}
                            className={cx(
                              "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                              "hover:bg-primary/5"
                            )}
                          >
                            Download result
                          </button>
                          <button
                            type="button"
                            onClick={() => setPinResponseResultId(responseActionResult.id)}
                            className={cx(
                              "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                              "hover:bg-primary/5"
                            )}
                          >
                            Pin to workspace
                          </button>
                          <button
                            type="button"
                            onClick={() => setResponseActionResultRawOpen((prev) => !prev)}
                            className={cx(
                              "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                              "hover:bg-primary/5"
                            )}
                          >
                            {responseActionResultRawOpen ? "Hide details" : "Open details"}
                          </button>
                        </div>

                        {responseActionResultRawOpen ? (
                          <InvestigationRawJsonPanel value={responseActionResult} title="Raw response result JSON" />
                        ) : null}
                      </div>
                    )}
                  </div>
                </Panel>
              </div>
                )}

                <Panel
              title="History"
              right={responseActionHistoryLoading ? "Loading" : responseActionHistory.length ? String(responseActionHistory.length) : "Empty"}
            >
              {responseActionHistoryError ? (
                <div className="text-[11px] text-red-400">{responseActionHistoryError}</div>
              ) : responseActionHistory.length === 0 ? (
                <div className="text-[12px] text-muted-foreground">No actions found for this agent.</div>
              ) : (
                <div className="space-y-2 max-h-[240px] overflow-y-auto pr-1">
                  {responseActionHistory.map((x) => {
                    const active = x.id === responseActionSelectedId;
                    return (
                      <button
                        key={x.id}
                        type="button"
                        onClick={() => onSelectResponseAction(x.id)}
                        className={cx(
                          "w-full rounded border px-3 py-2 text-left",
                          active ? "border-primary/60 bg-primary/10" : "border-border/60 bg-background/30 hover:bg-muted/10"
                        )}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <div className="text-[12px] font-mono">#{x.id} {x.action_type}</div>
                          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{x.status}</div>
                        </div>
                        <div className="mt-1 text-[11px] text-muted-foreground">requested {fmtMaybeIso(x.requested_at)}</div>
                      </button>
                    );
                  })}
                </div>
              )}
            </Panel>
              </>
            ) : null}

            <div className="rounded-lg border border-border/60 bg-background/40 px-4 py-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="text-[11px] text-muted-foreground">
                  Request, execution, and result are available in a single operator console.
                </div>
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
                  Close
                </button>
              </div>
            </div>
          </InvestigationShell>
        )}
      </Drawer>

      {pinResponseResultId && responseActionResult ? (
        <PinToWorkspaceDrawer
          open={Boolean(pinResponseResultId)}
          onClose={() => setPinResponseResultId(null)}
          title={`response result #${pinResponseResultId}`}
          defaultWorkspaceTitle={`Response action investigation · ${responseActionAgentId || "agent"}`}
          workspaceDefaults={{ primary_agent_id: responseActionResult.agent_id || undefined }}
          onPin={(workspaceId, options) =>
            pinResponseResultToWorkspace(workspaceId, pinResponseResultId, {
              ...options,
              source_module: "agents_response",
            })
          }
        />
      ) : null}

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
                          "w-full min-w-0 border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest text-center break-words",
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
