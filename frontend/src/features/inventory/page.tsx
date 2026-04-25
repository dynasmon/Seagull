import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import PageHeader from "@/shared/components/PageHeader";
import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import Drawer from "@/shared/components/Drawer";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { Table } from "@/shared/components/Table";
import { useDataTablePreferences } from "@/shared/hooks/useDataTablePreferences";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationFactCard,
  InvestigationKeyValueGrid,
  InvestigationMetaStrip,
  InvestigationRawJsonPanel,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  InvestigationTabs,
  copyTextToClipboard,
  safeJson,
} from "@/shared/components/investigation";
import { MetricCard } from "@/shared/components/MetricCard";
import { cx } from "@/shared/lib/cx";
import { isAbortError } from "@/shared/lib/http";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";
import PinToWorkspaceDrawer from "@/features/investigations/PinToWorkspaceDrawer";
import { pinInventorySnapshotToWorkspace } from "@/features/investigations/api";

import { useAgentsCatalog } from "@/app/providers";

import { SimpleTimeSeries } from "@/features/overview/components/Charts";
import { disableAgent, enableAgent, getAgent, setAgentConfig, updateAgent } from "@/features/agents/api";
import type { AgentDetail } from "@/features/agents/types";

import { getInventoryHistory, getInventoryLatest, getInventoryOverview } from "./api";
import type {
  FleetHealthRow,
  InventoryChangeRow,
  InventoryOverviewSnapshot,
  InventorySnapshotOut,
  InventoryWarningRow,
  PackageEntry
} from "./types";

type HygieneDomain = "dashboard" | "system" | "software" | "processes" | "network" | "identity" | "services";
const EMPTY_WARNING_ROWS: InventoryWarningRow[] = [];
const EMPTY_CHANGE_ROWS: InventoryChangeRow[] = [];
const EMPTY_FLEET_ROWS: FleetHealthRow[] = [];

const HYGIENE_TABS: Array<{ key: HygieneDomain; label: string }> = [
  { key: "dashboard", label: "Dashboard" },
  { key: "system", label: "System" },
  { key: "software", label: "Software" },
  { key: "processes", label: "Processes" },
  { key: "network", label: "Network" },
  { key: "identity", label: "Identity" },
  { key: "services", label: "Services" },
];

const DOMAIN_HINT: Record<HygieneDomain, string> = {
  dashboard: "Cross-agent hygiene baseline with fleet freshness and drift.",
  system: "Operating system posture, inventory freshness, and host baselines.",
  software: "Package manager distributions, package drift, and baseline deltas.",
  processes: "Process/runtime-oriented signals from inventory warnings and endpoint pivots.",
  network: "Endpoint network-facing inventory drift and warning pivots.",
  identity: "Identity and metadata hygiene with fast asset pivot controls.",
  services: "Service-level hygiene surfaced through warnings and inventory pivots.",
};

function fmtDateTime(iso?: string | null) {
  if (!iso) return "-";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const d = new Date(t);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function fmtMinutes(min?: number | null) {
  if (min === null || min === undefined || !Number.isFinite(min)) return "-";
  if (min < 1) return "< 1m";
  if (min < 60) return `${Math.round(min)}m`;
  const h = Math.floor(min / 60);
  const m = Math.round(min % 60);
  if (h < 24) return `${h}h ${String(m).padStart(2, "0")}m`;
  const d = Math.floor(h / 24);
  const hh = h % 24;
  return `${d}d ${hh}h`;
}

function normAgentId(v?: string | null) {
  const s = (v || "").trim();
  return s ? s : "__all";
}

function parsePositiveInt(v?: string | null): number | null {
  const raw = String(v || "").trim();
  if (!raw) return null;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.trunc(n);
}

function StatusBadge({ status }: { status: FleetHealthRow["inventory_status"] }) {
  const s = status;
  const klass =
    s === "fresh"
      ? "border-success/40 text-success bg-success/10"
      : s === "stale"
        ? "border-warning/40 text-warning bg-warning/10"
        : "border-danger/40 text-danger bg-danger/10";
  const label = s === "fresh" ? "fresh" : s === "stale" ? "stale" : "no inventory";
  return (
    <span className={cx("inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-mono uppercase", klass)}>
      {label}
    </span>
  );
}

function Section({ id, title, children, defaultOpen = true }: { id: string; title: string; children: any; defaultOpen?: boolean }) {
  const key = `nw_inventory_section_${id}`;
  const [open, setOpen] = useState(() => {
    try {
      const v = localStorage.getItem(key);
      if (v === null) return defaultOpen;
      return v === "1";
    } catch {
      return defaultOpen;
    }
  });

  function toggle() {
    setOpen((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(key, next ? "1" : "0");
      } catch {
        // no-op
      }
      return next;
    });
  }

  return (
    <div className="space-y-4">
      <button type="button" onClick={toggle} className="w-full flex items-center gap-3 text-left select-none">
        <span className="text-muted-foreground font-mono text-xs">{open ? "▾" : "▸"}</span>
        <span className="text-[11px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{title}</span>
        <div className="h-px bg-border/60 flex-1" />
      </button>
      {open ? <div className="space-y-4">{children}</div> : null}
    </div>
  );
}

function BarGaugeList({
  title,
  items,
  onPick,
  maxItems = 12,
  valueFormatter
}: {
  title: string;
  items: Array<{ metric: string; value: number }>;
  onPick?: (metric: string) => void;
  maxItems?: number;
  valueFormatter?: (v: number) => string;
}) {
  const sliced = items.slice(0, maxItems);
  const max = Math.max(1, ...sliced.map((i) => Number(i.value) || 0));

  return (
    <div className="space-y-3">
      <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{title}</div>

      <div className="space-y-2">
        {sliced.map((row) => {
          const pct = Math.max(0, Math.min(100, (row.value / max) * 100));
          const clickable = Boolean(onPick);
          return (
            <button
              key={row.metric}
              type="button"
              disabled={!clickable}
              onClick={() => onPick?.(row.metric)}
              className={cx(
                "w-full text-left rounded-md border border-border/60 bg-background/40 px-3 py-2",
                clickable ? "hover:bg-muted/10" : "cursor-default",
                "focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="truncate text-[11px] font-mono text-foreground">{row.metric}</div>
                <div className="shrink-0 text-[11px] font-mono text-muted-foreground">
                  {valueFormatter ? valueFormatter(row.value) : String(row.value)}
                </div>
              </div>
              <div className="mt-2 h-2 w-full rounded bg-muted/20 overflow-hidden">
                <div className="h-full bg-primary/60" style={{ width: `${pct}%` }} />
              </div>
            </button>
          );
        })}

        {sliced.length === 0 ? (
          <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2 text-[11px] text-muted-foreground">
            No data.
          </div>
        ) : null}
      </div>
    </div>
  );
}

function parseWarnings(extra: Record<string, any> | undefined | null): string[] {
  const e = extra || {};
  const w = e.warnings ?? e.warning;
  if (!w) return [];
  if (Array.isArray(w)) return w.map((x) => String(x)).filter(Boolean);
  if (typeof w === "string") return [w];
  return [JSON.stringify(w)];
}

function countish(value: any): number | null {
  if (Array.isArray(value)) return value.length;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (value && typeof value === "object") return Object.keys(value).length;
  return null;
}

function extractExtraDomainMetrics(extra: Record<string, any> | undefined | null): Array<{ key: string; value: string }> {
  const src = extra || {};
  const picks: Array<{ label: string; value: any }> = [
    { label: "processes", value: src.processes ?? src.runtime_processes ?? src.process_list },
    { label: "network_connections", value: src.network_connections ?? src.connections ?? src.net_connections },
    { label: "network_interfaces", value: src.network_interfaces ?? src.interfaces ?? src.net_ifaces },
    { label: "services", value: src.services ?? src.systemd_services ?? src.listening_services },
    { label: "users", value: src.users ?? src.identities ?? src.accounts },
    { label: "groups", value: src.groups ?? src.roles },
  ];

  return picks
    .map((item) => ({ key: item.label, n: countish(item.value) }))
    .filter((item) => item.n !== null)
    .map((item) => ({ key: item.key, value: String(item.n) }));
}

function normalizeTagsInput(value: string): string[] {
  const raw = value
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  // de-dup while keeping order
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

function safeJsonParse(value: string): { ok: true; data: any } | { ok: false; error: string } {
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

function filterPackages(packages: PackageEntry[], q: string) {
  const s = (q || "").trim().toLowerCase();
  if (!s) return packages;
  return packages.filter((p) => {
    const name = (p.name || "").toLowerCase();
    const ver = (p.version || "").toLowerCase();
    const arch = (p.arch || "").toLowerCase();
    return name.includes(s) || ver.includes(s) || arch.includes(s);
  });
}

function warningMatchesDomain(text: string, domain: HygieneDomain): boolean {
  const value = (text || "").toLowerCase();
  if (!value) return false;
  if (domain === "dashboard") return true;
  if (domain === "system") return /(kernel|os|hostname|platform|filesystem|uptime|hardware)/i.test(value);
  if (domain === "software") return /(package|version|manager|dependency|inventory|hash)/i.test(value);
  if (domain === "processes") return /(process|pid|runtime|command|exec|thread)/i.test(value);
  if (domain === "network") return /(network|interface|port|socket|route|dns|ip|tcp|udp)/i.test(value);
  if (domain === "identity") return /(identity|user|group|host|domain|role|tag|metadata|auth)/i.test(value);
  return /(service|daemon|listener|unit|systemd|http|ssh|agent)/i.test(value);
}

export default function InventoryPage() {
  const { agents } = useAgentsCatalog();
  const [sp, setSp] = useSearchParams();

  const urlAgentId = normAgentId(sp.get("agent_id"));
  const urlSnapshotId = parsePositiveInt(sp.get("snapshot_id"));
  const urlOpenDrawer = String(sp.get("open_drawer") || "").trim() === "1";
  const urlDomainRaw = String(sp.get("view") || "").trim().toLowerCase();
  const urlDomain = (HYGIENE_TABS.find((x) => x.key === urlDomainRaw)?.key || "dashboard") as HygieneDomain;

  const [agentScope, setAgentScope] = useState<string>(urlAgentId);
  const [domain, setDomain] = useState<HygieneDomain>(urlDomain);
  const [windowMinutes, setWindowMinutes] = useState<number>(() => {
    const w = Number(sp.get("window_minutes"));
    return Number.isFinite(w) && w >= 30 ? w : 360;
  });
  const inventoryTablePrefs = useDataTablePreferences({
    storageKey: "nw_inventory_tables_v2",
    defaultPageSize: 100,
    minPageSize: 25,
    maxPageSize: 200,
    defaultCompact: false,
  });
  const compactRows = inventoryTablePrefs.compact;

  // Keep local scope in sync with the URL when user navigates via sidebar.
  useEffect(() => {
    setAgentScope(urlAgentId);
  }, [urlAgentId]);

  useEffect(() => {
    setDomain(urlDomain);
  }, [urlDomain]);

  const [snapshot, setSnapshot] = useState<InventoryOverviewSnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshSeqRef = useRef(0);
  const refreshAbortRef = useRef<AbortController | null>(null);

  const refresh = useCallback(async () => {
    const mySeq = ++refreshSeqRef.current;
    refreshAbortRef.current?.abort();
    const controller = new AbortController();
    refreshAbortRef.current = controller;
    setBusy(true);

    try {
      const data = await getInventoryOverview(
        {
          window_minutes: windowMinutes,
          agent_id: agentScope
        },
        { signal: controller.signal, timeoutMs: 12000 }
      );
      if (refreshSeqRef.current !== mySeq) return;
      setSnapshot(data);
      setError(null);
    } catch (e: any) {
      if (isAbortError(e)) return;
      if (refreshSeqRef.current !== mySeq) return;
      setError(e?.message || "Failed to load inventory overview");
    } finally {
      if (refreshSeqRef.current === mySeq) {
        setBusy(false);
      }
      if (refreshAbortRef.current === controller) {
        refreshAbortRef.current = null;
      }
    }
  }, [agentScope, windowMinutes]);

  const live = useLiveRefresh({
    profile: windowMinutes > 24 * 60 ? "expensive-operational" : "operational",
    refresh,
  });

  useEffect(() => {
    live.invalidate("dependency", { immediate: true, supersede: true });
  }, [agentScope, live.invalidate, windowMinutes]);

  usePortalRealtimeSubscription("ui.inventory.invalidate", (event) => {
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    if (agentScope !== "__all" && eventAgentId && eventAgentId !== agentScope) return;
    live.invalidate();
  });

  usePortalRealtimeSubscription("ui.agents.invalidate", () => {
    live.invalidate();
  });

  usePortalRealtimeSubscription("ui.agents.presence.patch", (event) => {
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    if (agentScope !== "__all" && eventAgentId && eventAgentId !== agentScope) return;
    live.invalidate();
  });

  useEffect(() => {
    return () => {
      refreshAbortRef.current?.abort();
    };
  }, []);

  function pushUrl(nextAgent: string, nextWindow?: number, nextDomain?: HygieneDomain) {
    const next = new URLSearchParams(sp);

    const agent = normAgentId(nextAgent);
    if (agent && agent !== "__all") next.set("agent_id", agent);
    else next.delete("agent_id");
    next.delete("snapshot_id");
    next.delete("open_drawer");

    const w = nextWindow ?? windowMinutes;
    if (Number.isFinite(w)) next.set("window_minutes", String(w));
    const view = nextDomain || domain;
    if (view === "dashboard") next.delete("view");
    else next.set("view", view);

    setSp(next, { replace: true });
  }

  // -----------------------------
  // Drawer state
  // -----------------------------
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerAgentId, setDrawerAgentId] = useState<string | null>(null);
  const [drawerTab, setDrawerTab] = useState<"overview" | "snapshot" | "history" | "packages" | "configuration">("overview");
  const [drawerCopied, setDrawerCopied] = useState<null | "ok" | "fail">(null);

  const [drawerAgent, setDrawerAgent] = useState<AgentDetail | null>(null);
  const [drawerLatest, setDrawerLatest] = useState<InventorySnapshotOut | null>(null);
  const [drawerHistory, setDrawerHistory] = useState<InventorySnapshotOut[]>([]);
  const [drawerErr, setDrawerErr] = useState<string | null>(null);
  const [drawerBusy, setDrawerBusy] = useState(false);
  const [pinSnapshotId, setPinSnapshotId] = useState<number | null>(null);
  const [focusedSnapshotId, setFocusedSnapshotId] = useState<number | null>(null);
  const deepLinkHandledRef = useRef<string | null>(null);

  // editable state
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editTags, setEditTags] = useState("");
  const [editConfig, setEditConfig] = useState("{}");
  const [editMsg, setEditMsg] = useState<string | null>(null);

  const [pkgQuery, setPkgQuery] = useState("");

  const openDrawer = useCallback(async (agentId: string, focusSnapshotId?: number | null) => {
    const id = (agentId || "").trim();
    if (!id) return;

    setDrawerOpen(true);
    setDrawerAgentId(id);
    setDrawerTab("overview");
    setDrawerErr(null);
    setEditMsg(null);
    setDrawerCopied(null);
    setPkgQuery("");

    setDrawerBusy(true);
    try {
      const [a, latest, hist] = await Promise.all([
        getAgent(id),
        getInventoryLatest(id).catch(() => null),
        getInventoryHistory(id, { limit: 20 }).catch(() => [])
      ]);

      setDrawerAgent(a);
      setDrawerLatest(latest);
      setDrawerHistory(hist);
      setFocusedSnapshotId(typeof focusSnapshotId === "number" ? focusSnapshotId : null);

      setEditName(a.display_name || "");
      setEditDesc(a.description || "");
      setEditTags((a.tags || []).join(", "));
      setEditConfig(JSON.stringify(a.config || {}, null, 2));
    } catch (e: any) {
      setDrawerErr(e?.message || "Failed to load agent details");
    } finally {
      setDrawerBusy(false);
    }
  }, []);

  useEffect(() => {
    if (urlAgentId === "__all") return;
    if (!urlSnapshotId && !urlOpenDrawer) return;
    const key = `${urlAgentId}:${urlSnapshotId || ""}:${urlOpenDrawer ? "1" : "0"}`;
    if (deepLinkHandledRef.current === key) return;
    deepLinkHandledRef.current = key;
    openDrawer(urlAgentId, urlSnapshotId);
  }, [urlAgentId, urlSnapshotId, urlOpenDrawer, openDrawer]);

  function closeDrawer() {
    setDrawerOpen(false);
    setDrawerAgentId(null);
    setDrawerAgent(null);
    setDrawerLatest(null);
    setDrawerHistory([]);
    setDrawerErr(null);
    setEditMsg(null);
    setFocusedSnapshotId(null);
    setDrawerCopied(null);
  }

  const agentsOptions = useMemo(() => {
    const rows = [...agents];
    rows.sort((a, b) => {
      const an = (a.display_name || "").trim().toLowerCase();
      const bn = (b.display_name || "").trim().toLowerCase();
      if (an && bn && an !== bn) return an.localeCompare(bn);
      if (an && !bn) return -1;
      if (!an && bn) return 1;
      return a.agent_id.localeCompare(b.agent_id);
    });
    return rows;
  }, [agents]);

  const toolbarRight = (
    <div className="flex items-center gap-3">
      <Button
        variant="subtle"
        size="lg"
        onClick={() => inventoryTablePrefs.setCompact(!compactRows)}
      >
        {compactRows ? "Compact rows" : "Comfortable rows"}
      </Button>
      <div className="hidden md:block text-[11px] font-mono text-muted-foreground">
        {live.state.lastUpdatedAt ? `Updated ${fmtDateTime(live.state.lastUpdatedAt.toISOString())}` : ""}
      </div>

      <Button
        variant="subtle"
        size="lg"
        onClick={live.refreshNow}
        disabled={busy}
      >
        Refresh
      </Button>
    </div>
  );

  const scopeLabel = useMemo(() => {
    if (agentScope === "__all") return "All agents";
    const found = agentsOptions.find((a) => a.agent_id === agentScope);
    if (!found) return agentScope;
    return found.display_name ? `${found.display_name} (${found.agent_id})` : found.agent_id;
  }, [agentScope, agentsOptions]);

  const osRows = snapshot?.os_distribution || [];
  const mgrRows = snapshot?.manager_distribution || [];

  const osTable =
    osRows.length === 0 ? (
      <EmptyState title="NO DATA" hint="No OS distribution available in the current window." />
    ) : (
      <Table
        compact={compactRows}
        columns={[
          { key: "os", title: "OS", className: "font-mono text-foreground" },
          { key: "agents", title: "AGENTS", className: "text-right font-mono text-muted-foreground w-24" }
        ]}
        rows={osRows}
        rowKey={(r) => r.os}
      />
    );

  const mgrTable =
    mgrRows.length === 0 ? (
      <EmptyState title="NO DATA" hint="No package manager distribution available in the current window." />
    ) : (
      <Table
        compact={compactRows}
        columns={[
          { key: "manager", title: "MANAGER", className: "font-mono text-foreground" },
          { key: "agents", title: "AGENTS", className: "text-right font-mono text-muted-foreground w-24" }
        ]}
        rows={mgrRows}
        rowKey={(r) => r.manager}
      />
    );

  const warningsRows: InventoryWarningRow[] = snapshot?.recent_warnings ?? EMPTY_WARNING_ROWS;
  const changesRows: InventoryChangeRow[] = snapshot?.recent_changes ?? EMPTY_CHANGE_ROWS;
  const fleetRows: FleetHealthRow[] = snapshot?.fleet_health ?? EMPTY_FLEET_ROWS;
  const domainWarnings = useMemo(
    () => warningsRows.filter((w) => warningMatchesDomain(w.warning || "", domain)).slice(0, 12),
    [warningsRows, domain]
  );
  const domainPivotRows = useMemo(() => {
    const rows = [...fleetRows];
    if (domain === "software") {
      rows.sort((a, b) => (b.packages_count || 0) - (a.packages_count || 0));
      return rows.slice(0, 12);
    }
    if (domain === "processes" || domain === "services") {
      rows.sort((a, b) => b.warnings_count - a.warnings_count);
      return rows.slice(0, 12);
    }
    if (domain === "network") {
      rows.sort((a, b) => {
        const av = (a.inventory_age_min ?? 999999) + (a.warnings_count || 0) * 30;
        const bv = (b.inventory_age_min ?? 999999) + (b.warnings_count || 0) * 30;
        return bv - av;
      });
      return rows.slice(0, 12);
    }
    return rows.slice(0, 12);
  }, [fleetRows, domain]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Inventory"
        breadcrumb={["Assets"]}
        description={
          <span>
            IT hygiene workspace across assets, software, runtime, and service posture. Click any agent row to open the inspector drawer.
          </span>
        }
        toolbarRight={toolbarRight}
      />

      <div className="ui-tab-shell px-1 pb-2">
        {HYGIENE_TABS.map((tab) => {
          const active = domain === tab.key;
          return (
            <button
              key={tab.key}
              type="button"
              onClick={() => {
                setDomain(tab.key);
                pushUrl(agentScope, windowMinutes, tab.key);
              }}
              className={cx("ui-tab-item", active && "ui-tab-item-active")}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
      <Panel title={`${HYGIENE_TABS.find((x) => x.key === domain)?.label || "Dashboard"} view`} className="min-h-[100px]">
        <div className="grid gap-3 md:grid-cols-2">
          <div className="text-[12px] text-muted-foreground">{DOMAIN_HINT[domain]}</div>
          <div className="text-[12px] text-muted-foreground">
            Scope <span className="font-mono text-foreground">{scopeLabel}</span> · window{" "}
            <span className="font-mono text-foreground">{windowMinutes}m</span>
          </div>
        </div>
      </Panel>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Panel title="Scope" className="lg:col-span-1">
          <div className="space-y-4">
            <div>
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Agent</div>
              <SelectInput
                value={agentScope}
                onChange={(e) => {
                  const v = normAgentId(e.target.value);
                  setAgentScope(v);
                  pushUrl(v);
                }}
                className="mt-1 w-full text-[11px] font-mono"
              >
                <option value="__all">All agents</option>
                {agentsOptions.map((a) => (
                  <option key={a.agent_id} value={a.agent_id}>
                    {a.display_name ? a.display_name : a.agent_id}
                  </option>
                ))}
              </SelectInput>
              <div className="mt-2 text-[11px] font-mono text-muted-foreground">
                Current scope: <span className="text-foreground/90">{scopeLabel}</span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Window (min)</div>
                <DraftNumberInput
                  value={windowMinutes}
                  min={30}
                  max={10080}
                  fallback={360}
                  onCommit={(safe) => {
                    setWindowMinutes(safe);
                    pushUrl(agentScope, safe);
                  }}
                  className={cx(
                    "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                    "text-[11px] text-foreground outline-none font-mono",
                    "focus:ring-2 focus:ring-primary/30"
                  )}
                  title="Lookback window (minutes)"
                />
              </div>

              <div>
                <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Auto-refresh</div>
                <div className="mt-1 rounded-md border border-border/60 bg-background/30 px-3 py-2 text-[11px] font-mono text-muted-foreground">
                  {Math.round(live.state.profile.fallbackMs / 1000)}s shared fallback
                </div>
              </div>
            </div>

            {error ? (
              <div className="rounded-md border border-border/60 bg-background/20 px-3 py-2 text-[11px] text-muted-foreground">
                {error}
              </div>
            ) : null}
          </div>
        </Panel>

        <Panel title="KPIs" className="lg:col-span-2">
          {!snapshot && busy ? (
            <Loading label="Loading inventory overview..." />
          ) : snapshot ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
              <MetricCard title="Agents" value={snapshot.kpis.agents_total} helper="Registered endpoints" />
              <MetricCard title="Online (5m)" value={snapshot.kpis.agents_online_5m} helper="Last seen <= 5 minutes" />
              <MetricCard title="With inventory (6h)" value={snapshot.kpis.agents_with_inventory_6h} helper="Any snapshot in the last 6 hours" />
              <MetricCard
                title="Oldest inventory"
                value={fmtMinutes(snapshot.kpis.oldest_inventory_age_minutes)}
                helper="Max age across latest snapshots"
              />
            </div>
          ) : (
            <EmptyState title="No data" hint="No inventory telemetry yet." />
          )}
        </Panel>
      </div>

      {(domain === "processes" || domain === "network" || domain === "identity" || domain === "services") ? (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <Panel title={`${HYGIENE_TABS.find((x) => x.key === domain)?.label || "Domain"} warning pivots`} scrollY className="min-h-[360px]">
            {domainWarnings.length === 0 ? (
              <EmptyState title="No domain-specific warnings" hint="Try a wider lookback window or scope all agents." />
            ) : (
              <Table
                compact={compactRows}
                className="text-xs"
                columns={[
                  {
                    key: "time",
                    title: "TIME",
                    className: "w-40 font-mono text-muted-foreground",
                    render: (r: InventoryWarningRow) => fmtDateTime(r.time),
                  },
                  {
                    key: "agent_id",
                    title: "AGENT",
                    className: "w-52 font-mono text-foreground",
                    render: (r: InventoryWarningRow) => (
                      <button
                        type="button"
                        onClick={() => openDrawer(r.agent_id)}
                        className="text-left font-mono text-[11px] text-primary/90 underline-offset-4 hover:underline"
                      >
                        {r.agent_id}
                      </button>
                    )
                  },
                  {
                    key: "warning",
                    title: "WARNING",
                    className: "text-muted-foreground",
                    render: (r: InventoryWarningRow) => <div className="max-w-[540px] truncate" title={r.warning}>{r.warning}</div>,
                  }
                ]}
                rows={domainWarnings}
                rowKey={(r, i) => `${r.time || "na"}-${r.agent_id}-${i}`}
              />
            )}
          </Panel>

          <Panel
            title="Asset pivots"
            actions={<span className="text-[10px] font-mono text-muted-foreground">{domainPivotRows.length} agents</span>}
            scrollY
            className="min-h-[360px]"
          >
            {domainPivotRows.length === 0 ? (
              <EmptyState title="No assets" hint="No assets available for this scope." />
            ) : (
              <Table
                compact={compactRows}
                className="text-xs"
                columns={[
                  {
                    key: "agent_id",
                    title: "AGENT",
                    className: "font-mono text-foreground w-56",
                    render: (r: FleetHealthRow) => (
                      <button
                        type="button"
                        onClick={() => openDrawer(r.agent_id)}
                        className="text-left font-mono text-[11px] text-primary/90 underline-offset-4 hover:underline"
                      >
                        {r.agent_id}
                      </button>
                    )
                  },
                  {
                    key: "inventory_status",
                    title: "INVENTORY",
                    className: "w-28",
                    render: (r: FleetHealthRow) => <StatusBadge status={r.inventory_status} />
                  },
                  {
                    key: "packages_count",
                    title: "PKGS",
                    className: "text-right font-mono text-muted-foreground w-20",
                    render: (r: FleetHealthRow) => (r.packages_count ?? "-")
                  },
                  {
                    key: "warnings_count",
                    title: "WARN",
                    className: "text-right font-mono text-muted-foreground w-20",
                    render: (r: FleetHealthRow) => r.warnings_count
                  },
                ]}
                rows={domainPivotRows}
                rowKey={(r) => r.agent_id}
              />
            )}
          </Panel>
        </div>
      ) : null}

      {(domain === "dashboard" || domain === "system" || domain === "software") ? (
      <Section id="timeseries" title="Activity" defaultOpen>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Panel title="Inventory snapshots / minute" actions={<span className="text-[10px] font-mono text-muted-foreground">{windowMinutes}m window</span>} className="min-h-[420px]">
            {snapshot ? (
              <SimpleTimeSeries
                data={snapshot.snapshots_per_minute.data}
                seriesKeys={snapshot.snapshots_per_minute.series}
                height={320}
                minWidth={720}
              />
            ) : busy ? (
              <Loading />
            ) : (
              <EmptyState title="No data" />
            )}
          </Panel>

          <Panel title="Inventory changes / 10m" actions={<span className="text-[10px] font-mono text-muted-foreground">packages_hash delta</span>} className="min-h-[420px]">
            {snapshot ? (
              <SimpleTimeSeries
                data={snapshot.changes_per_10m.data}
                seriesKeys={snapshot.changes_per_10m.series}
                height={320}
                minWidth={720}
              />
            ) : busy ? (
              <Loading />
            ) : (
              <EmptyState title="No data" />
            )}
          </Panel>
        </div>
      </Section>
      ) : null}

      {(domain === "dashboard" || domain === "system" || domain === "software") ? (
      <Section id="distribution" title="Distributions" defaultOpen>
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <Panel title="OS distribution" scrollY className="min-h-[420px]">
            {snapshot ? osTable : busy ? <Loading /> : <EmptyState title="No data" />}
          </Panel>

          <Panel title="Package manager distribution" scrollY className="min-h-[420px]">
            {snapshot ? mgrTable : busy ? <Loading /> : <EmptyState title="No data" />}
          </Panel>

          <Panel title="Top agents" className="min-h-[420px]">
            {snapshot ? (
              <div className="space-y-6">
                <BarGaugeList
                  title="Inventory age (minutes)"
                  items={snapshot.inventory_age_by_agent}
                  onPick={(id) => openDrawer(id)}
                  valueFormatter={(v) => fmtMinutes(v)}
                />

                <div className="h-px bg-border/60" />

                <BarGaugeList
                  title="Packages count"
                  items={snapshot.packages_count_by_agent}
                  onPick={(id) => openDrawer(id)}
                  valueFormatter={(v) => `${v}`}
                />
              </div>
            ) : busy ? (
              <Loading />
            ) : (
              <EmptyState title="No data" />
            )}
          </Panel>
        </div>
      </Section>
      ) : null}

      {(domain === "dashboard" || domain === "system" || domain === "network" || domain === "identity" || domain === "services") ? (
      <Section id="fleet" title="Fleet health" defaultOpen>
        <Panel
          title="Fleet health"
          actions={snapshot ? <span className="text-[10px] font-mono text-muted-foreground">{fleetRows.length} agents</span> : undefined}
          scrollY
          className="min-h-[520px]"
        >
          {snapshot ? (
            fleetRows.length === 0 ? (
              <EmptyState title="NO AGENTS" hint="No agent inventory data available for the current scope." />
            ) : (
              <Table
                compact={compactRows}
                scrollX={false}
                className="text-xs"
                columns={[
                  {
                    key: "agent_id",
                    title: "AGENT",
                    className: "font-mono text-foreground w-56",
                    render: (r: FleetHealthRow) => (
                      <button
                        type="button"
                        onClick={() => openDrawer(r.agent_id)}
                        className={cx(
                          "text-left font-mono text-[11px] text-primary/90 underline-offset-4 hover:underline",
                          "focus:outline-none focus:ring-2 focus:ring-primary/30"
                        )}
                      >
                        {r.agent_id}
                      </button>
                    )
                  },
                  {
                    key: "inventory_status",
                    title: "INVENTORY",
                    className: "w-28",
                    render: (r: FleetHealthRow) => <StatusBadge status={r.inventory_status} />
                  },
                  {
                    key: "inventory_age_min",
                    title: "INV AGE",
                    className: "text-right font-mono text-muted-foreground w-24",
                    render: (r: FleetHealthRow) => fmtMinutes(r.inventory_age_min)
                  },
                  {
                    key: "last_seen_age_min",
                    title: "SEEN",
                    className: "text-right font-mono text-muted-foreground w-24",
                    render: (r: FleetHealthRow) => fmtMinutes(r.last_seen_age_min)
                  },
                  { key: "os", title: "OS", className: "font-mono text-foreground" },
                  { key: "manager", title: "MGR", className: "font-mono text-muted-foreground w-24" },
                  {
                    key: "packages_count",
                    title: "PKGS",
                    className: "text-right font-mono text-muted-foreground w-20",
                    render: (r: FleetHealthRow) => (r.packages_count ?? "-")
                  },
                  {
                    key: "warnings_count",
                    title: "WARN",
                    className: "text-right font-mono text-muted-foreground w-20",
                    render: (r: FleetHealthRow) => r.warnings_count
                  }
                ]}
                rows={fleetRows}
                rowKey={(r) => r.agent_id}
              />
            )
          ) : busy ? (
            <Loading />
          ) : (
            <EmptyState title="No data" />
          )}
        </Panel>
      </Section>
      ) : null}

      {(domain === "dashboard" || domain === "software" || domain === "processes" || domain === "network" || domain === "services") ? (
      <Section id="changes" title="Recent changes & warnings" defaultOpen={false}>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Panel title="Recent inventory changes" scrollY className="min-h-[520px]">
            {snapshot ? (
              changesRows.length === 0 ? (
                <EmptyState title="NO CHANGES" hint="No inventory baselines/changes in the current window." />
              ) : (
                <Table
                  compact={compactRows}
                  scrollX={false}
                  className="text-xs"
                  columns={[
                    {
                      key: "time",
                      title: "TIME",
                      className: "font-mono text-muted-foreground w-40",
                      render: (r: InventoryChangeRow) => fmtDateTime(r.time)
                    },
                    {
                      key: "agent_id",
                      title: "AGENT",
                      className: "font-mono text-foreground w-56",
                      render: (r: InventoryChangeRow) => (
                        <button
                          type="button"
                          onClick={() => openDrawer(r.agent_id)}
                          className={cx(
                            "text-left font-mono text-[11px] text-primary/90 underline-offset-4 hover:underline",
                            "focus:outline-none focus:ring-2 focus:ring-primary/30"
                          )}
                        >
                          {r.agent_id}
                        </button>
                      )
                    },
                    {
                      key: "change_type",
                      title: "TYPE",
                      className: "font-mono text-muted-foreground w-24",
                      render: (r: InventoryChangeRow) => r.change_type
                    },
                    {
                      key: "delta",
                      title: "Δ PKGS",
                      className: "text-right font-mono text-muted-foreground w-20",
                      render: (r: InventoryChangeRow) => {
                        if (r.old_count === null || r.old_count === undefined) return "-";
                        const oldN = Number(r.old_count ?? 0);
                        const newN = Number(r.new_count ?? 0);
                        return `${newN - oldN}`;
                      }
                    }
                  ]}
                  rows={changesRows}
                  rowKey={(r, i) => `${r.time || "na"}-${r.agent_id}-${i}`}
                />
              )
            ) : busy ? (
              <Loading />
            ) : (
              <EmptyState title="No data" />
            )}
          </Panel>

          <Panel title="Recent inventory warnings" scrollY className="min-h-[520px]">
            {snapshot ? (
              warningsRows.length === 0 ? (
                <EmptyState title="NO WARNINGS" hint="No inventory warnings in the current window." />
              ) : (
                <Table
                  compact={compactRows}
                  scrollX={false}
                  className="text-xs"
                  columns={[
                    {
                      key: "time",
                      title: "TIME",
                      className: "font-mono text-muted-foreground w-40",
                      render: (r: InventoryWarningRow) => fmtDateTime(r.time)
                    },
                    {
                      key: "agent_id",
                      title: "AGENT",
                      className: "font-mono text-foreground w-56",
                      render: (r: InventoryWarningRow) => (
                        <button
                          type="button"
                          onClick={() => openDrawer(r.agent_id)}
                          className={cx(
                            "text-left font-mono text-[11px] text-primary/90 underline-offset-4 hover:underline",
                            "focus:outline-none focus:ring-2 focus:ring-primary/30"
                          )}
                        >
                          {r.agent_id}
                        </button>
                      )
                    },
                    {
                      key: "warning",
                      title: "WARNING",
                      className: "font-mono text-muted-foreground",
                      render: (r: InventoryWarningRow) => (
                        <div className="max-w-[520px] whitespace-pre-wrap break-words text-[11px] text-muted-foreground">
                          {r.warning}
                        </div>
                      )
                    }
                  ]}
                  rows={warningsRows}
                  rowKey={(r, i) => `${r.time || "na"}-${r.agent_id}-${i}`}
                />
              )
            ) : busy ? (
              <Loading />
            ) : (
              <EmptyState title="No data" />
            )}
          </Panel>
        </div>
      </Section>
      ) : null}

      {/* Drawer Inspector */}
      <Drawer
        open={drawerOpen}
        title={drawerAgentId ? `Agent inventory · ${drawerAgentId}` : "Agent inventory"}
        description="Investigation-first inventory context with configuration controls."
        onClose={closeDrawer}
        widthClassName="w-[1140px]"
      >
        <InvestigationShell>
          {drawerBusy ? <Loading label="Loading agent..." /> : null}

          {drawerErr ? (
            <div className="rounded-md border border-danger/50 bg-danger/10 px-4 py-3 text-sm text-danger">
              {drawerErr}
            </div>
          ) : null}

          {drawerAgent ? (
            <>
              <InvestigationMetaStrip
                items={[
                  { label: "Agent", value: drawerAgent.display_name || drawerAgent.agent_id, variant: "info" },
                  { label: "Agent ID", value: drawerAgent.agent_id },
                  { label: "Last seen", value: fmtDateTime(drawerAgent.last_seen_at) },
                  { label: "State", value: drawerAgent.is_revoked ? "disabled" : "active", variant: drawerAgent.is_revoked ? "neutral" : "low" },
                  { label: "Latest snapshot", value: drawerLatest ? fmtDateTime(drawerLatest.collected_at) : "none" },
                ]}
              />

              <InvestigationActionBar>
                <InvestigationActionButton
                  onClick={() => {
                    if (!drawerLatest) return;
                    setPinSnapshotId(drawerLatest.id);
                  }}
                  disabled={!drawerLatest}
                  tone="primary"
                >
                  Pin latest snapshot
                </InvestigationActionButton>
                <InvestigationActionButton
                  onClick={async () => {
                    const payload = {
                      agent: drawerAgent,
                      latest_snapshot: drawerLatest,
                      recent_history: drawerHistory.slice(0, 20),
                    };
                    const ok = await copyTextToClipboard(safeJson(payload));
                    setDrawerCopied(ok ? "ok" : "fail");
                    window.setTimeout(() => setDrawerCopied(null), 1200);
                  }}
                >
                  {drawerCopied === "ok" ? "Copied" : drawerCopied === "fail" ? "Copy failed" : "Copy context JSON"}
                </InvestigationActionButton>
                <InvestigationActionButton
                  onClick={() => {
                    const sp = new URLSearchParams();
                    sp.set("agent_id", drawerAgent.agent_id);
                    sp.set("window_minutes", String(windowMinutes));
                    if (domain !== "dashboard") sp.set("view", domain);
                    setSp(sp, { replace: false });
                  }}
                >
                  Scope inventory view
                </InvestigationActionButton>
              </InvestigationActionBar>

              <InvestigationTabs
                value={drawerTab}
                onChange={setDrawerTab}
                tabs={[
                  { key: "overview", label: "Dashboard" },
                  { key: "snapshot", label: "System" },
                  { key: "history", label: "Software timeline" },
                  { key: "packages", label: "Software packages" },
                  { key: "configuration", label: "Identity & controls" },
                ]}
              />

              {drawerTab === "overview" ? (
                <InvestigationSection title="Inventory overview" subtitle="Quick health and baseline context for this endpoint.">
                  <InvestigationSummaryGrid>
                    <InvestigationFactCard label="Display name" value={drawerAgent.display_name || "-"} mono />
                    <InvestigationFactCard label="Description" value={drawerAgent.description || "-"} />
                    <InvestigationFactCard label="Tags" value={drawerAgent.tags.length ? drawerAgent.tags.join(", ") : "-"} mono />
                    <InvestigationFactCard label="Last seen" value={fmtDateTime(drawerAgent.last_seen_at)} mono />
                    <InvestigationFactCard
                      label="Snapshot manager"
                      value={drawerLatest?.manager || "-"}
                      mono
                    />
                    <InvestigationFactCard
                      label="Package count"
                      value={drawerLatest ? String(drawerLatest.packages_count) : "-"}
                      mono
                    />
                  </InvestigationSummaryGrid>

                  <div className="mt-4">
                    <InvestigationKeyValueGrid
                      entries={[
                        ...extractExtraDomainMetrics(drawerLatest?.extra || {}).map((m) => ({ key: m.key, value: m.value })),
                        ...parseWarnings(drawerLatest?.extra || {}).slice(0, 8).map((w, idx) => ({
                          key: `warning_${idx + 1}`,
                          value: w,
                        })),
                      ]}
                    />
                  </div>
                </InvestigationSection>
              ) : null}

              {drawerTab === "snapshot" ? (
                !drawerLatest ? (
                  <EmptyState title="No snapshot" hint="No inventory snapshot for this agent." />
                ) : (
                  <div className="space-y-4">
                    <InvestigationSection title="Latest snapshot details">
                      <InvestigationSummaryGrid>
                        <InvestigationFactCard
                          label="Collected"
                          value={fmtDateTime(drawerLatest.collected_at)}
                          mono
                        />
                        <InvestigationFactCard label="Manager" value={drawerLatest.manager || "-"} mono />
                        <InvestigationFactCard label="Schema" value={String(drawerLatest.schema_version)} mono />
                        <InvestigationFactCard label="Packages hash" value={drawerLatest.packages_hash || "-"} mono />
                        <InvestigationFactCard label="Packages count" value={String(drawerLatest.packages_count)} mono />
                        <InvestigationFactCard
                          label="OS"
                          value={drawerLatest.os?.pretty_name || drawerLatest.os?.name || drawerLatest.os?.id || "unknown"}
                          mono
                        />
                      </InvestigationSummaryGrid>
                    </InvestigationSection>

                    <InvestigationSection title="Domain evidence">
                      {(() => {
                        const extra = drawerLatest.extra || {};
                        const entries = [
                          { key: "processes", value: extra.processes ?? extra.runtime_processes ?? extra.process_list },
                          { key: "network", value: extra.network_connections ?? extra.connections ?? extra.network_interfaces ?? extra.interfaces },
                          { key: "services", value: extra.services ?? extra.systemd_services ?? extra.listening_services },
                          { key: "identity", value: extra.users ?? extra.identities ?? extra.accounts ?? extra.groups },
                        ].filter((x) => x.value !== undefined);

                        if (entries.length === 0) {
                          return <EmptyState title="No domain evidence" hint="This snapshot did not include process/network/service/identity extras." />;
                        }

                        return (
                          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                            {entries.map((entry) => (
                              <div key={entry.key} className="rounded-md border border-border/60 bg-background/30 p-3">
                                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{entry.key}</div>
                                <pre className="mt-2 max-h-[220px] overflow-auto text-[11px] text-muted-foreground whitespace-pre-wrap break-words">
                                  {safeJson(entry.value)}
                                </pre>
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </InvestigationSection>

                    <InvestigationRawJsonPanel value={drawerLatest} title="Raw snapshot JSON" />
                  </div>
                )
              ) : null}

              {drawerTab === "history" ? (
                <InvestigationSection title="Recent snapshots" subtitle="Track package hash drift and pin relevant baseline states.">
                  <div className="overflow-hidden rounded-lg border border-border/60">
                    <table className={cx("w-full", compactRows ? "text-xs" : "text-sm")}>
                      <thead className="bg-muted/10">
                        <tr className="text-[10px] uppercase tracking-widest font-mono text-muted-foreground">
                          <th className="text-left px-3 py-2">Collected</th>
                          <th className="text-right px-3 py-2">Packages</th>
                          <th className="text-right px-3 py-2">Changed</th>
                          <th className="text-right px-3 py-2">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/60">
                        {drawerHistory.slice(0, 20).map((s, idx) => {
                          const next = drawerHistory[idx + 1];
                          const changed = next ? s.packages_hash !== next.packages_hash : false;
                          return (
                            <tr
                              key={s.id}
                              className={cx("text-[11px] font-mono", focusedSnapshotId === s.id && "bg-primary/10")}
                            >
                              <td className="px-3 py-2 text-muted-foreground">{fmtDateTime(s.collected_at)}</td>
                              <td className="px-3 py-2 text-right text-muted-foreground">{s.packages_count}</td>
                              <td className="px-3 py-2 text-right">
                                <span
                                  className={cx(
                                    "inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] uppercase",
                                    changed
                                      ? "border-warning/40 text-warning bg-warning/10"
                                      : "border-border/60 text-muted-foreground bg-muted/10",
                                  )}
                                >
                                  {changed ? "yes" : "no"}
                                </span>
                              </td>
                              <td className="px-3 py-2 text-right">
                                <div className="flex items-center justify-end gap-2">
                                  <button
                                    type="button"
                                    onClick={() => setFocusedSnapshotId(s.id)}
                                    className={cx(
                                      "rounded-md border border-border/60 bg-background/40 px-2 py-1",
                                      "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                                      "hover:bg-muted/15 hover:text-foreground",
                                    )}
                                  >
                                    Focus
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => setPinSnapshotId(s.id)}
                                    className={cx(
                                      "rounded-md border border-border/60 bg-background/40 px-2 py-1",
                                      "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                                      "hover:bg-muted/15 hover:text-foreground",
                                      focusedSnapshotId === s.id && "border-primary/40 text-foreground",
                                    )}
                                  >
                                    Pin
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                        {drawerHistory.length === 0 ? (
                          <tr>
                            <td className="px-3 py-3 text-[11px] text-muted-foreground" colSpan={4}>
                              No history.
                            </td>
                          </tr>
                        ) : null}
                      </tbody>
                    </table>
                  </div>
                </InvestigationSection>
              ) : null}

              {drawerTab === "packages" ? (
                <InvestigationSection title="Package evidence" subtitle="Search the latest package list without leaving the drawer.">
                  {!drawerLatest ? (
                    <EmptyState title="No snapshot" hint="No package list available." />
                  ) : (
                    <div className="space-y-3">
                      <div className="flex items-end justify-between gap-3">
                        <div className="text-[11px] text-muted-foreground">
                          Showing up to 200 entries from latest snapshot.
                        </div>
                        <input
                          value={pkgQuery}
                          onChange={(e) => setPkgQuery(e.target.value)}
                          placeholder="Search packages..."
                          className={cx(
                            "w-[260px] max-w-full border border-border/60 bg-background/40 px-3 py-2",
                            "text-[11px] text-foreground outline-none font-mono",
                            "placeholder:text-muted-foreground/60 focus:ring-2 focus:ring-primary/30",
                          )}
                        />
                      </div>

                      {(() => {
                        const filtered = filterPackages(drawerLatest.packages || [], pkgQuery);
                        const visible = filtered.slice(0, 200);
                        if ((drawerLatest.packages || []).length === 0) {
                          return <EmptyState title="NO PACKAGES" hint="No package entries in the latest snapshot." />;
                        }
                        if (visible.length === 0) {
                          return <EmptyState title="NO MATCHES" hint="Your filter did not match any package." />;
                        }
                        return (
                          <Table
                            compact={compactRows}
                            scrollX={false}
                            className="text-xs"
                            columns={[
                              { key: "name", title: "NAME", className: "font-mono text-foreground" },
                              { key: "version", title: "VERSION", className: "font-mono text-muted-foreground w-44" },
                              {
                                key: "arch",
                                title: "ARCH",
                                className: "text-right font-mono text-muted-foreground w-20",
                                render: (p: PackageEntry) => p.arch || "",
                              },
                            ]}
                            rows={visible}
                            rowKey={(p: PackageEntry, i) => `${p.name}-${p.version}-${p.arch || ""}-${i}`}
                          />
                        );
                      })()}
                    </div>
                  )}
                </InvestigationSection>
              ) : null}

              {drawerTab === "configuration" ? (
                <div className="space-y-4">
                  <InvestigationSection title="Metadata controls" subtitle="Editable identity fields for this endpoint.">
                    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                      <div className="space-y-3">
                        <div>
                          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Display name</div>
                          <input
                            value={editName}
                            onChange={(e) => setEditName(e.target.value)}
                            className={cx(
                              "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                              "text-[11px] text-foreground outline-none font-mono",
                              "focus:ring-2 focus:ring-primary/30",
                            )}
                          />
                        </div>
                        <div>
                          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Description</div>
                          <input
                            value={editDesc}
                            onChange={(e) => setEditDesc(e.target.value)}
                            className={cx(
                              "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                              "text-[11px] text-foreground outline-none font-mono",
                              "focus:ring-2 focus:ring-primary/30",
                            )}
                          />
                        </div>
                        <div>
                          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Tags (comma)</div>
                          <input
                            value={editTags}
                            onChange={(e) => setEditTags(e.target.value)}
                            placeholder="prod, linux, web"
                            className={cx(
                              "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                              "text-[11px] text-foreground outline-none font-mono",
                              "placeholder:text-muted-foreground/60 focus:ring-2 focus:ring-primary/30",
                            )}
                          />
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          <button
                            type="button"
                            onClick={async () => {
                              if (!drawerAgentId) return;
                              setEditMsg(null);
                              setDrawerBusy(true);
                              try {
                                const next = drawerAgent.is_revoked
                                  ? await enableAgent(drawerAgentId)
                                  : await disableAgent(drawerAgentId);
                                setDrawerAgent(next);
                                setEditMsg("State updated.");
                              } catch (e: any) {
                                setEditMsg(e?.message || "Failed to update state");
                              } finally {
                                setDrawerBusy(false);
                              }
                            }}
                            className={cx(
                              "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                              "text-xs font-mono uppercase tracking-widest",
                              drawerAgent.is_revoked ? "text-success" : "text-warning",
                              "hover:bg-muted/15 focus:outline-none focus:ring-2 focus:ring-primary/30",
                            )}
                          >
                            {drawerAgent.is_revoked ? "Enable agent" : "Disable agent"}
                          </button>

                          <button
                            type="button"
                            onClick={async () => {
                              if (!drawerAgentId) return;
                              setEditMsg(null);
                              setDrawerBusy(true);
                              try {
                                const next = await updateAgent(drawerAgentId, {
                                  display_name: editName.trim() ? editName.trim() : null,
                                  description: editDesc.trim() ? editDesc.trim() : null,
                                  tags: normalizeTagsInput(editTags),
                                });
                                setDrawerAgent(next);
                                setEditMsg("Metadata updated.");
                              } catch (e: any) {
                                setEditMsg(e?.message || "Failed to update metadata");
                              } finally {
                                setDrawerBusy(false);
                              }
                            }}
                            className={cx(
                              "rounded-md border border-border/60 bg-primary/20 px-3 py-2",
                              "text-xs font-mono uppercase tracking-widest text-foreground",
                              "hover:bg-primary/25 focus:outline-none focus:ring-2 focus:ring-primary/30",
                            )}
                          >
                            Save metadata
                          </button>
                        </div>
                      </div>

                      <div className="space-y-3">
                        <div>
                          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Agent config (JSON)</div>
                          <textarea
                            value={editConfig}
                            onChange={(e) => setEditConfig(e.target.value)}
                            rows={14}
                            className={cx(
                              "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                              "text-[11px] text-foreground outline-none font-mono",
                              "focus:ring-2 focus:ring-primary/30",
                            )}
                          />
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={async () => {
                              if (!drawerAgentId) return;
                              setEditMsg(null);
                              const parsed = safeJsonParse(editConfig);
                              if (!parsed.ok) {
                                setEditMsg(parsed.error);
                                return;
                              }
                              setDrawerBusy(true);
                              try {
                                const next = await setAgentConfig(drawerAgentId, parsed.data);
                                setDrawerAgent(next);
                                setEditMsg("Config updated.");
                              } catch (e: any) {
                                setEditMsg(e?.message || "Failed to update config");
                              } finally {
                                setDrawerBusy(false);
                              }
                            }}
                            className={cx(
                              "rounded-md border border-border/60 bg-primary/20 px-3 py-2",
                              "text-xs font-mono uppercase tracking-widest text-foreground",
                              "hover:bg-primary/25 focus:outline-none focus:ring-2 focus:ring-primary/30",
                            )}
                          >
                            Save config
                          </button>
                          <button
                            type="button"
                            onClick={() => setEditConfig(JSON.stringify(drawerAgent.config || {}, null, 2))}
                            className={cx(
                              "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                              "text-xs font-mono uppercase tracking-widest text-muted-foreground",
                              "hover:bg-muted/15 hover:text-foreground",
                              "focus:outline-none focus:ring-2 focus:ring-primary/30",
                            )}
                          >
                            Reset
                          </button>
                        </div>
                      </div>
                    </div>

                    {editMsg ? <div className="text-[11px] text-muted-foreground font-mono">{editMsg}</div> : null}
                  </InvestigationSection>
                </div>
              ) : null}
            </>
          ) : (
            !drawerBusy && <EmptyState title="No agent selected" hint="Open an agent from the inventory tables." />
          )}
        </InvestigationShell>
      </Drawer>

      {pinSnapshotId ? (
        <PinToWorkspaceDrawer
          open={Boolean(pinSnapshotId)}
          onClose={() => setPinSnapshotId(null)}
          title={`inventory snapshot #${pinSnapshotId}`}
          defaultWorkspaceTitle={`Inventory investigation · ${drawerAgentId || "agent"}`}
          workspaceDefaults={{ primary_agent_id: drawerAgentId || undefined }}
          onPin={(workspaceId, options) =>
            pinInventorySnapshotToWorkspace(workspaceId, pinSnapshotId, {
              ...options,
              source_module: "inventory",
            })
          }
        />
      ) : null}
    </div>
  );
}
