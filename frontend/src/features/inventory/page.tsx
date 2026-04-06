import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import PageHeader from "@/shared/components/PageHeader";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import Drawer from "@/shared/components/Drawer";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import { Table } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import { isAbortError } from "@/shared/lib/http";
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

const POLL_MS = 15000;

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
      ? "border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
      : s === "stale"
        ? "border-amber-500/40 text-amber-400 bg-amber-500/10"
        : "border-red-500/40 text-red-400 bg-red-500/10";
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

function Panel({ title, right, children, scrollY = false, className = "" }: { title: string; right?: any; children: any; scrollY?: boolean; className?: string }) {
  return (
    <div className={cx("border border-border/60 bg-background/70 backdrop-blur-sm flex flex-col", className)}>
      <div className="flex items-center justify-between border-b border-border/60 bg-muted/10 px-4 py-3">
        <h3 className="text-[11px] font-mono font-bold uppercase tracking-[0.35em] text-primary/90">{title}</h3>
        {right ? <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">{right}</div> : null}
      </div>
      <div className={cx("p-4 flex-1 min-h-0", scrollY ? "overflow-y-auto" : "overflow-hidden")}>{children}</div>
    </div>
  );
}

function StatTile({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-lg border border-border/60 bg-background/80 backdrop-blur-md px-5 py-4">
      <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{label}</div>
      <div className="mt-2 text-3xl font-bold font-mono tracking-tight leading-none">{value}</div>
      {hint ? <div className="mt-2 text-[11px] text-muted-foreground font-mono opacity-80">{hint}</div> : null}
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

export default function InventoryPage() {
  const { agents } = useAgentsCatalog();
  const [sp, setSp] = useSearchParams();

  const urlAgentId = normAgentId(sp.get("agent_id"));
  const urlSnapshotId = parsePositiveInt(sp.get("snapshot_id"));
  const urlOpenDrawer = String(sp.get("open_drawer") || "").trim() === "1";

  const [agentScope, setAgentScope] = useState<string>(urlAgentId);
  const [windowMinutes, setWindowMinutes] = useState<number>(() => {
    const w = Number(sp.get("window_minutes"));
    return Number.isFinite(w) && w >= 30 ? w : 360;
  });

  // Keep local scope in sync with the URL when user navigates via sidebar.
  useEffect(() => {
    setAgentScope(urlAgentId);
  }, [urlAgentId]);

  const [snapshot, setSnapshot] = useState<InventoryOverviewSnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

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
      setLastUpdatedAt(new Date());
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

  useEffect(() => {
    let alive = true;
    refresh();

    const t = window.setInterval(() => {
      if (!alive) return;
      refresh();
    }, POLL_MS);

    return () => {
      alive = false;
      refreshAbortRef.current?.abort();
      window.clearInterval(t);
    };
  }, [refresh]);

  function pushUrl(nextAgent: string, nextWindow?: number) {
    const next = new URLSearchParams(sp);

    const agent = normAgentId(nextAgent);
    if (agent && agent !== "__all") next.set("agent_id", agent);
    else next.delete("agent_id");
    next.delete("snapshot_id");
    next.delete("open_drawer");

    const w = nextWindow ?? windowMinutes;
    if (Number.isFinite(w)) next.set("window_minutes", String(w));

    setSp(next, { replace: true });
  }

  // -----------------------------
  // Drawer state
  // -----------------------------
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerAgentId, setDrawerAgentId] = useState<string | null>(null);

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
    setDrawerErr(null);
    setEditMsg(null);
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
      <div className="hidden md:block text-[11px] font-mono text-muted-foreground">
        {lastUpdatedAt ? `Updated ${fmtDateTime(lastUpdatedAt.toISOString())}` : ""}
      </div>

      <button
        type="button"
        onClick={refresh}
        className={cx(
          "rounded-md border border-border/60 bg-background/40 px-3 py-2",
          "text-xs font-mono uppercase tracking-widest text-muted-foreground",
          "hover:bg-muted/15 hover:text-foreground",
          "focus:outline-none focus:ring-2 focus:ring-primary/30",
          busy && "opacity-60 cursor-not-allowed"
        )}
        disabled={busy}
      >
        Refresh
      </button>
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
        columns={[
          { key: "manager", title: "MANAGER", className: "font-mono text-foreground" },
          { key: "agents", title: "AGENTS", className: "text-right font-mono text-muted-foreground w-24" }
        ]}
        rows={mgrRows}
        rowKey={(r) => r.manager}
      />
    );

  const warningsRows: InventoryWarningRow[] = snapshot?.recent_warnings || [];
  const changesRows: InventoryChangeRow[] = snapshot?.recent_changes || [];
  const fleetRows: FleetHealthRow[] = snapshot?.fleet_health || [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Inventory"
        breadcrumb={["Assets"]}
        description={
          <span>
            Fleet inventory telemetry (OS, package baselines, freshness). Click any agent row to open the inspector drawer.
          </span>
        }
        toolbarRight={toolbarRight}
      />

      {/* Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Panel title="Scope" className="lg:col-span-1">
          <div className="space-y-4">
            <div>
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Agent</div>
              <select
                value={agentScope}
                onChange={(e) => {
                  const v = normAgentId(e.target.value);
                  setAgentScope(v);
                  pushUrl(v);
                }}
                className={cx(
                  "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                  "text-[11px] text-foreground outline-none font-mono",
                  "focus:ring-2 focus:ring-primary/30"
                )}
              >
                <option value="__all">All agents</option>
                {agentsOptions.map((a) => (
                  <option key={a.agent_id} value={a.agent_id}>
                    {a.display_name ? a.display_name : a.agent_id}
                  </option>
                ))}
              </select>
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
                  {Math.round(POLL_MS / 1000)}s
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
              <StatTile label="Agents" value={snapshot.kpis.agents_total} hint="Registered endpoints" />
              <StatTile label="Online (5m)" value={snapshot.kpis.agents_online_5m} hint="Last seen <= 5 minutes" />
              <StatTile label="With inventory (6h)" value={snapshot.kpis.agents_with_inventory_6h} hint="Any snapshot in the last 6 hours" />
              <StatTile
                label="Oldest inventory"
                value={fmtMinutes(snapshot.kpis.oldest_inventory_age_minutes)}
                hint="Max age across latest snapshots"
              />
            </div>
          ) : (
            <EmptyState title="No data" hint="No inventory telemetry yet." />
          )}
        </Panel>
      </div>

      <Section id="timeseries" title="Activity" defaultOpen>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Panel title="Inventory snapshots / minute" right={`${windowMinutes}m window`} className="min-h-[420px]">
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

          <Panel title="Inventory changes / 10m" right="packages_hash delta" className="min-h-[420px]">
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

      <Section id="fleet" title="Fleet health" defaultOpen>
        <Panel
          title="Fleet health"
          right={snapshot ? `${fleetRows.length} agents` : undefined}
          scrollY
          className="min-h-[520px]"
        >
          {snapshot ? (
            fleetRows.length === 0 ? (
              <EmptyState title="NO AGENTS" hint="No agent inventory data available for the current scope." />
            ) : (
              <Table
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

      <Section id="changes" title="Recent changes & warnings" defaultOpen={false}>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Panel title="Recent inventory changes" scrollY className="min-h-[520px]">
            {snapshot ? (
              changesRows.length === 0 ? (
                <EmptyState title="NO CHANGES" hint="No inventory baselines/changes in the current window." />
              ) : (
                <Table
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

      {/* Drawer Inspector */}
      <Drawer
        open={drawerOpen}
        title={drawerAgentId ? `Agent inspector · ${drawerAgentId}` : "Agent inspector"}
        description="Inventory + configuration. Changes apply immediately."
        onClose={closeDrawer}
      >
        {drawerBusy ? <Loading label="Loading agent..." /> : null}

        {drawerErr ? (
          <div className="rounded-md border border-border/60 bg-background/20 px-4 py-3 text-sm text-muted-foreground">
            {drawerErr}
          </div>
        ) : null}

        {drawerAgent ? (
          <div className="space-y-8">
            {/* Quick meta */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="rounded-lg border border-border/60 bg-background/60 px-4 py-4">
                <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Last seen</div>
                <div className="mt-2 font-mono text-sm text-foreground">{fmtDateTime(drawerAgent.last_seen_at)}</div>
                <div className="mt-2 text-[11px] text-muted-foreground">Revoked: {drawerAgent.is_revoked ? "yes" : "no"}</div>
              </div>

              <div className="rounded-lg border border-border/60 bg-background/60 px-4 py-4">
                <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Last inventory</div>
                <div className="mt-2 font-mono text-sm text-foreground">{fmtDateTime(drawerLatest?.collected_at || null)}</div>
                <div className="mt-2 text-[11px] text-muted-foreground">
                  Packages: {drawerLatest?.packages_count ?? "-"} · Manager: {drawerLatest?.manager ?? "-"}
                </div>
                {drawerLatest ? (
                  <button
                    type="button"
                    onClick={() => setPinSnapshotId(drawerLatest.id)}
                    className={cx(
                      "mt-3 rounded-md border border-border/60 bg-background/40 px-3 py-2",
                      "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                      "hover:bg-muted/15 hover:text-foreground"
                    )}
                  >
                    Pin latest snapshot
                  </button>
                ) : null}
              </div>
            </div>

            {/* Configuration */}
            <div className="space-y-4">
              <div className="text-[11px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Configuration</div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <div>
                    <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Display name</div>
                    <input
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                      className={cx(
                        "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                        "text-[11px] text-foreground outline-none font-mono",
                        "focus:ring-2 focus:ring-primary/30"
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
                        "focus:ring-2 focus:ring-primary/30"
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
                        "placeholder:text-muted-foreground/60 focus:ring-2 focus:ring-primary/30"
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
                        drawerAgent.is_revoked ? "text-emerald-400" : "text-amber-400",
                        "hover:bg-muted/15 focus:outline-none focus:ring-2 focus:ring-primary/30"
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
                            tags: normalizeTagsInput(editTags)
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
                        "hover:bg-primary/25 focus:outline-none focus:ring-2 focus:ring-primary/30"
                      )}
                    >
                      Save metadata
                    </button>

                    {editMsg ? <div className="text-[11px] text-muted-foreground font-mono">{editMsg}</div> : null}
                  </div>
                </div>

                <div className="space-y-3">
                  <div>
                    <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Agent config (JSON)</div>
                    <textarea
                      value={editConfig}
                      onChange={(e) => setEditConfig(e.target.value)}
                      rows={12}
                      className={cx(
                        "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2",
                        "text-[11px] text-foreground outline-none font-mono",
                        "focus:ring-2 focus:ring-primary/30"
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
                        "hover:bg-primary/25 focus:outline-none focus:ring-2 focus:ring-primary/30"
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
                        "focus:outline-none focus:ring-2 focus:ring-primary/30"
                      )}
                    >
                      Reset
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Inventory summary */}
            <div className="space-y-4">
              <div className="text-[11px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Inventory</div>

              {!drawerLatest ? (
                <div className="rounded-md border border-border/60 bg-background/20 px-4 py-3 text-sm text-muted-foreground">
                  No inventory snapshot for this agent.
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="rounded-lg border border-border/60 bg-background/60 px-4 py-4">
                      <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">OS</div>
                      <div className="mt-2 text-sm text-foreground font-mono">
                        {drawerLatest.os?.pretty_name || drawerLatest.os?.name || drawerLatest.os?.id || "unknown"}
                      </div>
                      <div className="mt-2 text-[11px] text-muted-foreground font-mono opacity-80">
                        {drawerLatest.os?.goos ? `goos=${drawerLatest.os.goos}` : ""}
                      </div>
                    </div>

                    <div className="rounded-lg border border-border/60 bg-background/60 px-4 py-4">
                      <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Packages hash</div>
                      <div className="mt-2 text-[11px] font-mono text-foreground break-all">{drawerLatest.packages_hash}</div>
                      <div className="mt-2 text-[11px] text-muted-foreground font-mono opacity-80">
                        Count: {drawerLatest.packages_count}
                      </div>
                    </div>
                  </div>

                  {/* Warnings */}
                  <div>
                    <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Warnings</div>
                    {parseWarnings(drawerLatest.extra).length === 0 ? (
                      <div className="mt-2 rounded-md border border-border/60 bg-background/30 px-3 py-2 text-[11px] text-muted-foreground">
                        No warnings.
                      </div>
                    ) : (
                      <ul className="mt-2 space-y-2">
                        {parseWarnings(drawerLatest.extra).slice(0, 8).map((w, idx) => (
                          <li
                            key={`${idx}-${w.slice(0, 24)}`}
                            className="rounded-md border border-border/60 bg-background/30 px-3 py-2 text-[11px] text-muted-foreground whitespace-pre-wrap break-words"
                          >
                            {w}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  {/* History */}
                  <div>
                    <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Recent snapshots</div>
                    <div className="mt-2 overflow-hidden rounded-lg border border-border/60">
                      <table className="w-full text-sm">
                        <thead className="bg-muted/10">
                          <tr className="text-[10px] uppercase tracking-widest font-mono text-muted-foreground">
                            <th className="text-left px-3 py-2">Collected</th>
                            <th className="text-right px-3 py-2">Packages</th>
                            <th className="text-right px-3 py-2">Changed</th>
                            <th className="text-right px-3 py-2">Action</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border/60">
                          {drawerHistory.slice(0, 20).map((s, idx) => {
                            const next = drawerHistory[idx + 1];
                            const changed = next ? s.packages_hash !== next.packages_hash : false;
                            return (
                              <tr
                                key={s.id}
                                className={cx(
                                  "text-[11px] font-mono",
                                  focusedSnapshotId === s.id && "bg-primary/10"
                                )}
                              >
                                <td className="px-3 py-2 text-muted-foreground">{fmtDateTime(s.collected_at)}</td>
                                <td className="px-3 py-2 text-right text-muted-foreground">{s.packages_count}</td>
                                <td className="px-3 py-2 text-right">
                                  <span
                                    className={cx(
                                      "inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] uppercase",
                                      changed
                                        ? "border-amber-500/40 text-amber-400 bg-amber-500/10"
                                        : "border-border/60 text-muted-foreground bg-muted/10"
                                    )}
                                  >
                                    {changed ? "yes" : "no"}
                                  </span>
                                </td>
                                <td className="px-3 py-2 text-right">
                                  <button
                                    type="button"
                                    onClick={() => setPinSnapshotId(s.id)}
                                    className={cx(
                                      "rounded-md border border-border/60 bg-background/40 px-2 py-1",
                                      "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                                      "hover:bg-muted/15 hover:text-foreground",
                                      focusedSnapshotId === s.id && "border-primary/40 text-foreground"
                                    )}
                                  >
                                    Pin
                                  </button>
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
                  </div>

                  {/* Packages */}
                  <div>
                    <div className="flex items-end justify-between gap-3">
                      <div>
                        <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Packages</div>
                        <div className="mt-1 text-[11px] text-muted-foreground">
                          Showing up to 200 entries (search filters client-side).
                        </div>
                      </div>
                      <input
                        value={pkgQuery}
                        onChange={(e) => setPkgQuery(e.target.value)}
                        placeholder="Search packages..."
                        className={cx(
                          "w-[260px] max-w-full border border-border/60 bg-background/40 px-3 py-2",
                          "text-[11px] text-foreground outline-none font-mono",
                          "placeholder:text-muted-foreground/60 focus:ring-2 focus:ring-primary/30"
                        )}
                      />
                    </div>

                    <div className="mt-3">
                      {(() => {
                        const filtered = filterPackages(drawerLatest.packages || [], pkgQuery);
                        const visible = filtered.slice(0, 200);
                        if (filtered.length === 0) {
                          return <EmptyState title="NO PACKAGES" hint="No package entries in the latest snapshot." />;
                        }

                        if (visible.length === 0) {
                          return <EmptyState title="NO MATCHES" hint="Your filter did not match any package." />;
                        }

                        return (
                          <Table
                            scrollX={false}
                            className="text-xs"
                            columns={[
                              { key: "name", title: "NAME", className: "font-mono text-foreground" },
                              { key: "version", title: "VERSION", className: "font-mono text-muted-foreground w-44" },
                              { key: "arch", title: "ARCH", className: "text-right font-mono text-muted-foreground w-20", render: (p: PackageEntry) => p.arch || "" }
                            ]}
                            rows={visible}
                            rowKey={(p: PackageEntry, i) => `${p.name}-${p.version}-${p.arch || ""}-${i}`}
                          />
                        );
                      })()}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : null}
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
