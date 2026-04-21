import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import PageHeader from "@/shared/components/PageHeader";
import { useDataTablePreferences } from "@/shared/hooks/useDataTablePreferences";
import { cx } from "@/shared/lib/cx";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";

import { useAuth } from "@/features/auth/context";

import { ScanStats } from "./ActiveScanPanel";
import { getVulnScansPage } from "./api";
import VulnScanDrawer from "./VulnScanDrawer";
import type { VulnScan } from "./types";

type Density = "comfortable" | "compact";

type Filters = {
  reporterAgentId: string;
  status: string;
  tool: string;
};

function fmtWhen(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function fmtSeconds(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "-";
  if (sec < 60) return `${Math.round(sec)}s`;
  const m = Math.floor(sec / 60);
  const r = Math.round(sec % 60);
  if (m < 60) return r ? `${m}m ${r}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const mr = m % 60;
  return mr ? `${h}h ${mr}m` : `${h}h`;
}

function fmtAge(iso?: string | null): string {
  if (!iso) return "-";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return String(iso);
  const delta = Date.now() - t;
  if (delta < 10_000) return "just now";
  const sec = Math.floor(delta / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

function statusVariant(status: string) {
  const s = String(status || "").toLowerCase();
  if (s === "queued" || s === "acknowledged" || s === "running") return "info";
  if (s === "failed" || s === "cancelled") return "critical";
  return "neutral";
}

function densityToggleLabel(d: Density): string {
  return d === "compact" ? "Compact" : "Comfortable";
}

function Toggle({
  value,
  onChange,
  label,
}: {
  value: boolean;
  onChange: (next: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!value)}
      className={cx(
        "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
        "px-3 py-2 text-xs font-mono uppercase tracking-widest",
        value ? "text-foreground" : "text-muted-foreground",
        "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
      )}
      title={label}
    >
      <span className={cx("h-2.5 w-2.5 rounded-full", value ? "bg-primary" : "bg-muted-foreground/50")} />
      {label}
    </button>
  );
}

function applyLifecycleScanPatch(existing: VulnScan, patch: Record<string, any>): VulnScan {
  return {
    ...existing,
    id: patch.id ?? existing.id,
    status: patch.status ?? existing.status,
    lifecycle_state: patch.lifecycle_state ?? existing.lifecycle_state,
    current_phase: patch.current_phase ?? existing.current_phase,
    acknowledged_at: "acknowledged_at" in patch ? patch.acknowledged_at : existing.acknowledged_at,
    started_at: "started_at" in patch ? patch.started_at : existing.started_at,
    finished_at: "finished_at" in patch ? patch.finished_at : existing.finished_at,
    last_progress_at: patch.last_progress_at ?? existing.last_progress_at,
    duration_ms: "duration_ms" in patch ? patch.duration_ms : existing.duration_ms,
    error_summary: "error_summary" in patch ? patch.error_summary : existing.error_summary,
    stats: patch.stats ? (patch.stats as Record<string, any>) : existing.stats,
    phase_timestamps: patch.phase_timestamps ? (patch.phase_timestamps as Record<string, string>) : existing.phase_timestamps,
    updated_at: patch.updated_at ?? existing.updated_at,
  };
}

function buildVulnScanFromPatch(patch: Record<string, any>): VulnScan | null {
  const uuid = String(patch.scan_uuid || "").trim();
  if (!uuid) return null;
  const now = new Date().toISOString();
  return {
    id: patch.id ?? 0,
    scan_uuid: uuid,
    reporter_agent_id: patch.reporter_agent_id ?? null,
    target: patch.target ?? null,
    tool: patch.tool ?? "unknown",
    tool_version: patch.tool_version ?? null,
    status: patch.status ?? "queued",
    lifecycle_state: patch.lifecycle_state ?? "queued",
    current_phase: patch.current_phase ?? "queued",
    queued_at: patch.queued_at ?? now,
    acknowledged_at: patch.acknowledged_at ?? null,
    started_at: patch.started_at ?? null,
    finished_at: patch.finished_at ?? null,
    last_progress_at: patch.last_progress_at ?? now,
    duration_ms: patch.duration_ms ?? null,
    trigger_source: patch.trigger_source ?? "unknown",
    error_summary: patch.error_summary ?? null,
    stats: (patch.stats ?? {}) as Record<string, any>,
    phase_timestamps: (patch.phase_timestamps ?? {}) as Record<string, string>,
    scope: (patch.scope ?? {}) as Record<string, any>,
    config: (patch.config ?? {}) as Record<string, any>,
    updated_at: patch.updated_at ?? now,
    created_at: patch.created_at ?? now,
  };
}

export default function VulnerabilityScansPage() {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const [items, setItems] = useState<VulnScan[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);

  const [busy, setBusy] = useState(false);
  const [busyMore, setBusyMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scansTablePrefs = useDataTablePreferences({
    storageKey: "nw_vuln_scans_table_v1",
    defaultPageSize: 50,
    minPageSize: 10,
    maxPageSize: 500,
    defaultCompact: false,
  });
  const density: Density = scansTablePrefs.compact ? "compact" : "comfortable";
  const setDensity = (next: Density) => scansTablePrefs.setCompact(next === "compact");
  const pageSize = scansTablePrefs.pageSize;
  const setPageSize = scansTablePrefs.setPageSize;

  const [draft, setDraft] = useState<Filters>({ reporterAgentId: "", status: "all", tool: "" });
  const [filters, setFilters] = useState<Filters>(draft);

  const [selected, setSelected] = useState<VulnScan | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const reqSeq = useRef(0);
  const itemsRef = useRef<VulnScan[]>([]);

  useEffect(() => {
    itemsRef.current = items;
  }, [items]);

  const loadPage = useCallback(async (opts: { reset: boolean; cursor?: string | null }) => {
    if (!isAdmin) return;

    const mySeq = ++reqSeq.current;
    if (opts.reset) {
      setBusy(true);
      setError(null);
    } else {
      setBusyMore(true);
      setError(null);
    }

    try {
      const out = await getVulnScansPage({
        page_size: pageSize,
        cursor: opts.cursor ?? null,
        reporter_agent_id: (filters.reporterAgentId || "").trim() || undefined,
        status: filters.status !== "all" ? filters.status : undefined,
        tool: (filters.tool || "").trim() || undefined,
      });

      if (reqSeq.current !== mySeq) return;

      const nextItems = opts.reset ? (out.items || []) : [...itemsRef.current, ...(out.items || [])];
      setItems(nextItems);
      setCursor(out.next_cursor);
      setHasMore(Boolean(out.has_more));

      setSelected((prev) => {
        if (!prev) return null;
        return nextItems.find((x) => x.scan_uuid === prev.scan_uuid) ?? prev;
      });
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load scans");
      if (opts.reset) {
        setItems([]);
        setCursor(null);
        setHasMore(false);
      }
    } finally {
      if (reqSeq.current !== mySeq) return;
      setBusy(false);
      setBusyMore(false);
    }
  }, [isAdmin, filters, pageSize]);

  function applyFilters() {
    setFilters(draft);
  }

  function resetFilters() {
    const base: Filters = { reporterAgentId: "", status: "all", tool: "" };
    setDraft(base);
    setFilters(base);
  }

  const live = useLiveRefresh({
    enabled: isAdmin,
    profile: "admin",
    refresh: useCallback(async () => {
      await loadPage({ reset: true, cursor: null });
    }, [loadPage]),
  });
  const { refreshNow: refreshScansNow, invalidate: invalidateScans } = live;

  useEffect(() => {
    if (!isAdmin) return;
    invalidateScans("dependency", { immediate: true, supersede: true });
  }, [filters, invalidateScans, isAdmin, pageSize]);

  usePortalRealtimeSubscription("ui.vulnerabilities.scan.lifecycle", (event) => {
    if (!isAdmin) return;
    const { scan_uuid, agent_id, scan: scanData } = event.payload ?? {};
    if (!scan_uuid || !scanData) return;

    const agentFilter = (filters.reporterAgentId || "").trim();
    const eventAgent = String(agent_id || "").trim();
    if (agentFilter && eventAgent && agentFilter !== eventAgent) return;

    setItems((prev) => {
      const idx = prev.findIndex((s) => s.scan_uuid === scan_uuid);
      if (idx === -1) {
        const sf = filters.status;
        if (sf !== "all" && sf !== String((scanData as Record<string, any>).lifecycle_state || "").toLowerCase()) {
          return prev;
        }
        const built = buildVulnScanFromPatch(scanData as Record<string, any>);
        if (built) return [built, ...prev];
        return prev;
      }
      const next = [...prev];
      next[idx] = applyLifecycleScanPatch(next[idx], scanData as Record<string, any>);
      return next;
    });

    setSelected((prev) => {
      if (!prev || prev.scan_uuid !== scan_uuid) return prev;
      return applyLifecycleScanPatch(prev, scanData as Record<string, any>);
    });
  });

  usePortalRealtimeSubscription("ui.vulnerabilities.invalidate", (event) => {
    if (!isAdmin) return;
    const reason = String(event.payload?.reason || "");
    if (reason === "manual_scan_queued") {
      invalidateScans();
    }
  });

  const dense = density === "compact";

  const quickStats = useMemo(() => {
    const byStatus: Record<string, number> = {};
    const byTool: Record<string, number> = {};
    let running = 0;
    let finished = 0;
    let failed = 0;
    let durSum = 0;
    let durCount = 0;

    for (const s of items) {
      const st = String(s.lifecycle_state || "unknown").toLowerCase();
      byStatus[st] = (byStatus[st] || 0) + 1;
      byTool[s.tool] = (byTool[s.tool] || 0) + 1;

      if (st === "running" || st === "queued" || st === "started") running++;
      else if (st === "acknowledged") running++;
      else if (st === "failed" || st === "cancelled") failed++;
      else if (st === "completed") finished++;

      const dur = typeof s.duration_ms === "number" ? s.duration_ms / 1000 : NaN;
      if (Number.isFinite(dur)) {
        durSum += dur;
        durCount++;
      }
    }

    const avgDuration = durCount ? durSum / durCount : null;

    const tools = Object.entries(byTool)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([k, v]) => ({ k, v }));

    return { running, finished, failed, avgDuration, tools, byStatus };
  }, [items]);

  if (!isAdmin) {
    return (
      <div>
        <EmptyState
          title="Admin permissions required"
          description="Vulnerability scan history is restricted to administrators."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Vulnerabilities"
        breadcrumb={["Detection", "Vulnerabilities"]}
        description="Scan execution lifecycle and agent-reported phase progress."
        tabs={[
          { label: "Findings", to: "/vulnerabilities" },
          { label: "Scans", to: "/vulnerabilities/scans" },
        ]}
        toolbarRight={
          <div className="flex flex-wrap items-center gap-2">
            <Toggle
              value={density === "compact"}
              onChange={(v) => setDensity(v ? "compact" : "comfortable")}
              label={densityToggleLabel(density)}
            />

            <button
              type="button"
              onClick={() => void refreshScansNow()}
              className={cx(
                "inline-flex items-center rounded-md border border-border/60 bg-background/40",
                "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
              disabled={busy}
              title="Refresh"
            >
              {busy ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <Card title="Running" className="rounded-xl">
          <div className="text-3xl font-semibold">{quickStats.running}</div>
          <div className="mt-1 text-xs text-muted-foreground">in current page</div>
        </Card>
        <Card title="Finished" className="rounded-xl">
          <div className="text-3xl font-semibold">{quickStats.finished}</div>
          <div className="mt-1 text-xs text-muted-foreground">in current page</div>
        </Card>
        <Card title="Failed" className="rounded-xl">
          <div className="text-3xl font-semibold">{quickStats.failed}</div>
          <div className="mt-1 text-xs text-muted-foreground">in current page</div>
        </Card>
        <Card title="Avg duration" className="rounded-xl">
          <div className="text-3xl font-semibold">{quickStats.avgDuration == null ? "-" : fmtSeconds(quickStats.avgDuration)}</div>
          <div className="mt-1 text-xs text-muted-foreground">completed scans only</div>
        </Card>
      </div>

      <Card
        title="Filters"
        right={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={resetFilters}
              className={cx(
                "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              Reset
            </button>
            <button
              type="button"
              onClick={applyFilters}
              className={cx(
                "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              Apply
            </button>
          </div>
        }
        className="rounded-xl"
      >
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
          <div>
            <div className="text-xs text-muted-foreground">Reporter agent</div>
            <input
              value={draft.reporterAgentId}
              onChange={(e) => setDraft((p) => ({ ...p, reporterAgentId: e.target.value }))}
              placeholder="agent-id"
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm font-mono outline-none focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Status</div>
            <select
              value={draft.status}
              onChange={(e) => setDraft((p) => ({ ...p, status: e.target.value }))}
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              <option value="all">All</option>
              <option value="queued">Queued</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="running">Running</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </select>
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Tool</div>
            <input
              value={draft.tool}
              onChange={(e) => setDraft((p) => ({ ...p, tool: e.target.value }))}
              placeholder="osv / nuclei / trivy"
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm font-mono outline-none focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>

          <div className="flex items-end gap-2">
            <span className="text-xs text-muted-foreground">Page size</span>
            <DraftNumberInput
              value={pageSize}
              onCommit={(n) => setPageSize(n)}
              min={1}
              max={200}
              className={cx(
                "w-24 rounded-md border border-border/60 bg-background/40 px-2 py-2",
                "text-sm font-mono text-foreground outline-none",
                "focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>
        </div>
      </Card>

      <Card
        title="Scan inventory table"
        right={<span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{items.length} scans</span>}
        className="rounded-xl"
      >
        {busy ? (
          <div className="h-[360px]">
            <Loading label="Loading scans…" />
          </div>
        ) : error ? (
          <EmptyState title="Failed to load" description={error} />
        ) : items.length === 0 ? (
          <div className="h-[360px]">
            <EmptyState title="No scans" description="No scan executions were found for the current filters." />
          </div>
        ) : (
          <div className="w-full overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
                <tr className="border-b border-border/60 text-muted-foreground">
                  <th className="text-left font-medium px-3 py-2 w-[130px]">Status</th>
                  <th className="text-left font-medium px-3 py-2 w-[120px]">Trigger</th>
                  <th className="text-left font-medium px-3 py-2 w-[220px]">Started</th>
                  <th className="text-left font-medium px-3 py-2 w-[120px]">Duration</th>
                  <th className="text-left font-medium px-3 py-2 w-[240px]">Reporter / Target</th>
                  <th className="text-left font-medium px-3 py-2 w-[160px]">Tool</th>
                  <th className="text-left font-medium px-3 py-2">Stats</th>
                  <th className="text-right font-medium px-3 py-2 w-[120px]">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((s) => {
                  const selectedRow = selected?.scan_uuid === s.scan_uuid;
                  const rowPad = dense ? "py-1.5" : "py-2";
                  const start = Date.parse(s.started_at || "");
                  const end = s.finished_at ? Date.parse(s.finished_at) : Date.now();
                  const dur =
                    typeof s.duration_ms === "number"
                      ? Math.max(0, s.duration_ms / 1000)
                      : !Number.isNaN(start) && !Number.isNaN(end)
                        ? Math.max(0, (end - start) / 1000)
                        : NaN;
                  const isLive = ["queued", "acknowledged", "running"].includes(String(s.lifecycle_state || "").toLowerCase());
                  const hasNumericStats = Object.values(s.stats || {}).some(
                    (value) => typeof value === "number" && Number.isFinite(value)
                  );

                  return (
                    <tr
                      key={s.id || s.scan_uuid}
                      className={cx("border-b border-border/40 hover:bg-muted/30", selectedRow && "bg-muted/40")}
                      onClick={() => {
                        setSelected(s);
                        setDrawerOpen(true);
                      }}
                      role="button"
                      tabIndex={0}
                    >
                      <td className={cx("px-3", rowPad)}>
                        <div className="flex flex-col gap-1">
                          <Badge variant={statusVariant(s.lifecycle_state)}>{s.lifecycle_state}</Badge>
                          <div className="text-[11px] text-muted-foreground">{s.current_phase.replace(/_/g, " ")}</div>
                        </div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <span
                          className={cx(
                            "inline-flex rounded border px-2 py-0.5 text-[10px] font-mono uppercase tracking-widest",
                            s.trigger_source === "manual"
                              ? "border-info/30 text-info/70"
                              : "border-border/40 text-muted-foreground/60"
                          )}
                        >
                          {s.trigger_source || "—"}
                        </span>
                      </td>
                      <td className={cx("px-3 font-mono text-[12px]", rowPad)}>
                        <div className="text-foreground">{fmtWhen(s.started_at || s.queued_at)}</div>
                        <div className="text-muted-foreground">queued {fmtWhen(s.queued_at)}</div>
                        <div className="text-muted-foreground">last progress {fmtAge(s.last_progress_at)}</div>
                      </td>
                      <td className={cx("px-3 font-mono text-[12px]", rowPad)}>
                        {Number.isFinite(dur) ? fmtSeconds(dur) : isLive ? "running…" : "-"}
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="font-mono text-[12px]">{s.reporter_agent_id || "-"}</div>
                        <div className="truncate text-[11px] text-muted-foreground" title={s.target || ""}>
                          {s.target || s.scan_uuid}
                        </div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="font-mono text-[12px]">{s.tool}{s.tool_version ? `@${s.tool_version}` : ""}</div>
                        <div className="text-[11px] text-muted-foreground truncate">{s.scan_uuid}</div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        {hasNumericStats ? <ScanStats stats={s.stats} /> : <span className="text-xs text-muted-foreground">-</span>}
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="flex justify-end">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelected(s);
                              setDrawerOpen(true);
                            }}
                            className={cx(
                              "rounded-md border border-border/60 bg-background/40 px-3 py-1.5",
                              "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                              "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
                            )}
                          >
                            View
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="mt-4 flex items-center justify-between">
          <div className="text-xs text-muted-foreground">{hasMore ? "More available" : "End"}</div>
          <button
            type="button"
            onClick={() => void loadPage({ reset: false, cursor })}
            disabled={!hasMore || busyMore}
            className={cx(
              "rounded-md border border-border/60 bg-background/40 px-3 py-2",
              "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
              "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30",
              (!hasMore || busyMore) && "opacity-50 cursor-not-allowed"
            )}
          >
            {busyMore ? "Loading…" : "Load more"}
          </button>
        </div>
      </Card>

      <VulnScanDrawer
        open={drawerOpen}
        scan={selected}
        onClose={() => setDrawerOpen(false)}
      />
    </div>
  );
}
