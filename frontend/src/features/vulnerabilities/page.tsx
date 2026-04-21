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
import { listAgents } from "@/features/agents/api";
import type { AgentPublic } from "@/features/agents/types";

import { getVulnFindingsPage, getVulnPosture, getVulnScansPage, getVulnSummary, triggerVulnScanNow } from "./api";
import { ActiveScanPanel } from "./ActiveScanPanel";
import VulnFindingDrawer from "./VulnFindingDrawer";
import VulnScanDrawer from "./VulnScanDrawer";
import type { VulnFinding, VulnPosture, VulnScan, VulnSummary } from "./types";

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

type Density = "comfortable" | "compact";

type Filters = {
  q: string;
  minSeverity: string;
  observationState: string;
  disposition: string;
  reporterAgentId: string;
  assetAgentId: string;
  cve: string;
  includeSuppressed: boolean;
};

const RECENT_SCANS_PAGE_SIZE = 12;

function sevVariant(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "neutral";
}

function fmtWhen(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
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
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function prettyAssetLabel(f: VulnFinding): string {
  if (f.asset_agent_id) return `agent:${f.asset_agent_id}`;
  if (f.asset_key) return f.asset_key;
  if (f.target) return f.target;
  return "-";
}

function fmtRisk(n: number | null | undefined): string {
  const v = Number(n || 0);
  if (!Number.isFinite(v)) return "0.0";
  return v.toFixed(1);
}

function exposureScoreOf(f: VulnFinding): number {
  const a = Number((f.evidence as any)?.analysis?.exposure_score);
  if (Number.isFinite(a)) return a;
  const b = Number((f.asset as any)?.exposure?.surface_score);
  if (Number.isFinite(b)) return b;
  return 0;
}

function serviceHintsOf(f: VulnFinding): string[] {
  const fromAsset = (f.asset as any)?.exposure?.service_hints;
  if (Array.isArray(fromAsset)) return fromAsset.map((x) => String(x || "").trim()).filter(Boolean);
  const fromEvidence = (f.evidence as any)?.exposure?.service_hints;
  if (Array.isArray(fromEvidence)) return fromEvidence.map((x) => String(x || "").trim()).filter(Boolean);
  return [];
}

function packagePivotKey(f: VulnFinding): string {
  const fromEvidence =
    String((f.evidence as any)?.package?.name || (f.evidence as any)?.package_name || (f.evidence as any)?.dependency?.name || "").trim();
  if (fromEvidence) return fromEvidence;

  const fromLocation = String(f.location || "").trim();
  if (fromLocation) {
    const at = fromLocation.indexOf("@");
    if (at > 0) return fromLocation.slice(0, at);
    const colon = fromLocation.indexOf(":");
    if (colon > 0) return fromLocation.slice(0, colon);
    return fromLocation;
  }

  return "";
}

function observationVariant(state: string) {
  const s = String(state || "").toLowerCase();
  if (s === "observed") return "info";
  if (s === "awaiting_verification") return "high";
  return "neutral";
}

function dispositionVariant(disposition: string) {
  const s = String(disposition || "").toLowerCase();
  if (s === "suppressed") return "neutral";
  if (s === "accepted_risk") return "low";
  return "neutral";
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

export default function VulnerabilitiesPage() {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const [summary, setSummary] = useState<VulnSummary | null>(null);
  const [summaryBusy, setSummaryBusy] = useState(false);
  const [posture, setPosture] = useState<VulnPosture | null>(null);
  const [postureBusy, setPostureBusy] = useState(false);

  const [items, setItems] = useState<VulnFinding[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);

  const [busy, setBusy] = useState(false);
  const [busyMore, setBusyMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const findingsTablePrefs = useDataTablePreferences({
    storageKey: "nw_vuln_findings_table_v1",
    defaultPageSize: 50,
    minPageSize: 10,
    maxPageSize: 500,
    defaultCompact: false,
  });
  const density: Density = findingsTablePrefs.compact ? "compact" : "comfortable";
  const setDensity = (next: Density) => findingsTablePrefs.setCompact(next === "compact");
  const pageSize = findingsTablePrefs.pageSize;
  const setPageSize = findingsTablePrefs.setPageSize;
  const [activeDays, setActiveDays] = useState<number>(30);

  const [draft, setDraft] = useState<Filters>({
    q: "",
    minSeverity: "all",
    observationState: "all",
    disposition: "all",
    reporterAgentId: "",
    assetAgentId: "",
    cve: "",
    includeSuppressed: false,
  });

  const [filters, setFilters] = useState<Filters>(draft);

  const [selected, setSelected] = useState<VulnFinding | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedScan, setSelectedScan] = useState<VulnScan | null>(null);
  const [scanDrawerOpen, setScanDrawerOpen] = useState(false);
  const [agents, setAgents] = useState<AgentPublic[]>([]);
  const [scanTargetAgent, setScanTargetAgent] = useState<string>("");
  const [scanBusy, setScanBusy] = useState(false);
  const [scanMsg, setScanMsg] = useState<string | null>(null);
  const [scanErr, setScanErr] = useState<string | null>(null);
  const [recentScans, setRecentScans] = useState<VulnScan[]>([]);
  const [recentScansBusy, setRecentScansBusy] = useState(false);
  const [onlySelectedAgentScans, setOnlySelectedAgentScans] = useState(true);

  const reqSeq = useRef(0);
  const itemsRef = useRef<VulnFinding[]>([]);

  useEffect(() => {
    itemsRef.current = items;
  }, [items]);

  const loadSummary = useCallback(async (params?: { includeSuppressed?: boolean }) => {
    if (!isAdmin) return;
    setSummaryBusy(true);
    try {
      const out = await getVulnSummary({
        active_within_days: activeDays,
        include_suppressed: params?.includeSuppressed ?? filters.includeSuppressed,
      });
      setSummary(out);
    } catch {
      setSummary(null);
    } finally {
      setSummaryBusy(false);
    }
  }, [activeDays, filters.includeSuppressed, isAdmin]);

  const loadPosture = useCallback(async (params?: { includeSuppressed?: boolean }) => {
    if (!isAdmin) return;
    setPostureBusy(true);
    try {
      const out = await getVulnPosture({
        active_within_days: activeDays,
        include_suppressed: params?.includeSuppressed ?? filters.includeSuppressed,
        top_n: 15,
      });
      setPosture(out);
    } catch {
      setPosture(null);
    } finally {
      setPostureBusy(false);
    }
  }, [activeDays, filters.includeSuppressed, isAdmin]);

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
      const out = await getVulnFindingsPage({
        page_size: pageSize,
        cursor: opts.cursor ?? null,
        q: (filters.q || "").trim() || undefined,
        min_severity: filters.minSeverity !== "all" ? filters.minSeverity : undefined,
        observation_state: filters.observationState !== "all" ? filters.observationState : undefined,
        disposition: filters.disposition !== "all" ? filters.disposition : undefined,
        reporter_agent_id: (filters.reporterAgentId || "").trim() || undefined,
        asset_agent_id: (filters.assetAgentId || "").trim() || undefined,
        cve: (filters.cve || "").trim() || undefined,
        include_suppressed: filters.includeSuppressed || filters.disposition === "suppressed",
      });

      if (reqSeq.current !== mySeq) return;

      const nextItems = opts.reset ? (out.items || []) : [...itemsRef.current, ...(out.items || [])];
      setItems(nextItems);
      setCursor(out.next_cursor);
      setHasMore(Boolean(out.has_more));

      setSelected((prev) => {
        if (!prev) return null;
        return nextItems.find((x) => x.id === prev.id) || null;
      });
    } catch (e: any) {
      if (reqSeq.current !== mySeq) return;
      setError(e?.message || "Failed to load findings");
      if (opts.reset) {
        setItems([]);
        setCursor(null);
        setHasMore(false);
        setSelected(null);
        setDrawerOpen(false);
      }
    } finally {
      if (reqSeq.current !== mySeq) return;
      setBusy(false);
      setBusyMore(false);
    }
  }, [filters, isAdmin, pageSize]);

  function applyFilters() {
    setFilters(draft);
  }

  function resetFilters() {
    const base: Filters = {
      q: "",
      minSeverity: "all",
      observationState: "all",
      disposition: "all",
      reporterAgentId: "",
      assetAgentId: "",
      cve: "",
      includeSuppressed: false,
    };
    setDraft(base);
    setFilters(base);
  }

  useEffect(() => {
    if (!isAdmin) return;
    listAgents()
      .then((rows) => {
        const pick = (rows || []).filter((a) => !a.is_revoked);
        pick.sort((a, b) => a.agent_id.localeCompare(b.agent_id));
        setAgents(pick);
        const preferred =
          pick.find((a) => a.agent_id.includes("vuln"))?.agent_id ||
          pick[0]?.agent_id ||
          "";
        setScanTargetAgent(preferred);
      })
      .catch(() => setAgents([]));
  }, [isAdmin]);

  async function runManualScan() {
    if (!scanTargetAgent || scanBusy) return;
    setScanBusy(true);
    setScanErr(null);
    setScanMsg(null);
    try {
      const out = await triggerVulnScanNow(scanTargetAgent);
      setScanMsg(
        `Request ${out.request_state} for ${out.agent_id} at ${fmtWhen(out.queued_at)} · ${out.lifecycle_state} · id ${out.scan_uuid}`
      );
      void Promise.all([refreshDashboardNow(), refreshRecentScansNow()]);
    } catch (e: any) {
      setScanErr(e?.message || "Failed to trigger manual scan");
    } finally {
      setScanBusy(false);
    }
  }

  async function loadRecentScans(agentId: string) {
    if (onlySelectedAgentScans && !agentId) {
      setRecentScans([]);
      return;
    }
    setRecentScansBusy(true);
    try {
      const out = await getVulnScansPage({
        page_size: RECENT_SCANS_PAGE_SIZE,
        reporter_agent_id: onlySelectedAgentScans ? agentId : undefined,
      });
      const nextItems = out.items || [];
      setRecentScans(nextItems);
      setSelectedScan((prev) => {
        if (!prev) return null;
        return nextItems.find((item) => item.scan_uuid === prev.scan_uuid) ?? prev;
      });
    } catch {
      setRecentScans([]);
    } finally {
      setRecentScansBusy(false);
    }
  }

  const refreshDashboard = useCallback(async () => {
    await Promise.all([
      loadSummary({ includeSuppressed: filters.includeSuppressed }),
      loadPosture({ includeSuppressed: filters.includeSuppressed }),
    ]);
    await loadPage({ reset: true, cursor: null });
  }, [filters.includeSuppressed, loadPage, loadPosture, loadSummary]);

  const live = useLiveRefresh({
    enabled: isAdmin,
    profile: "admin",
    refresh: refreshDashboard,
  });

  const scansLive = useLiveRefresh({
    enabled: isAdmin && (!onlySelectedAgentScans || Boolean(scanTargetAgent)),
    profile: "admin",
    refresh: async () => {
      await loadRecentScans(scanTargetAgent);
    },
  });
  const { refreshNow: refreshDashboardNow, invalidate: invalidateDashboard } = live;
  const { refreshNow: refreshRecentScansNow, invalidate: invalidateRecentScans } = scansLive;
  const recentScansScopeKey = onlySelectedAgentScans ? scanTargetAgent || "__none__" : "__all__";
  const recentScansScopeMissing = recentScansScopeKey === "__none__";

  useEffect(() => {
    if (!isAdmin) return;
    if (recentScansScopeMissing) return;
    invalidateRecentScans("dependency", { immediate: true, supersede: true });
  }, [invalidateRecentScans, isAdmin, recentScansScopeKey, recentScansScopeMissing]);

  useEffect(() => {
    if (!isAdmin) return;
    invalidateDashboard("dependency", { immediate: true, supersede: true });
  }, [activeDays, filters, invalidateDashboard, isAdmin, pageSize]);

  usePortalRealtimeSubscription("ui.vulnerabilities.scan.lifecycle", (event) => {
    if (!isAdmin) return;
    const { scan_uuid, agent_id, lifecycle_event, scan: scanData } = event.payload ?? {};
    if (!scan_uuid || !scanData) return;

    setRecentScans((prev) => {
      const idx = prev.findIndex((s) => s.scan_uuid === scan_uuid);
      if (idx === -1) {
        const targetAgent = scanTargetAgent;
        const eventAgent = String(agent_id || (scanData as Record<string, any>).reporter_agent_id || "").trim();
        if (onlySelectedAgentScans && targetAgent && eventAgent !== targetAgent) return prev;
        const built = buildVulnScanFromPatch(scanData as Record<string, any>);
        if (built) return [built, ...prev].slice(0, RECENT_SCANS_PAGE_SIZE);
        return prev;
      }
      const next = [...prev];
      next[idx] = applyLifecycleScanPatch(next[idx], scanData as Record<string, any>);
      return next;
    });

    setSelectedScan((prev) => {
      if (!prev || prev.scan_uuid !== scan_uuid) return prev;
      return applyLifecycleScanPatch(prev, scanData as Record<string, any>);
    });

    if (lifecycle_event === "completed" || lifecycle_event === "failed") {
      invalidateDashboard();
    }
  });

  usePortalRealtimeSubscription("ui.vulnerabilities.invalidate", (event) => {
    if (!isAdmin) return;
    const reason = String(event.payload?.reason || "");
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    const reporterAgentId = String(filters.reporterAgentId || "").trim();
    const assetAgentId = String(filters.assetAgentId || "").trim();
    const hasScopedAgentFilter = Boolean(reporterAgentId || assetAgentId);

    if (
      hasScopedAgentFilter &&
      eventAgentId &&
      reporterAgentId !== eventAgentId &&
      assetAgentId !== eventAgentId
    ) {
      return;
    }

    if (reason === "findings_ingested") {
      invalidateDashboard();
    }
    if (reason === "manual_scan_queued") {
      if (!onlySelectedAgentScans || !scanTargetAgent || !eventAgentId || scanTargetAgent === eventAgentId) {
        invalidateRecentScans();
      }
    }
  });

  const severityBlocks = useMemo(() => {
    const m = summary?.by_severity || {};
    const order = ["critical", "high", "medium", "low", "unknown"];
    const out = order
      .filter((k) => Object.prototype.hasOwnProperty.call(m, k))
      .map((k) => ({ k, v: Number(m[k] || 0) }));

    Object.keys(m)
      .filter((k) => !order.includes(k))
      .sort()
      .forEach((k) => out.push({ k, v: Number(m[k] || 0) }));

    return out;
  }, [summary]);

  const dense = density === "compact";
  const visibleRecentScans = useMemo(
    () =>
      (recentScans || []).filter((s) =>
        onlySelectedAgentScans ? (s.reporter_agent_id || "") === (scanTargetAgent || "") : true
      ),
    [recentScans, onlySelectedAgentScans, scanTargetAgent]
  );
  const selectedAgentRecentScans = useMemo(
    () => (recentScans || []).filter((s) => (s.reporter_agent_id || "") === (scanTargetAgent || "")),
    [recentScans, scanTargetAgent]
  );
  const activeScan = useMemo(() => {
    const liveScan = selectedAgentRecentScans.find((scan) => {
      const state = String(scan.lifecycle_state || "").toLowerCase();
      return state === "queued" || state === "acknowledged" || state === "running";
    });
    return liveScan ?? selectedAgentRecentScans[0] ?? null;
  }, [selectedAgentRecentScans]);
  const activeFilterCount = useMemo(() => {
    let n = 0;
    if ((filters.q || "").trim()) n++;
    if (filters.minSeverity !== "all") n++;
    if (filters.observationState !== "all") n++;
    if (filters.disposition !== "all") n++;
    if ((filters.reporterAgentId || "").trim()) n++;
    if ((filters.assetAgentId || "").trim()) n++;
    if ((filters.cve || "").trim()) n++;
    if (filters.includeSuppressed) n++;
    return n;
  }, [filters]);
  const findingsHint = useMemo(() => {
    const scans = visibleRecentScans;
    const hasRunning = scans.some((s) => {
      const st = String(s.lifecycle_state || "").toLowerCase();
      return st === "queued" || st === "acknowledged" || st === "running";
    });
    const hasCompleted = scans.some((s) => {
      const st = String(s.lifecycle_state || "").toLowerCase();
      return st === "completed";
    });
    const totalEmitted = scans.reduce((acc, s) => {
      const v = Number((s.stats as any)?.emitted_findings || 0);
      return acc + (Number.isFinite(v) ? v : 0);
    }, 0);
    if (activeFilterCount > 0) {
      return `No findings match the current filters (${activeFilterCount} active).`;
    }
    if (hasRunning) {
      return "A scan is running/queued. Wait a few seconds and refresh.";
    }
    if (hasCompleted && totalEmitted === 0) {
      return "Completed scans reported no vulnerability findings.";
    }
    if (!scans.length) {
      return "No recent scans for this agent yet.";
    }
    return "No persisted findings for the recent scans yet.";
  }, [visibleRecentScans, activeFilterCount]);
  const assetPivots = useMemo(() => {
    const map = new Map<string, { label: string; count: number; maxRisk: number }>();
    for (const f of items) {
      const label = prettyAssetLabel(f);
      const entry = map.get(label) || { label, count: 0, maxRisk: 0 };
      entry.count += 1;
      entry.maxRisk = Math.max(entry.maxRisk, Number((f.evidence as any)?.analysis?.risk_score || 0));
      map.set(label, entry);
    }
    return Array.from(map.values())
      .sort((a, b) => (b.maxRisk === a.maxRisk ? b.count - a.count : b.maxRisk - a.maxRisk))
      .slice(0, 10);
  }, [items]);
  const packagePivots = useMemo(() => {
    const map = new Map<string, number>();
    for (const f of items) {
      const key = packagePivotKey(f);
      if (!key) continue;
      map.set(key, (map.get(key) || 0) + 1);
    }
    return Array.from(map.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [items]);

  if (!isAdmin) {
    return (
      <div className="p-6">
        <EmptyState
          title="Admin permissions required"
          description="Vulnerability findings are restricted to administrators."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Vulnerabilities"
        breadcrumb={["Detection", "Vulnerabilities"]}
        description="Triage vulnerability findings reported by agents."
        tabs={[
          { label: "Findings", to: "/vulnerabilities" },
          { label: "Scans", to: "/vulnerabilities/scans" },
        ]}
        toolbarRight={
          <div className="flex flex-wrap items-center gap-2">
            <Toggle
              value={density === "compact"}
              onChange={(v) => setDensity(v ? "compact" : "comfortable")}
              label={density === "compact" ? "Compact" : "Comfortable"}
            />

            <button
              type="button"
              onClick={() => {
                void Promise.all([refreshDashboardNow(), refreshRecentScansNow()]);
              }}
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
        <Card title="Observed" right={summaryBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{summary?.total_observed ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">active within {activeDays}d</div>
        </Card>

        <Card title="Awaiting Verification" right={summaryBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{summary?.total_awaiting_verification ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">waiting for rescan confirmation</div>
        </Card>

        <Card title="Suppressed" right={summaryBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{summary?.total_suppressed ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">excluded by default</div>
        </Card>

        <Card title="Severity" right={summaryBusy ? "loading" : undefined} className="rounded-xl">
          <div className="flex flex-wrap gap-2">
            {severityBlocks.length ? (
              severityBlocks.map((x) => (
                <span key={x.k} className="inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40 px-2 py-1">
                  <Badge variant={sevVariant(x.k)}>{x.k}</Badge>
                  <span className="font-mono text-[12px]">{x.v}</span>
                </span>
              ))
            ) : (
              <span className="text-sm text-muted-foreground">-</span>
            )}
          </div>

          <div className="mt-4 flex items-center gap-3">
            <span className="text-xs text-muted-foreground">Window (days)</span>
            <DraftNumberInput
              value={activeDays}
              onCommit={(n) => setActiveDays(n)}
              min={1}
              max={365}
              className={cx(
                "w-24 rounded-md border border-border/60 bg-background/40 px-2 py-1",
                "text-sm font-mono text-foreground outline-none",
                "focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>
        </Card>
      </div>

      <Card title="Quick Guide" className="rounded-xl">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4 text-xs text-muted-foreground">
          <div className="rounded-md border border-border/50 bg-background/30 p-3">
            <div className="font-mono uppercase tracking-widest text-[10px] mb-1">Observed / Awaiting</div>
            <div>
              `Observed` means the latest scan still sees the issue. `Awaiting verification` means an operator wants the next rescan to confirm remediation.
            </div>
          </div>
          <div className="rounded-md border border-border/50 bg-background/30 p-3">
            <div className="font-mono uppercase tracking-widest text-[10px] mb-1">Risk Score</div>
            <div>
              Prioritizes severity, confidence, recurrence, and exploitation/exposure signals.
            </div>
          </div>
          <div className="rounded-md border border-border/50 bg-background/30 p-3">
            <div className="font-mono uppercase tracking-widest text-[10px] mb-1">Exposure Score</div>
            <div>
              Measures host exposure surface (detected ports/services). Higher means more urgent.
            </div>
          </div>
          <div className="rounded-md border border-border/50 bg-background/30 p-3">
            <div className="font-mono uppercase tracking-widest text-[10px] mb-1">Manual Scan</div>
            <div>
              Manual scans now move through `queued`, `acknowledged`, `running`, detailed execution phases, and then `completed`/`failed`.
            </div>
          </div>
        </div>
      </Card>

      <ActiveScanPanel
        activeScan={activeScan}
        recentScans={recentScans}
        agents={agents}
        scanTargetAgent={scanTargetAgent}
        onAgentChange={setScanTargetAgent}
        onRunScan={runManualScan}
        scanBusy={scanBusy}
        scanMsg={scanMsg}
        scanErr={scanErr}
        recentScansBusy={recentScansBusy}
        onRefreshScans={() => {
          void refreshRecentScansNow();
        }}
        onViewScan={(scan) => {
          setSelectedScan(scan);
          setScanDrawerOpen(true);
        }}
        onlySelectedAgent={onlySelectedAgentScans}
        onToggleAgentFilter={() => setOnlySelectedAgentScans((value) => !value)}
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        <Card title="Mean risk score" right={postureBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{posture ? fmtRisk(posture.mean_risk) : "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">p95: {posture ? fmtRisk(posture.p95_risk) : "-"}</div>
        </Card>

        <Card title="Critical/High" right={postureBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">
            {posture ? posture.critical_open + posture.high_open : "-"}
          </div>
          <div className="mt-1 text-xs text-muted-foreground">
            critical {posture?.critical_open ?? "-"} · high {posture?.high_open ?? "-"}
          </div>
        </Card>

        <Card title="Exploitable likely" right={postureBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{posture?.exploitable_open ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">CVE/CVSS/network exposure heuristics</div>
        </Card>

        <Card title="Fix available" right={postureBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{posture?.fixable_open ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">remediation text or OSV fixed version</div>
        </Card>

        <Card title="Stale open (>30d)" right={postureBusy ? "loading" : undefined} className="rounded-xl">
          <div className="text-3xl font-semibold">{posture?.stale_open ?? "-"}</div>
          <div className="mt-1 text-xs text-muted-foreground">needs ownership/escalation</div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card
          title="Top risky findings"
          right={<span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{posture?.top_risks?.length ?? 0} items</span>}
          className="rounded-xl"
        >
          {!posture || posture.top_risks.length === 0 ? (
            <EmptyState title="No prioritized findings" description="No open findings in the selected window." />
          ) : (
            <div className="w-full overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
                  <tr className="border-b border-border/60 text-muted-foreground">
                    <th className="text-left font-medium px-3 py-2 w-[86px]">Risk</th>
                    <th className="text-left font-medium px-3 py-2">Finding</th>
                    <th className="text-left font-medium px-3 py-2 w-[160px]">Asset</th>
                    <th className="text-left font-medium px-3 py-2 w-[110px]">Fix</th>
                  </tr>
                </thead>
                <tbody>
                  {posture.top_risks.map((x) => (
                    <tr
                      key={x.id}
                      className="border-b border-border/40 hover:bg-muted/30 cursor-pointer"
                      onClick={() => {
                        const row = items.find((it) => it.id === x.id);
                        if (row) {
                          setSelected(row);
                          setDrawerOpen(true);
                          return;
                        }
                        const next = { ...draft, cve: x.cve || "", q: x.cve ? "" : x.title };
                        setDraft(next);
                        setFilters(next);
                      }}
                    >
                      <td className="px-3 py-2 font-mono text-[12px]">
                        <span className={cx("inline-flex rounded-md border px-2 py-0.5", Number(x.risk_score) >= 80 ? "border-red-500/50 text-red-300" : Number(x.risk_score) >= 65 ? "border-orange-500/50 text-orange-300" : "border-border/60 text-foreground")}>
                          {fmtRisk(x.risk_score)}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <div className="font-mono text-[12px] truncate" title={x.title}>
                          {x.cve ? `${x.cve} — ${x.title}` : x.title}
                        </div>
                        <div className="text-[11px] text-muted-foreground">
                          <Badge variant={sevVariant(x.severity)}>{x.severity}</Badge>
                          <span className="ml-2">conf {x.confidence}</span>
                          {x.internet_exposed ? <span className="ml-2">AV:N</span> : null}
                        </div>
                      </td>
                      <td className="px-3 py-2 font-mono text-[12px] truncate" title={x.asset_key}>{x.asset_agent_id ? `agent:${x.asset_agent_id}` : x.asset_key}</td>
                      <td className="px-3 py-2 text-[11px]">{x.has_fix ? "available" : "unknown"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card
          title="Most exposed assets"
          right={<span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{posture?.top_assets?.length ?? 0} assets</span>}
          className="rounded-xl"
        >
          {!posture || posture.top_assets.length === 0 ? (
            <EmptyState title="No exposed assets" description="No asset-level risk found in the selected window." />
          ) : (
            <div className="space-y-2">
              {posture.top_assets.map((a) => (
                <button
                  key={`${a.asset_key}-${a.asset_agent_id || "-"}`}
                  type="button"
                  onClick={() => {
                    const next = {
                      ...draft,
                      assetAgentId: a.asset_agent_id || "",
                      q: a.asset_agent_id ? draft.q : a.asset_key,
                    };
                    setDraft(next);
                    setFilters(next);
                  }}
                  className="w-full rounded-lg border border-border/60 bg-background/40 p-3 text-left hover:bg-muted/15"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-mono text-[12px] truncate" title={a.asset_agent_id ? `agent:${a.asset_agent_id}` : a.asset_key}>
                      {a.asset_agent_id ? `agent:${a.asset_agent_id}` : a.asset_key}
                    </div>
                    <div className="font-mono text-[12px] text-muted-foreground">max {fmtRisk(a.max_risk)}</div>
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    open {a.open_findings} · critical/high {a.critical_high} · avg {fmtRisk(a.avg_risk)} · seen {fmtAge(a.last_seen_at)}
                  </div>
                </button>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card
          title="Asset pivots"
          right={<span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{assetPivots.length} assets</span>}
          className="rounded-xl"
        >
          {assetPivots.length === 0 ? (
            <EmptyState title="No asset pivots" description="Load findings to pivot by affected assets." />
          ) : (
            <div className="space-y-2">
              {assetPivots.map((p) => (
                <button
                  key={p.label}
                  type="button"
                  onClick={() => {
                    const agentId = p.label.startsWith("agent:") ? p.label.slice(6) : "";
                    const next = { ...draft, assetAgentId: agentId, q: agentId ? draft.q : p.label };
                    setDraft(next);
                    setFilters(next);
                  }}
                  className={cx(
                    "w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-left",
                    "hover:bg-muted/15 focus:outline-none focus:ring-2 focus:ring-primary/30"
                  )}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-mono text-[12px] truncate">{p.label}</div>
                    <div className="text-[11px] text-muted-foreground">risk {fmtRisk(p.maxRisk)} · {p.count}</div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </Card>

        <Card
          title="Package pivots"
          right={<span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{packagePivots.length} packages</span>}
          className="rounded-xl"
        >
          {packagePivots.length === 0 ? (
            <EmptyState title="No package pivots" description="Package names were not present in the current findings page." />
          ) : (
            <div className="space-y-2">
              {packagePivots.map((p) => (
                <button
                  key={p.name}
                  type="button"
                  onClick={() => {
                    const next = { ...draft, q: p.name };
                    setDraft(next);
                    setFilters(next);
                  }}
                  className={cx(
                    "w-full rounded-md border border-border/60 bg-background/40 px-3 py-2 text-left",
                    "hover:bg-muted/15 focus:outline-none focus:ring-2 focus:ring-primary/30"
                  )}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-mono text-[12px] truncate">{p.name}</div>
                    <div className="text-[11px] text-muted-foreground">{p.count} findings</div>
                  </div>
                </button>
              ))}
            </div>
          )}
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
            <div className="text-xs text-muted-foreground">Search</div>
            <input
              value={draft.q}
              onChange={(e) => setDraft((p) => ({ ...p, q: e.target.value }))}
              placeholder="title / cve / external_id"
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm outline-none focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Min severity</div>
            <select
              value={draft.minSeverity}
              onChange={(e) => setDraft((p) => ({ ...p, minSeverity: e.target.value }))}
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              <option value="all">All</option>
              <option value="low">Low+</option>
              <option value="medium">Medium+</option>
              <option value="high">High+</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Observation state</div>
            <select
              value={draft.observationState}
              onChange={(e) => setDraft((p) => ({ ...p, observationState: e.target.value }))}
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              <option value="all">All</option>
              <option value="observed">Observed</option>
              <option value="awaiting_verification">Awaiting verification</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Disposition</div>
            <select
              value={draft.disposition}
              onChange={(e) => setDraft((p) => ({ ...p, disposition: e.target.value }))}
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              <option value="all">All</option>
              <option value="open">Open</option>
              <option value="accepted_risk">Accepted risk</option>
              <option value="suppressed">Suppressed</option>
            </select>
          </div>

          <div>
            <div className="text-xs text-muted-foreground">CVE</div>
            <input
              value={draft.cve}
              onChange={(e) => setDraft((p) => ({ ...p, cve: e.target.value }))}
              placeholder="CVE-2024-1234"
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm font-mono outline-none focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>

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
            <div className="text-xs text-muted-foreground">Asset agent</div>
            <input
              value={draft.assetAgentId}
              onChange={(e) => setDraft((p) => ({ ...p, assetAgentId: e.target.value }))}
              placeholder="agent-id"
              className={cx(
                "mt-1 w-full rounded-md border border-border/60 bg-background/40 px-3 py-2",
                "text-sm font-mono outline-none focus:ring-2 focus:ring-primary/30"
              )}
            />
          </div>

          <div className="flex items-end">
            <Toggle
              value={draft.includeSuppressed}
              onChange={(v) => setDraft((p) => ({ ...p, includeSuppressed: v }))}
              label={draft.includeSuppressed ? "Including suppressed" : "Exclude suppressed"}
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
        title="Filtered inventory table"
        right={
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              {items.length} items
            </span>
            <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              filters {activeFilterCount}
            </span>
          </div>
        }
        className="rounded-xl"
      >
        {busy ? (
          <div className="h-[360px]">
            <Loading label="Loading findings…" />
          </div>
        ) : error ? (
          <EmptyState title="Failed to load" description={error} />
        ) : items.length === 0 ? (
          <div className="h-[360px]">
            <div className="flex h-full flex-col items-center justify-center gap-3">
              <EmptyState title="No findings" description={findingsHint} />
              {activeFilterCount > 0 ? (
                <button
                  type="button"
                  onClick={resetFilters}
                  className={cx(
                    "rounded-md border border-border/60 bg-background/40 px-3 py-2",
                    "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                    "hover:bg-muted/15 hover:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
                  )}
                >
                  Clear filters
                </button>
              ) : null}
            </div>
          </div>
        ) : (
          <div className="w-full overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
                <tr className="border-b border-border/60 text-muted-foreground">
                  <th className="text-left font-medium px-3 py-2 w-[120px] whitespace-nowrap">Severity</th>
                  <th className="text-left font-medium px-3 py-2 min-w-[280px]">Title</th>
                  <th className="text-left font-medium px-3 py-2 w-[190px] whitespace-nowrap">Asset</th>
                  <th className="text-left font-medium px-3 py-2 w-[180px] whitespace-nowrap">State</th>
                  <th className="text-left font-medium px-3 py-2 w-[170px] whitespace-nowrap">Exposure</th>
                  <th className="text-left font-medium px-3 py-2 w-[150px] whitespace-nowrap">Last seen</th>
                  <th className="text-left font-medium px-3 py-2 w-[110px] whitespace-nowrap">Hits</th>
                  <th className="text-right font-medium px-3 py-2 w-[120px] whitespace-nowrap">Actions</th>
                </tr>
              </thead>

              <tbody>
                {items.map((f) => {
                  const selectedRow = selected?.id === f.id;
                  const rowPad = dense ? "py-1.5" : "py-2";
                  const expScore = exposureScoreOf(f);
                  const svc = serviceHintsOf(f).slice(0, 2);
                  return (
                    <tr
                      key={f.id}
                      className={cx(
                        "border-b border-border/40 hover:bg-muted/30",
                        selectedRow && "bg-muted/40",
                        "align-top"
                      )}
                      onClick={() => {
                        setSelected(f);
                        setDrawerOpen(true);
                      }}
                      role="button"
                      tabIndex={0}
                    >
                      <td className={cx("px-3", rowPad)}>
                        <Badge variant={sevVariant(f.severity)}>{f.severity}</Badge>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="font-mono text-[12px] truncate" title={f.title}>
                          {f.cve ? `${f.cve} — ${f.title}` : f.title}
                        </div>
                        <div className="text-[11px] text-muted-foreground truncate">
                          {f.location || f.external_id || f.source} · conf {f.confidence}
                        </div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="font-mono text-[12px] truncate" title={prettyAssetLabel(f)}>
                          {prettyAssetLabel(f)}
                        </div>
                        <div className="text-[11px] text-muted-foreground truncate">
                          {f.reporter_agent_id ? `reported by ${f.reporter_agent_id}` : "-"}
                        </div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant={observationVariant(f.observation_state)}>{f.observation_state}</Badge>
                          {f.operator_disposition !== "open" ? (
                            <Badge variant={dispositionVariant(f.operator_disposition)}>{f.operator_disposition}</Badge>
                          ) : null}
                        </div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="font-mono text-[12px]">
                          score {expScore}
                        </div>
                        <div className="text-[11px] text-muted-foreground truncate" title={svc.join(", ") || "-"}>
                          {svc.length ? svc.join(", ") : "-"}
                        </div>
                      </td>
                      <td className={cx("px-3 font-mono text-[12px]", rowPad)}>
                        <div title={fmtWhen(f.last_seen_at)}>{fmtAge(f.last_seen_at)}</div>
                      </td>
                      <td className={cx("px-3 font-mono text-[12px]", rowPad)}>{f.occurrences}</td>
                      <td className={cx("px-3 text-right", rowPad)}>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelected(f);
                            setDrawerOpen(true);
                          }}
                          className={cx(
                            "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40",
                            "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                            "hover:bg-muted/15 hover:text-foreground",
                            "focus:outline-none focus:ring-2 focus:ring-primary/30"
                          )}
                          title="Open drawer"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {hasMore ? (
              <div className="mt-4 flex justify-center">
                <button
                  type="button"
                  disabled={busyMore}
                  onClick={() => loadPage({ reset: false, cursor })}
                  className={cx(
                    "rounded-md border border-border/60 bg-background/40 px-4 py-2",
                    "text-xs font-mono uppercase tracking-widest text-muted-foreground",
                    "hover:bg-muted/15 hover:text-foreground",
                    "focus:outline-none focus:ring-2 focus:ring-primary/30",
                    busyMore && "opacity-60"
                  )}
                >
                  {busyMore ? "Loading…" : "Load more"}
                </button>
              </div>
            ) : null}
          </div>
        )}
      </Card>

      <VulnFindingDrawer
        open={drawerOpen}
        finding={selected}
        onClose={() => setDrawerOpen(false)}
        onPatched={(next) => {
          setSelected(next);
          setItems((prev) => prev.map((x) => (x.id === next.id ? next : x)));

          // If the user is excluding suppressed findings and this item was just suppressed,
          // remove it locally to match server behavior.
          if (!filters.includeSuppressed && filters.disposition !== "suppressed" && next.is_suppressed) {
            setItems((prev) => prev.filter((x) => x.id !== next.id));
            setDrawerOpen(false);
          }

          loadSummary();
          loadPosture();
        }}
      />
      <VulnScanDrawer
        open={scanDrawerOpen}
        scan={selectedScan}
        onClose={() => setScanDrawerOpen(false)}
      />
    </div>
  );
}
