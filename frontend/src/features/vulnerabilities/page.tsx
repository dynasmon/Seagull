import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { Card } from "@/shared/components/Card";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import PageHeader from "@/shared/components/PageHeader";
import { SelectInput } from "@/shared/components/SelectInput";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { TextInput } from "@/shared/components/TextInput";
import { useDataTablePreferences } from "@/shared/hooks/useDataTablePreferences";
import { cx } from "@/shared/lib/cx";
import { RiskScorePill } from "./RiskScorePill";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";

import { useAuth } from "@/features/auth/context";
import { listAgents } from "@/features/agents/api";
import type { AgentPublic } from "@/features/agents/types";

import { getVulnFindingsPage, getVulnPosture, getVulnScansPage, getVulnSummary, triggerVulnScanNow } from "./api";
import { ActiveScanPanel } from "./ActiveScanPanel";
import {
  dispositionVariant,
  findingAssetLabel,
  findingComponentLabel,
  findingDispositionLabel,
  findingExposureLabel,
  findingFixedVersion,
  findingInstalledVersion,
  findingObservationLabel,
  mergeFindingsById,
  observationVariant,
  sevVariant,
  sortFindingsByPriority,
} from "./findingUtils";
import {
  applyLifecycleScanPatch,
  buildVulnScanFromPatch,
  fmtAge,
  fmtWhen,
  scanLifecycleLabel,
  upsertLifecycleScan,
} from "./scanUtils";
import VulnFindingDrawer from "./VulnFindingDrawer";
import VulnScanDrawer from "./VulnScanDrawer";
import type { VulnFinding, VulnPosture, VulnScan, VulnSummary } from "./types";

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
const FINDING_PATCH_METRICS_DELAY_MS = 300;
const MIN_SEVERITY_RANK: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function fmtRisk(n: number | null | undefined): string {
  const v = Number(n || 0);
  if (!Number.isFinite(v)) return "0.0";
  return v.toFixed(1);
}

function packagePivotKey(f: VulnFinding): string {
  const direct = String(f.component?.name || "").trim();
  if (direct) return direct;
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

function findingMatchesFilters(f: VulnFinding, filters: Filters): boolean {
  if (!filters.includeSuppressed && filters.disposition !== "suppressed" && f.operator_disposition === "suppressed") {
    return false;
  }
  if (filters.minSeverity !== "all" && Number(f.severity_rank || 0) < Number(MIN_SEVERITY_RANK[filters.minSeverity] || 0)) {
    return false;
  }
  if (filters.observationState !== "all" && f.observation_state !== filters.observationState) {
    return false;
  }
  if (filters.disposition !== "all" && f.operator_disposition !== filters.disposition) {
    return false;
  }
  if (filters.reporterAgentId && f.reporter_agent_id !== filters.reporterAgentId) {
    return false;
  }
  if (filters.assetAgentId && f.asset_agent_id !== filters.assetAgentId) {
    return false;
  }
  if (filters.cve && String(f.cve || "").toLowerCase() !== filters.cve.toLowerCase()) {
    return false;
  }
  const query = String(filters.q || "").trim().toLowerCase();
  if (query) {
    const haystack = [
      f.title,
      f.cve,
      f.external_id,
      f.asset_display,
      f.asset_key,
      f.location,
      f.component?.name,
      f.risk_summary,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    if (!haystack.includes(query)) {
      return false;
    }
  }
  return true;
}

function StatItem({
  label,
  value,
  sub,
  loading,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  loading?: boolean;
}) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</div>
      <div className={cx("mt-1 text-2xl font-semibold tracking-tight tabular-nums transition-opacity", loading && "opacity-50")}>
        {value}
      </div>
      {sub && <div className="mt-0.5 text-[11px] text-muted-foreground">{sub}</div>}
    </div>
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
  const metricsRefreshTimerRef = useRef<number | null>(null);
  const didInvalidateDashboardRef = useRef(false);
  const didInvalidateRecentScansRef = useRef(false);

  useEffect(() => {
    itemsRef.current = items;
  }, [items]);

  const loadSummary = useCallback(
    async (params?: { includeSuppressed?: boolean }) => {
      if (!isAdmin) return;
      setSummaryBusy(true);
      try {
        const out = await getVulnSummary({
          active_within_days: activeDays,
          include_suppressed: params?.includeSuppressed ?? filters.includeSuppressed,
        });
        setSummary(out);
      } catch {
        // keep stale data on error
      } finally {
        setSummaryBusy(false);
      }
    },
    [activeDays, filters.includeSuppressed, isAdmin]
  );

  const loadPosture = useCallback(
    async (params?: { includeSuppressed?: boolean }) => {
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
        // keep stale data on error
      } finally {
        setPostureBusy(false);
      }
    },
    [activeDays, filters.includeSuppressed, isAdmin]
  );

  const loadPage = useCallback(
    async (opts: { reset: boolean; cursor?: string | null; signal?: AbortSignal }) => {
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
          signal: opts.signal,
        });

        if (reqSeq.current !== mySeq || opts.signal?.aborted) return;

        const nextItems = sortFindingsByPriority(
          opts.reset ? (out.items || []) : mergeFindingsById(itemsRef.current, out.items || [])
        );
        setItems(nextItems);
        setCursor(out.next_cursor);
        setHasMore(Boolean(out.has_more));

        setSelected((prev) => {
          if (!prev) return null;
          return nextItems.find((x) => x.id === prev.id) || prev;
        });
      } catch (e: any) {
        if (reqSeq.current !== mySeq || opts.signal?.aborted) return;
        setError(e?.message || "Failed to load findings");
        if (opts.reset) {
          setItems([]);
          setCursor(null);
          setHasMore(false);
        }
      } finally {
        if (reqSeq.current !== mySeq || opts.signal?.aborted) return;
        setBusy(false);
        setBusyMore(false);
      }
    },
    [filters, isAdmin, pageSize]
  );

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
          pick.find((a) => a.agent_id.includes("vuln"))?.agent_id || pick[0]?.agent_id || "";
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
      const optimisticScan = buildVulnScanFromPatch(
        ((out.scan as Record<string, any> | undefined) ?? out) as Record<string, any>
      );
      if (optimisticScan) {
        setRecentScans((prev) => upsertLifecycleScan(prev, optimisticScan, { maxItems: RECENT_SCANS_PAGE_SIZE }));
        setSelectedScan((prev) => {
          if (!prev || prev.scan_uuid !== optimisticScan.scan_uuid) return prev;
          return applyLifecycleScanPatch(prev, optimisticScan);
        });
      }
      setScanMsg(
        `Request ${out.request_state} for ${out.agent_id} at ${fmtWhen(out.queued_at)} · ${scanLifecycleLabel(out.lifecycle_state)} · scan ${out.scan_uuid}`
      );
      if (!optimisticScan) {
        void refreshRecentScansNow();
      }
    } catch (e: any) {
      setScanErr(e?.message || "Failed to trigger manual scan");
    } finally {
      setScanBusy(false);
    }
  }

  async function loadRecentScans(agentId: string, signal?: AbortSignal) {
    if (onlySelectedAgentScans && !agentId) {
      setRecentScans([]);
      return;
    }
    setRecentScansBusy(true);
    try {
      const out = await getVulnScansPage({
        page_size: RECENT_SCANS_PAGE_SIZE,
        reporter_agent_id: onlySelectedAgentScans ? agentId : undefined,
        signal,
      });
      if (signal?.aborted) return;
      const nextItems = out.items || [];
      setRecentScans(nextItems);
      setSelectedScan((prev) => {
        if (!prev) return null;
        return nextItems.find((item) => item.scan_uuid === prev.scan_uuid) ?? prev;
      });
    } catch {
      if (!signal?.aborted) setRecentScans([]);
    } finally {
      setRecentScansBusy(false);
    }
  }

  const refreshMetrics = useCallback(
    async () => {
      await Promise.all([
        loadSummary({ includeSuppressed: filters.includeSuppressed }),
        loadPosture({ includeSuppressed: filters.includeSuppressed }),
      ]);
    },
    [filters.includeSuppressed, loadPosture, loadSummary]
  );

  const refreshDashboard = useCallback(
    async (signal?: AbortSignal) => {
      await Promise.all([
        refreshMetrics(),
        loadPage({ reset: true, cursor: null, signal }),
      ]);
    },
    [loadPage, refreshMetrics]
  );

  const live = useLiveRefresh({
    enabled: isAdmin,
    profile: "admin",
    refresh: async (context) => {
      await refreshDashboard(context.signal);
    },
  });

  const scansLive = useLiveRefresh({
    enabled: isAdmin && (!onlySelectedAgentScans || Boolean(scanTargetAgent)),
    profile: "admin",
    refresh: async (context) => {
      await loadRecentScans(scanTargetAgent, context.signal);
    },
  });
  const { refreshNow: refreshDashboardNow, invalidate: invalidateDashboard } = live;
  const { refreshNow: refreshRecentScansNow, invalidate: invalidateRecentScans } = scansLive;

  const scheduleMetricsRefresh = useCallback(() => {
    if (metricsRefreshTimerRef.current !== null) return;
    metricsRefreshTimerRef.current = window.setTimeout(() => {
      metricsRefreshTimerRef.current = null;
      void refreshMetrics();
    }, FINDING_PATCH_METRICS_DELAY_MS);
  }, [refreshMetrics]);

  const recentScansScopeKey = onlySelectedAgentScans ? scanTargetAgent || "__none__" : "__all__";
  const recentScansScopeMissing = recentScansScopeKey === "__none__";

  useEffect(() => {
    if (!isAdmin) return;
    if (recentScansScopeMissing) return;
    if (!didInvalidateRecentScansRef.current) {
      didInvalidateRecentScansRef.current = true;
      return;
    }
    invalidateRecentScans("dependency", { immediate: true, supersede: true });
  }, [invalidateRecentScans, isAdmin, recentScansScopeKey, recentScansScopeMissing]);

  useEffect(() => {
    if (!isAdmin) return;
    if (!didInvalidateDashboardRef.current) {
      didInvalidateDashboardRef.current = true;
      return;
    }
    invalidateDashboard("dependency", { immediate: true, supersede: true });
  }, [activeDays, filters, invalidateDashboard, isAdmin, pageSize]);

  useEffect(() => {
    return () => {
      if (metricsRefreshTimerRef.current !== null) {
        window.clearTimeout(metricsRefreshTimerRef.current);
        metricsRefreshTimerRef.current = null;
      }
    };
  }, []);

  usePortalRealtimeSubscription("ui.vulnerabilities.scan.lifecycle", (event) => {
    if (!isAdmin) return;
    const { scan_uuid, agent_id, lifecycle_event, scan: scanData } = event.payload ?? {};
    if (!scan_uuid || !scanData) return;
    const scanPatch = scanData as Record<string, any>;

    setRecentScans((prev) => {
      const targetAgent = scanTargetAgent;
      const eventAgent = String(agent_id || scanPatch.reporter_agent_id || "").trim();
      const alreadyVisible = prev.some((scan) => scan.scan_uuid === scan_uuid);
      if (onlySelectedAgentScans && targetAgent && eventAgent !== targetAgent && !alreadyVisible) return prev;
      return upsertLifecycleScan(prev, scanPatch, { maxItems: RECENT_SCANS_PAGE_SIZE });
    });

    setSelectedScan((prev) => {
      if (!prev || prev.scan_uuid !== scan_uuid) return prev;
      return applyLifecycleScanPatch(prev, scanPatch);
    });

    if (lifecycle_event === "completed" || lifecycle_event === "failed") scheduleMetricsRefresh();
  });

  usePortalRealtimeSubscription("ui.vulnerabilities.finding.patch", (event) => {
    if (!isAdmin) return;
    const payload = event.payload ?? {};
    const incoming = Array.isArray(payload.findings)
      ? (payload.findings.filter(Boolean) as VulnFinding[])
      : [];
    const eventAgentId = String(payload.agent_id || "").trim();
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

    if (payload.requires_reconcile) {
      invalidateDashboard();
      return;
    }
    if (!incoming.length) return;

    setItems((prev) => {
      const incomingById = new Map<number, VulnFinding>();
      for (const finding of incoming) {
        if (typeof finding?.id !== "number") continue;
        incomingById.set(finding.id, finding);
      }
      const retained = prev.filter((existing) => {
        const replacement = incomingById.get(existing.id);
        if (!replacement) return true;
        return findingMatchesFilters(replacement, filters);
      });
      const visibleIncoming = incoming.filter((finding) => findingMatchesFilters(finding, filters));
      return sortFindingsByPriority(mergeFindingsById(retained, visibleIncoming));
    });

    setSelected((prev) => {
      if (!prev) return null;
      return incoming.find((finding) => finding.id === prev.id) ?? prev;
    });

    scheduleMetricsRefresh();
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

    if (reason === "findings_ingested") invalidateDashboard();
    if (reason === "manual_scan_queued") {
      if (!onlySelectedAgentScans || !scanTargetAgent || !eventAgentId || scanTargetAgent === eventAgentId) {
        invalidateRecentScans();
      }
    }
  });

  // Derived state

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
    const scans = (recentScans || []).filter((s) =>
      onlySelectedAgentScans ? (s.reporter_agent_id || "") === (scanTargetAgent || "") : true
    );
    const hasRunning = scans.some((s) => {
      const st = String(s.lifecycle_state || "").toLowerCase();
      return st === "queued" || st === "acknowledged" || st === "running";
    });
    const hasCompleted = scans.some((s) => String(s.lifecycle_state || "").toLowerCase() === "completed");
    const totalEmitted = scans.reduce((acc, s) => {
      const v = Number((s.stats as any)?.emitted_findings || 0);
      return acc + (Number.isFinite(v) ? v : 0);
    }, 0);
    if (activeFilterCount > 0) return `No findings match the current filters (${activeFilterCount} active).`;
    if (hasRunning) return "A scan is in progress. Wait a few seconds and refresh.";
    if (hasCompleted && totalEmitted === 0) return "Completed scans reported no vulnerability findings.";
    if (!scans.length) return "No recent scans for this agent yet.";
    return "No persisted findings for the recent scans yet.";
  }, [recentScans, onlySelectedAgentScans, scanTargetAgent, activeFilterCount]);

  const assetPivots = useMemo(() => {
    const map = new Map<string, { label: string; count: number; maxRisk: number }>();
    for (const f of items) {
      const label = findingAssetLabel(f);
      const entry = map.get(label) || { label, count: 0, maxRisk: 0 };
      entry.count += 1;
      entry.maxRisk = Math.max(entry.maxRisk, Number(f.priority?.score || 0));
      map.set(label, entry);
    }
    return Array.from(map.values())
      .sort((a, b) => (b.maxRisk === a.maxRisk ? b.count - a.count : b.maxRisk - a.maxRisk))
      .slice(0, 8);
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
      .slice(0, 8);
  }, [items]);

  const hasPivots = assetPivots.length > 0 || packagePivots.length > 0;

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
      {/* ── Header ── */}
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
            <Button
              variant="subtle"
              size="lg"
              onClick={() => setDensity(density === "compact" ? "comfortable" : "compact")}
            >
              <span
                className={cx(
                  "h-2.5 w-2.5 rounded-full",
                  density === "compact" ? "bg-primary" : "bg-muted-foreground/50"
                )}
              />
              {density === "compact" ? "Compact" : "Comfortable"}
            </Button>

            <Button
              variant="subtle"
              size="lg"
              onClick={() => void Promise.all([refreshDashboardNow(), refreshRecentScansNow()])}
              disabled={busy && items.length === 0}
            >
              Refresh
            </Button>
          </div>
        }
      />

      {/* ── Section 1: Posture ── */}
      <Card
        title="Posture"
        right={
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span>window</span>
            <DraftNumberInput
              value={activeDays}
              onCommit={(n) => setActiveDays(n)}
              min={1}
              max={365}
              className="ui-input h-8 w-16 px-2 font-mono"
            />
            <span>days</span>
          </div>
        }
        className="rounded-xl"
      >
        {/* Primary metric row */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatItem
            label="Critical / High"
            value={posture ? posture.critical_open + posture.high_open : "—"}
            sub={
              posture
                ? `critical ${posture.critical_open} · high ${posture.high_open}`
                : "loading…"
            }
            loading={postureBusy}
          />
          <StatItem
            label="Exploitable"
            value={posture?.exploitable_open ?? "—"}
            sub="CVE + CVSS + exposure"
            loading={postureBusy}
          />
          <StatItem
            label="Awaiting Verification"
            value={summary?.total_awaiting_verification ?? "—"}
            sub="rescan pending"
            loading={summaryBusy}
          />
          <StatItem
            label="Fix Available"
            value={posture?.fixable_open ?? "—"}
            sub="remediation or OSV patch"
            loading={postureBusy}
          />
        </div>

        {/* Secondary metric strip */}
        <div className="mt-4 flex flex-wrap gap-x-6 gap-y-2 border-t border-border/30 pt-4">
          <div className="flex items-baseline gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Observed
            </span>
            <span
              className={cx(
                "font-mono text-sm tabular-nums transition-opacity",
                summaryBusy && "opacity-50"
              )}
            >
              {summary?.total_observed ?? "—"}
            </span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Stale &gt;30d
            </span>
            <span
              className={cx(
                "font-mono text-sm tabular-nums transition-opacity",
                postureBusy && "opacity-50"
              )}
            >
              {posture?.stale_open ?? "—"}
            </span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Mean risk
            </span>
            <span
              className={cx(
                "font-mono text-sm tabular-nums transition-opacity",
                postureBusy && "opacity-50"
              )}
            >
              {posture ? fmtRisk(posture.mean_risk) : "—"}
              {posture ? <span className="text-muted-foreground"> · p95 {fmtRisk(posture.p95_risk)}</span> : null}
            </span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Suppressed
            </span>
            <span
              className={cx(
                "font-mono text-sm tabular-nums transition-opacity",
                summaryBusy && "opacity-50"
              )}
            >
              {summary?.total_suppressed ?? "—"}
            </span>
          </div>
          {severityBlocks.length > 0 && (
            <div className="flex items-baseline gap-2">
              <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                Severity
              </span>
              <span className="flex flex-wrap gap-1.5">
                {severityBlocks.map((x) => (
                  <span key={x.k} className="inline-flex items-center gap-1 font-mono text-xs">
                    <Badge variant={sevVariant(x.k)}>{x.k}</Badge>
                    <span className="text-muted-foreground">{x.v}</span>
                  </span>
                ))}
              </span>
            </div>
          )}
        </div>
      </Card>

      {/* ── Posture detail tables ── */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card
          title="Priority Queue"
          right={
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              explainable ranking
            </span>
          }
          className="rounded-xl"
        >
          {!posture || posture.top_risks.length === 0 ? (
            <EmptyState title="No prioritized findings" description="No open findings in the selected window." />
          ) : (
            <div className="space-y-2">
              {posture.top_risks.map((x) => (
                <button
                  key={x.id}
                  type="button"
                  className="w-full rounded-md border border-border bg-card p-3 text-left transition-colors hover:border-primary/30 hover:bg-surface-2/70"
                  onClick={() => {
                    const row = items.find((it) => it.id === x.id);
                    if (row) {
                      setSelected(row);
                      setDrawerOpen(true);
                      return;
                    }
                    const next = { ...draft, cve: x.cve || "", q: x.cve ? "" : x.component_name || x.title };
                    setDraft(next);
                    setFilters(next);
                  }}
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <RiskScorePill score={x.risk_score} />
                        <SeverityPill variant={sevVariant(x.severity)} withDot>{x.severity}</SeverityPill>
                        <span className="text-[11px] text-muted-foreground">conf {x.confidence}</span>
                        <span className="text-[11px] text-muted-foreground">{x.exposure_source.replaceAll("_", " ")}</span>
                      </div>
                      <div className="mt-2 truncate font-mono text-[12px]" title={x.component_name || x.title}>
                        {x.component_name || x.title}
                      </div>
                      <div className="mt-1 text-[11px] text-muted-foreground">
                        {x.installed_version ? `installed ${x.installed_version}` : "installed version unknown"}
                        {x.fixed_version ? ` · fix ${x.fixed_version}` : " · no fix version recorded"}
                        {x.cve ? ` · ${x.cve}` : ""}
                      </div>
                      {x.risk_summary ? (
                        <div className="mt-2 line-clamp-2 text-sm text-foreground/85">{x.risk_summary}</div>
                      ) : null}
                      {x.priority_factors?.length ? (
                        <div className="mt-2 flex flex-wrap gap-1.5">
                          {x.priority_factors.slice(0, 4).map((factor) => (
                            <span
                              key={factor}
                              className="inline-flex items-center rounded border border-border bg-surface-2 px-2 py-0.5 font-mono text-[10px] text-muted-foreground"
                            >
                              {factor}
                            </span>
                          ))}
                        </div>
                      ) : null}
                    </div>
                    <div className="min-w-[170px] text-right text-[11px] text-muted-foreground">
                      <div className="font-mono text-[12px] text-foreground" title={x.asset_display}>
                        {x.asset_display}
                      </div>
                      <div className="mt-1">{x.has_fix ? "fix ready for validation" : "manual remediation required"}</div>
                      <div className="mt-1">seen {fmtAge(x.last_seen_at)}</div>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </Card>

        <Card
          title="Most exposed assets"
          right={
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              {posture?.top_assets?.length ?? 0} assets
            </span>
          }
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
                  className="w-full rounded-md border border-border bg-card p-3 text-left transition-colors hover:border-primary/30 hover:bg-surface-2/70"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div
                      className="truncate font-mono text-[12px]"
                      title={a.asset_agent_id ? `agent:${a.asset_agent_id}` : a.asset_key}
                    >
                      {a.asset_agent_id ? `agent:${a.asset_agent_id}` : a.asset_key}
                    </div>
                    <div className="font-mono text-[12px] text-muted-foreground">
                      max {fmtRisk(a.max_risk)}
                    </div>
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    open {a.open_findings} · critical/high {a.critical_high} · avg{" "}
                    {fmtRisk(a.avg_risk)} · seen {fmtAge(a.last_seen_at)}
                  </div>
                </button>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* ── Section 2: Scan execution ── */}
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
        onRefreshScans={() => void refreshRecentScansNow()}
        onViewScan={(scan) => {
          setSelectedScan(scan);
          setScanDrawerOpen(true);
        }}
        onlySelectedAgent={onlySelectedAgentScans}
        onToggleAgentFilter={() => setOnlySelectedAgentScans((v) => !v)}
      />

      {/* ── Section 3: Findings ── */}
      <Card
        title="Findings Queue"
        right={
          <div className="flex items-center gap-3">
            {busy && items.length > 0 && (
              <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/80 animate-pulse">
                updating
              </span>
            )}
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              {items.length} items
            </span>
            {activeFilterCount > 0 && (
              <span className="rounded border border-primary/30 px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-widest text-primary/70">
                {activeFilterCount} filter{activeFilterCount !== 1 ? "s" : ""}
              </span>
            )}
          </div>
        }
        className="rounded-xl"
      >
        {/* Filter grid */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <div className="text-xs text-muted-foreground">Search</div>
            <TextInput
              value={draft.q}
              onChange={(e) => setDraft((p) => ({ ...p, q: e.target.value }))}
              onKeyDown={(e) => e.key === "Enter" && applyFilters()}
              placeholder="title / CVE / external_id"
              className="mt-1"
            />
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Min severity</div>
            <SelectInput
              value={draft.minSeverity}
              onChange={(e) => setDraft((p) => ({ ...p, minSeverity: e.target.value }))}
              className="mt-1"
            >
              <option value="all">All</option>
              <option value="low">Low+</option>
              <option value="medium">Medium+</option>
              <option value="high">High+</option>
              <option value="critical">Critical</option>
            </SelectInput>
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Observation state</div>
            <SelectInput
              value={draft.observationState}
              onChange={(e) => setDraft((p) => ({ ...p, observationState: e.target.value }))}
              className="mt-1"
            >
              <option value="all">All</option>
              <option value="observed">Still observed</option>
              <option value="awaiting_verification">Pending verification</option>
              <option value="resolved">No longer observed</option>
            </SelectInput>
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Disposition</div>
            <SelectInput
              value={draft.disposition}
              onChange={(e) => setDraft((p) => ({ ...p, disposition: e.target.value }))}
              className="mt-1"
            >
              <option value="all">All</option>
              <option value="open">Active</option>
              <option value="accepted_risk">Risk accepted</option>
              <option value="suppressed">Suppressed</option>
            </SelectInput>
          </div>

          <div>
            <div className="text-xs text-muted-foreground">CVE</div>
            <TextInput
              value={draft.cve}
              onChange={(e) => setDraft((p) => ({ ...p, cve: e.target.value }))}
              onKeyDown={(e) => e.key === "Enter" && applyFilters()}
              placeholder="CVE-2024-1234"
              className="mt-1 font-mono"
            />
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Reporter agent</div>
            <TextInput
              value={draft.reporterAgentId}
              onChange={(e) => setDraft((p) => ({ ...p, reporterAgentId: e.target.value }))}
              onKeyDown={(e) => e.key === "Enter" && applyFilters()}
              placeholder="agent-id"
              className="mt-1 font-mono"
            />
          </div>

          <div>
            <div className="text-xs text-muted-foreground">Asset agent</div>
            <TextInput
              value={draft.assetAgentId}
              onChange={(e) => setDraft((p) => ({ ...p, assetAgentId: e.target.value }))}
              onKeyDown={(e) => e.key === "Enter" && applyFilters()}
              placeholder="agent-id"
              className="mt-1 font-mono"
            />
          </div>

          <div className="flex items-end justify-between gap-2">
            <div className="flex items-end gap-2">
              <span className="mb-2 text-xs text-muted-foreground">Page</span>
              <DraftNumberInput
                value={pageSize}
                onCommit={(n) => setPageSize(n)}
                min={1}
                max={200}
                className="ui-input h-10 w-20 font-mono"
              />
            </div>

            <div className="flex items-end gap-2">
              <Button
                variant={draft.includeSuppressed ? "secondary" : "subtle"}
                size="lg"
                onClick={() => setDraft((p) => ({ ...p, includeSuppressed: !p.includeSuppressed }))}
                className="mb-0"
              >
                <span
                  className={cx(
                    "h-2 w-2 rounded-full",
                    draft.includeSuppressed ? "bg-primary" : "bg-muted-foreground/40"
                  )}
                />
                Suppressed
              </Button>
            </div>
          </div>
        </div>

        {/* Filter action row */}
        <div className="mt-3 flex items-center gap-2">
          <Button variant="primary" size="lg" onClick={applyFilters}>Apply</Button>
          <Button variant="subtle" size="lg" onClick={resetFilters}>Reset</Button>
        </div>

        {/* Quick-pivot chips: assets and packages from loaded findings */}
        {hasPivots && (
          <div className="mt-4 space-y-2">
            {assetPivots.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/80">
                  Assets
                </span>
                {assetPivots.map((p) => (
                  <button
                    key={p.label}
                    type="button"
                    onClick={() => {
                      const agentId = p.label.startsWith("agent:") ? p.label.slice(6) : "";
                      const next = {
                        ...draft,
                        assetAgentId: agentId,
                        q: agentId ? draft.q : p.label,
                      };
                      setDraft(next);
                      setFilters(next);
                    }}
                    className={cx(
                      "inline-flex items-center gap-1 rounded border border-border bg-surface-2",
                      "px-2 py-0.5 font-mono text-[10px] text-muted-foreground",
                      "transition-colors hover:border-primary/30 hover:text-foreground"
                    )}
                  >
                    {p.label}
                    <span className="text-muted-foreground/50">×{p.count}</span>
                  </button>
                ))}
              </div>
            )}
            {packagePivots.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/80">
                  Packages
                </span>
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
                      "inline-flex items-center gap-1 rounded border border-border bg-surface-2",
                      "px-2 py-0.5 font-mono text-[10px] text-muted-foreground",
                      "transition-colors hover:border-primary/30 hover:text-foreground"
                    )}
                  >
                    {p.name}
                    <span className="text-muted-foreground/50">×{p.count}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Table divider */}
        <div className="mt-4 border-t border-border/40" />

        {/* Findings table — non-blanking: keep rows visible while updating */}
        {busy && items.length === 0 ? (
          <div className="py-16">
            <Loading label="Loading findings…" />
          </div>
        ) : error ? (
          <EmptyState title="Failed to load" description={error} />
        ) : items.length === 0 ? (
          <div className="py-16">
            <div className="flex flex-col items-center gap-3">
              <EmptyState title="No findings" description={findingsHint} />
              {activeFilterCount > 0 && (
                <Button variant="subtle" size="lg" onClick={resetFilters}>Clear filters</Button>
              )}
            </div>
          </div>
        ) : (
          <div className="w-full">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-[2] bg-surface-2/95 text-left text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground backdrop-blur-sm">
                <tr>
                  <th className="border-b border-border px-3 py-2.5">Finding</th>
                  <th className="border-b border-border px-3 py-2.5">Asset / Context</th>
                  <th className="border-b border-border px-3 py-2.5">Status</th>
                  <th className="border-b border-border px-3 py-2.5">Seen / Hits</th>
                  <th className="border-b border-border px-3 py-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((f) => {
                  const selectedRow = selected?.id === f.id;
                  const rowPad = dense ? "py-1.5" : "py-2.5";
                  const svc = (f.exposure?.service_hints || []).slice(0, 2);
                  const installedVersion = findingInstalledVersion(f);
                  const fixedVersion = findingFixedVersion(f);
                  return (
                    <tr
                      key={f.id}
                      className={cx(
                        "cursor-pointer border-t border-border/55 align-top ui-row",
                        selectedRow && "ui-row-selected",
                      )}
                      onClick={() => {
                        setSelected(f);
                        setDrawerOpen(true);
                      }}
                      role="button"
                      tabIndex={0}
                    >
                      <td className={cx("px-3", rowPad)}>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <RiskScorePill score={f.priority?.score} />
                          <SeverityPill variant={sevVariant(f.severity)} withDot>{f.severity}</SeverityPill>
                          <span className="text-[11px] text-muted-foreground">conf {f.confidence}</span>
                        </div>
                        <div className="mt-1 font-mono text-[12px] break-all" title={findingComponentLabel(f)}>
                          {findingComponentLabel(f)}
                        </div>
                        <div className="text-[11px] text-muted-foreground">
                          {installedVersion ? `installed ${installedVersion}` : "installed version unknown"}
                          {fixedVersion ? ` · fix ${fixedVersion}` : " · no fix version recorded"}
                          {f.cve ? ` · ${f.cve}` : ""}
                        </div>
                        <div className="mt-1 line-clamp-2 text-sm text-foreground/85">
                          {f.risk_summary || f.title}
                        </div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="font-mono text-[12px] break-all" title={findingAssetLabel(f)}>
                          {findingAssetLabel(f)}
                        </div>
                        <div className="text-[11px] text-muted-foreground">
                          {findingExposureLabel(f)}
                          {svc.length ? ` · ${svc.join(", ")}` : ""}
                        </div>
                        <div className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">
                          {f.asset_context?.length ? f.asset_context.join(" · ") : "-"}
                        </div>
                      </td>
                      <td className={cx("px-3", rowPad)}>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Badge variant={observationVariant(f.observation_state)}>
                            {findingObservationLabel(f)}
                          </Badge>
                          {f.operator_disposition !== "open" && (
                            <Badge variant={dispositionVariant(f.operator_disposition)}>
                              {findingDispositionLabel(f)}
                            </Badge>
                          )}
                        </div>
                        <div className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">
                          {f.remediation_guidance || "Await scanner evidence or analyst disposition."}
                        </div>
                      </td>
                      <td className={cx("px-3 font-mono text-[12px]", rowPad)}>
                        <div title={fmtWhen(f.last_seen_at)}>{fmtAge(f.last_seen_at)}</div>
                        <div className="text-[11px] text-muted-foreground" title={fmtWhen(f.first_seen_at)}>
                          first {fmtAge(f.first_seen_at)}
                        </div>
                        <div className="text-[11px] text-muted-foreground">{f.occurrences} hits</div>
                      </td>
                      <td className={cx("px-3 text-right", rowPad)}>
                        <Button
                          variant="subtle"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelected(f);
                            setDrawerOpen(true);
                          }}
                        >
                          View
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {hasMore && (
              <div className="mt-4 flex justify-center">
                <Button
                  variant="subtle"
                  size="lg"
                  disabled={busyMore}
                  onClick={() => void loadPage({ reset: false, cursor })}
                >
                  {busyMore ? "Loading…" : "Load more"}
                </Button>
              </div>
            )}
          </div>
        )}
      </Card>

      {/* ── Drawers ── */}
      <VulnFindingDrawer
        open={drawerOpen}
        finding={selected}
        onClose={() => setDrawerOpen(false)}
        onPatched={(next) => {
          setSelected(next);
          setItems((prev) => {
            const retained = prev.filter((item) => item.id !== next.id);
            const merged = findingMatchesFilters(next, filters) ? [...retained, next] : retained;
            return sortFindingsByPriority(merged);
          });
          scheduleMetricsRefresh();
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
