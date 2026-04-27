import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { listAgents } from "@/features/agents/api";
import type { AgentPublic } from "@/features/agents/types";
import { useAuth } from "@/features/auth/context";
import { Button } from "@/shared/components/Button";
import { Card } from "@/shared/components/Card";
import { DataQueryStateBanner } from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import PageHeader from "@/shared/components/PageHeader";
import { useDataTablePreferences } from "@/shared/hooks/useDataTablePreferences";
import { isAbortError } from "@/shared/lib/http";
import { usePortalRealtimeSubscription } from "@/shared/realtime";
import { CursorPage } from "@/shared/types/pagination";

import {
  createAssetTriageAction,
  getExposureAssetDetail,
  getExposureAssetGraph,
  getExposureSummary,
  listExposureAssets,
  listExposureFindings,
  listExposurePaths,
  openAssetInvestigation,
  requestExposureRecalculate,
} from "./api";
import { ExposureAssetDrawer } from "./components/ExposureAssetDrawer";
import { ExposureAssetTable } from "./components/ExposureAssetTable";
import { ExposureAttackPathTimeline } from "./components/ExposureAttackPathTimeline";
import { ExposureFiltersBar } from "./components/ExposureFiltersBar";
import { ExposureFindingDrawer } from "./components/ExposureFindingDrawer";
import { ExposureFindingList } from "./components/ExposureFindingList";
import { ExposureGraphCanvas } from "./components/ExposureGraphCanvas";
import { ExposureGraphLegend } from "./components/ExposureGraphLegend";
import { ExposureSummaryCards } from "./components/ExposureSummaryCards";
import { DEFAULT_ASSET_FILTERS, type AssetFilters } from "./filters";
import type {
  ExposureAssetDetail,
  ExposureAssetPosture,
  ExposureAttackPath,
  ExposureFinding,
  ExposureGraph,
  ExposureGraphNode,
  ExposureInvestigationResult,
  ExposureSummary,
  ExposureTriageResponseAction,
} from "./types";
import { toTitleCase } from "./utils";

type Tab = "assets" | "paths" | "graph" | "findings";
type RealtimeRefreshKey = "summary" | "assets" | "selectedAsset" | "graph" | "findings";

function normalizeError(error: unknown): string {
  const candidate = error as {
    message?: unknown;
    status?: unknown;
    body?: {
      detail?: unknown;
      message?: unknown;
      code?: unknown;
      request_id?: unknown;
    };
  };

  const flatten = (value: unknown): string | null => {
    if (!value) return null;
    if (typeof value === "string") return value.trim() || null;
    if (typeof value !== "object") return String(value);
    const maybe = value as {
      message?: unknown;
      detail?: unknown;
      code?: unknown;
      context?: { asset_key?: unknown };
      request_id?: unknown;
    };
    const nested = flatten(maybe.message) ?? flatten(maybe.detail);
    if (!nested) return null;
    const code = typeof maybe.code === "string" && maybe.code.trim() ? ` (${maybe.code})` : "";
    const assetKey =
      maybe.context && typeof maybe.context === "object" && typeof maybe.context.asset_key === "string"
        ? ` · asset ${maybe.context.asset_key}`
        : "";
    return `${nested}${code}${assetKey}`;
  };

  const bodyMessage = flatten(candidate?.body?.detail) ?? flatten(candidate?.body?.message);
  if (bodyMessage) return bodyMessage;
  if (typeof candidate?.message === "string" && candidate.message.trim() && candidate.message !== "[object Object]") {
    return candidate.message;
  }
  if (candidate?.status === 404) return "Exposure graph endpoint or asset graph data was not found.";
  return "Request failed";
}

function mergeAssetIntoPage(
  page: CursorPage<ExposureAssetPosture> | null,
  nextAsset: ExposureAssetPosture,
): CursorPage<ExposureAssetPosture> | null {
  if (!page) return page;
  return {
    ...page,
    items: page.items.map((item) => (item.asset_key === nextAsset.asset_key ? nextAsset : item)),
  };
}

export default function ExposurePage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const assetTablePrefs = useDataTablePreferences({
    storageKey: "exposure.assets.table",
    defaultPageSize: 50,
    minPageSize: 25,
    maxPageSize: 200,
    defaultCompact: true,
  });

  const [tab, setTab] = useState<Tab>("assets");
  const [draftFilters, setDraftFilters] = useState<AssetFilters>(DEFAULT_ASSET_FILTERS);
  const [assetFilters, setAssetFilters] = useState<AssetFilters>(DEFAULT_ASSET_FILTERS);

  const [agents, setAgents] = useState<AgentPublic[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(false);

  const [summary, setSummary] = useState<ExposureSummary | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(true);
  const [summaryRefreshing, setSummaryRefreshing] = useState(false);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  const [assetsPage, setAssetsPage] = useState<CursorPage<ExposureAssetPosture> | null>(null);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [assetsRefreshing, setAssetsRefreshing] = useState(false);
  const [assetsLoadingMore, setAssetsLoadingMore] = useState(false);
  const [assetsError, setAssetsError] = useState<string | null>(null);
  const [assetsCursor, setAssetsCursor] = useState<string | null>(null);

  const [pathsPage, setPathsPage] = useState<CursorPage<ExposureAttackPath> | null>(null);
  const [pathsLoading, setPathsLoading] = useState(false);
  const [pathsRefreshing, setPathsRefreshing] = useState(false);
  const [pathsLoadingMore, setPathsLoadingMore] = useState(false);
  const [pathsError, setPathsError] = useState<string | null>(null);
  const [pathsCursor, setPathsCursor] = useState<string | null>(null);

  const [findingsPage, setFindingsPage] = useState<CursorPage<ExposureFinding> | null>(null);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsRefreshing, setFindingsRefreshing] = useState(false);
  const [findingsLoadingMore, setFindingsLoadingMore] = useState(false);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [findingsCursor, setFindingsCursor] = useState<string | null>(null);

  const [selectedAsset, setSelectedAsset] = useState<ExposureAssetPosture | null>(null);
  const [assetDetail, setAssetDetail] = useState<ExposureAssetDetail | null>(null);
  const [assetDetailLoading, setAssetDetailLoading] = useState(false);
  const [assetDetailError, setAssetDetailError] = useState<string | null>(null);

  const [selectedFinding, setSelectedFinding] = useState<ExposureFinding | null>(null);

  const [graphData, setGraphData] = useState<ExposureGraph | null>(null);
  const [graphLabel, setGraphLabel] = useState<string | null>(null);
  const [graphAssetKey, setGraphAssetKey] = useState<string | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphRefreshing, setGraphRefreshing] = useState(false);
  const [graphError, setGraphError] = useState<string | null>(null);

  const [recalculateBusy, setRecalculateBusy] = useState(false);
  const [recalculateMessage, setRecalculateMessage] = useState<string | null>(null);
  const [recalculateError, setRecalculateError] = useState<string | null>(null);

  const timersRef = useRef<Partial<Record<RealtimeRefreshKey, number>>>({});
  const didBootstrapRef = useRef(false);
  const didRunInitialAssetsFetchRef = useRef(false);

  const assetsPageRef = useRef<CursorPage<ExposureAssetPosture> | null>(assetsPage);
  const findingsPageRef = useRef<CursorPage<ExposureFinding> | null>(findingsPage);
  const selectedAssetRef = useRef<ExposureAssetPosture | null>(selectedAsset);
  const graphAssetKeyRef = useRef<string | null>(graphAssetKey);
  const graphLabelRef = useRef<string | null>(graphLabel);
  const assetDetailRef = useRef<ExposureAssetDetail | null>(assetDetail);
  const tabRef = useRef<Tab>(tab);
  const filtersRef = useRef<AssetFilters>(assetFilters);

  assetsPageRef.current = assetsPage;
  findingsPageRef.current = findingsPage;
  selectedAssetRef.current = selectedAsset;
  graphAssetKeyRef.current = graphAssetKey;
  graphLabelRef.current = graphLabel;
  assetDetailRef.current = assetDetail;
  tabRef.current = tab;
  filtersRef.current = assetFilters;

  const agentOptions = useMemo(
    () =>
      agents.map((agent) => ({
        value: agent.agent_id,
        label: agent.display_name ? `${agent.display_name} (${agent.agent_id})` : agent.agent_id,
      })),
    [agents],
  );

  const reasonCodeOptions = useMemo(() => {
    const counts = summary?.top_reason_codes ?? [];
    return counts.map((item) => ({
      value: item.key,
      label: `${toTitleCase(item.key)} (${item.count})`,
    }));
  }, [summary]);

  const refreshAssetPageSize = useCallback(() => {
    const loaded = assetsPageRef.current?.items.length ?? 0;
    return Math.max(assetTablePrefs.pageSize, loaded || assetTablePrefs.pageSize);
  }, [assetTablePrefs.pageSize]);

  const refreshFindingsPageSize = useCallback(() => {
    const loaded = findingsPageRef.current?.items.length ?? 0;
    return Math.max(50, loaded || 50);
  }, []);

  const queueRealtimeRefresh = useCallback((key: RealtimeRefreshKey, task: () => void, delayMs = 450) => {
    const current = timersRef.current[key];
    if (current) window.clearTimeout(current);
    timersRef.current[key] = window.setTimeout(() => {
      timersRef.current[key] = undefined;
      task();
    }, delayMs);
  }, []);

  const fetchSummary = useCallback(async (signal?: AbortSignal) => {
    const hasData = summary !== null;
    if (hasData) setSummaryRefreshing(true);
    else setSummaryLoading(true);
    try {
      const data = await getExposureSummary(signal);
      if (signal?.aborted) return;
      setSummary(data);
      setSummaryError(null);
    } catch (error) {
      if (isAbortError(error) || signal?.aborted) return;
      setSummaryError(normalizeError(error));
    } finally {
      if (signal?.aborted) return;
      setSummaryLoading(false);
      setSummaryRefreshing(false);
    }
  }, [summary]);

  const fetchAssets = useCallback(
    async ({
      cursor = null,
      signal,
      pageSize,
    }: {
      cursor?: string | null;
      signal?: AbortSignal;
      pageSize?: number;
    } = {}) => {
      const hasData = (assetsPageRef.current?.items.length ?? 0) > 0;
      if (cursor) setAssetsLoadingMore(true);
      else if (hasData) setAssetsRefreshing(true);
      else setAssetsLoading(true);

      const filters = filtersRef.current;
      const nextPageSize = pageSize ?? (cursor ? assetTablePrefs.pageSize : refreshAssetPageSize());

      try {
        const data = await listExposureAssets({
          page_size: nextPageSize,
          cursor,
          q: filters.q || undefined,
          severity: filters.severity || undefined,
          min_score: filters.min_score ?? undefined,
          agent_id: filters.agent_id || undefined,
          status: filters.status || undefined,
          reason_code: filters.reason_code || undefined,
          sort: filters.sort,
          has_attack_chain: filters.has_attack_chain ?? undefined,
          has_critical_vuln: filters.has_critical_vuln ?? undefined,
          has_persistence_signal: filters.has_persistence_signal ?? undefined,
          signal,
        });
        if (signal?.aborted) return;
        setAssetsPage((prev) => (cursor && prev ? { ...data, items: [...prev.items, ...data.items] } : data));
        setAssetsCursor(data.next_cursor);
        setAssetsError(null);
      } catch (error) {
        if (isAbortError(error) || signal?.aborted) return;
        setAssetsError(normalizeError(error));
      } finally {
        if (signal?.aborted) return;
        setAssetsLoading(false);
        setAssetsRefreshing(false);
        setAssetsLoadingMore(false);
      }
    },
    [assetTablePrefs.pageSize, refreshAssetPageSize],
  );

  const fetchPaths = useCallback(
    async ({
      cursor = null,
      signal,
      pageSize = 25,
    }: {
      cursor?: string | null;
      signal?: AbortSignal;
      pageSize?: number;
    } = {}) => {
      const hasData = (pathsPage?.items.length ?? 0) > 0;
      if (cursor) setPathsLoadingMore(true);
      else if (hasData) setPathsRefreshing(true);
      else setPathsLoading(true);
      try {
        const data = await listExposurePaths({ page_size: pageSize, cursor, signal });
        if (signal?.aborted) return;
        setPathsPage((prev) => (cursor && prev ? { ...data, items: [...prev.items, ...data.items] } : data));
        setPathsCursor(data.next_cursor);
        setPathsError(null);
      } catch (error) {
        if (isAbortError(error) || signal?.aborted) return;
        setPathsError(normalizeError(error));
      } finally {
        if (signal?.aborted) return;
        setPathsLoading(false);
        setPathsRefreshing(false);
        setPathsLoadingMore(false);
      }
    },
    [pathsPage],
  );

  const fetchFindings = useCallback(
    async ({
      cursor = null,
      signal,
      pageSize,
    }: {
      cursor?: string | null;
      signal?: AbortSignal;
      pageSize?: number;
    } = {}) => {
      const hasData = (findingsPageRef.current?.items.length ?? 0) > 0;
      if (cursor) setFindingsLoadingMore(true);
      else if (hasData) setFindingsRefreshing(true);
      else setFindingsLoading(true);
      try {
        const data = await listExposureFindings({
          page_size: pageSize ?? (cursor ? 50 : refreshFindingsPageSize()),
          cursor,
          signal,
        });
        if (signal?.aborted) return;
        setFindingsPage((prev) => (cursor && prev ? { ...data, items: [...prev.items, ...data.items] } : data));
        setFindingsCursor(data.next_cursor);
        setFindingsError(null);
      } catch (error) {
        if (isAbortError(error) || signal?.aborted) return;
        setFindingsError(normalizeError(error));
      } finally {
        if (signal?.aborted) return;
        setFindingsLoading(false);
        setFindingsRefreshing(false);
        setFindingsLoadingMore(false);
      }
    },
    [refreshFindingsPageSize],
  );

  const loadAssetDetail = useCallback(
    async (
      assetKey: string,
      opts: {
        asset?: ExposureAssetPosture | null;
        preserveDetail?: boolean;
        signal?: AbortSignal;
      } = {},
    ) => {
      if (opts.asset) setSelectedAsset(opts.asset);
      const currentKey = assetDetailRef.current?.posture.asset_key;
      if (!opts.preserveDetail || currentKey !== assetKey) {
        setAssetDetail(null);
      }
      setAssetDetailLoading(true);
      try {
        const detail = await getExposureAssetDetail(assetKey, opts.signal);
        if (opts.signal?.aborted) return;
        setAssetDetail(detail);
        setSelectedAsset(detail.posture);
        setAssetsPage((prev) => mergeAssetIntoPage(prev, detail.posture));
        setAssetDetailError(null);
      } catch (error) {
        if (isAbortError(error) || opts.signal?.aborted) return;
        setAssetDetailError(normalizeError(error));
      } finally {
        if (opts.signal?.aborted) return;
        setAssetDetailLoading(false);
      }
    },
    [],
  );

  const loadGraph = useCallback(
    async (
      assetKey: string,
      label: string,
      opts: {
        preserveGraph?: boolean;
        signal?: AbortSignal;
      } = {},
    ) => {
      setGraphAssetKey(assetKey);
      setGraphLabel(label);
      setTab("graph");
      if (!opts.preserveGraph || graphAssetKeyRef.current !== assetKey) {
        setGraphData(null);
      }
      if (graphData && graphAssetKeyRef.current === assetKey) setGraphRefreshing(true);
      else setGraphLoading(true);
      try {
        const data = await getExposureAssetGraph(assetKey, { signal: opts.signal });
        if (opts.signal?.aborted) return;
        setGraphData(data);
        setGraphError(null);
      } catch (error) {
        if (isAbortError(error) || opts.signal?.aborted) return;
        setGraphError(normalizeError(error));
      } finally {
        if (opts.signal?.aborted) return;
        setGraphLoading(false);
        setGraphRefreshing(false);
      }
    },
    [graphData],
  );

  const handleSelectAsset = useCallback(
    async (asset: ExposureAssetPosture) => {
      setSelectedAsset(asset);
      setAssetDetailError(null);
      await loadAssetDetail(asset.asset_key, { asset, preserveDetail: false });
    },
    [loadAssetDetail],
  );

  const handleGraphNodeInspect = useCallback(
    async (node: ExposureGraphNode) => {
      if (!node.asset_key) return;
      const knownAsset = assetsPageRef.current?.items.find((asset) => asset.asset_key === node.asset_key) ?? null;
      setSelectedAsset(knownAsset);
      setAssetDetailError(null);
      await loadAssetDetail(node.asset_key, { asset: knownAsset, preserveDetail: false });
    },
    [loadAssetDetail],
  );

  const handleViewGraph = useCallback(
    (assetKey: string) => {
      const asset = assetsPageRef.current?.items.find((item) => item.asset_key === assetKey) ?? null;
      const label = asset?.display_name || selectedAssetRef.current?.display_name || assetKey;
      void loadGraph(assetKey, label, { preserveGraph: false });
    },
    [loadGraph],
  );

  const handleOpenInvestigation = useCallback(
    async (assetKey: string): Promise<ExposureInvestigationResult | void> => {
      if (!isAdmin) return;
      const result = await openAssetInvestigation(assetKey);
      navigate(`/investigations?workspace_id=${encodeURIComponent(String(result.workspace_id))}`);
      return result;
    },
    [isAdmin, navigate],
  );

  const handleCreateTriageAction = useCallback(
    async (assetKey: string): Promise<ExposureTriageResponseAction | void> => {
      if (!isAdmin) return;
      return createAssetTriageAction(assetKey);
    },
    [isAdmin],
  );

  const handleRefreshSelectedAsset = useCallback(
    async (assetKey: string) => {
      const selected = selectedAssetRef.current;
      await loadAssetDetail(assetKey, { asset: selected, preserveDetail: true });
      if (graphAssetKeyRef.current === assetKey && graphLabelRef.current) {
        await loadGraph(assetKey, graphLabelRef.current, { preserveGraph: true });
      }
    },
    [loadAssetDetail, loadGraph],
  );

  const handleRecalculate = useCallback(async () => {
    if (!isAdmin || recalculateBusy) return;
    setRecalculateBusy(true);
    setRecalculateError(null);
    setRecalculateMessage(null);
    try {
      const result = await requestExposureRecalculate();
      setRecalculateMessage(`Exposure recalculation accepted at ${result.requested_at}.`);
    } catch (error) {
      setRecalculateError(normalizeError(error));
    } finally {
      setRecalculateBusy(false);
    }
  }, [isAdmin, recalculateBusy]);

  useEffect(() => {
    if (didBootstrapRef.current) return;
    didBootstrapRef.current = true;
    const ac = new AbortController();
    void fetchSummary(ac.signal);
    void fetchAssets({ signal: ac.signal, pageSize: assetTablePrefs.pageSize });
    setAgentsLoading(true);
    listAgents()
      .then((items) => {
        if (ac.signal.aborted) return;
        setAgents(items || []);
      })
      .catch(() => {
        if (ac.signal.aborted) return;
        setAgents([]);
      })
      .finally(() => {
        if (ac.signal.aborted) return;
        setAgentsLoading(false);
      });
    return () => {
      ac.abort();
    };
  }, [assetTablePrefs.pageSize, fetchAssets, fetchSummary]);

  useEffect(() => {
    if (!didRunInitialAssetsFetchRef.current) {
      didRunInitialAssetsFetchRef.current = true;
      return;
    }
    const ac = new AbortController();
    void fetchAssets({ signal: ac.signal, pageSize: assetTablePrefs.pageSize });
    return () => ac.abort();
  }, [assetFilters, assetTablePrefs.pageSize, fetchAssets]);

  useEffect(() => {
    if (tab === "paths" && !pathsPage && !pathsLoading) {
      const ac = new AbortController();
      void fetchPaths({ signal: ac.signal });
      return () => ac.abort();
    }
    if (tab === "findings" && !findingsPage && !findingsLoading) {
      const ac = new AbortController();
      void fetchFindings({ signal: ac.signal });
      return () => ac.abort();
    }
    return undefined;
  }, [fetchFindings, fetchPaths, findingsLoading, findingsPage, pathsLoading, pathsPage, tab]);

  useEffect(() => {
    const timers = timersRef.current;
    return () => {
      for (const timer of Object.values(timers)) {
        if (timer) window.clearTimeout(timer);
      }
    };
  }, []);

  usePortalRealtimeSubscription("exposure.summary.updated", () => {
    queueRealtimeRefresh("summary", () => {
      void fetchSummary();
    });
  });

  usePortalRealtimeSubscription("exposure.asset.updated", (event) => {
    const assetKey = String(event.payload?.asset_key || "").trim() || null;
    queueRealtimeRefresh("assets", () => {
      void fetchAssets({ pageSize: refreshAssetPageSize() });
    });
    if (assetKey && selectedAssetRef.current?.asset_key === assetKey) {
      queueRealtimeRefresh("selectedAsset", () => {
        void loadAssetDetail(assetKey, { asset: selectedAssetRef.current, preserveDetail: true });
      });
    }
    if (assetKey && graphAssetKeyRef.current === assetKey && graphLabelRef.current) {
      queueRealtimeRefresh("graph", () => {
        void loadGraph(assetKey, graphLabelRef.current || assetKey, { preserveGraph: true });
      });
    }
  });

  usePortalRealtimeSubscription("exposure.finding.updated", (event) => {
    const assetKey = String(event.payload?.asset_key || "").trim() || null;
    if (tabRef.current === "findings") {
      queueRealtimeRefresh("findings", () => {
        void fetchFindings({ pageSize: refreshFindingsPageSize() });
      });
    }
    if (assetKey && selectedAssetRef.current?.asset_key === assetKey) {
      queueRealtimeRefresh("selectedAsset", () => {
        void loadAssetDetail(assetKey, { asset: selectedAssetRef.current, preserveDetail: true });
      });
    }
  });

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: "assets", label: "Asset Posture" },
    { id: "paths", label: "Attack Paths" },
    { id: "graph", label: "Graph" },
    { id: "findings", label: "Findings" },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Exposure Graph"
        breadcrumb={["Assets & Exposure", "Exposure Graph"]}
        description="Asset risk, evidence relationships, and attack-path prioritization."
        toolbarRight={
          isAdmin ? (
            <Button variant="subtle" size="lg" onClick={() => void handleRecalculate()} disabled={recalculateBusy}>
              {recalculateBusy ? "Recalculating…" : "Recalculate"}
            </Button>
          ) : undefined
        }
      />

      <div className="space-y-3 px-4 sm:px-5">
        {recalculateError ? <DataQueryStateBanner tone="danger" message={recalculateError} /> : null}
        {recalculateMessage ? <DataQueryStateBanner tone="success" message={recalculateMessage} /> : null}
        {summaryError ? (
          <DataQueryStateBanner
            tone="danger"
            message={summaryError}
            right={
              <Button variant="danger" size="sm" onClick={() => void fetchSummary()}>
                Retry
              </Button>
            }
          />
        ) : summaryRefreshing ? (
          <DataQueryStateBanner tone="neutral" message="Refreshing summary from exposure backend…" />
        ) : null}
        <ExposureSummaryCards summary={summary} loading={summaryLoading && !summary} />
      </div>

      <div className="px-4 sm:px-5">
        <div className="ui-tab-shell border-b border-border/60">
          {tabs.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`ui-tab-item${tab === item.id ? " ui-tab-item-active" : ""}`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      <div className="px-4 sm:px-5">
        {tab === "assets" ? (
          <Card
            title="Asset posture"
            right={
              <div className="flex items-center gap-2">
                {agentsLoading ? <span className="font-mono text-[11px] text-muted-foreground">loading agents</span> : null}
                <Button variant="ghost" size="sm" onClick={() => void fetchAssets({ pageSize: refreshAssetPageSize() })}>
                  Refresh
                </Button>
              </div>
            }
          >
            <div className="space-y-4">
              <ExposureFiltersBar
                filters={draftFilters}
                agentOptions={agentOptions}
                reasonCodeOptions={reasonCodeOptions}
                onChange={(next) => setDraftFilters((prev) => ({ ...prev, ...next }))}
                onApply={() => setAssetFilters(draftFilters)}
                onReset={() => {
                  setDraftFilters(DEFAULT_ASSET_FILTERS);
                  setAssetFilters(DEFAULT_ASSET_FILTERS);
                }}
                applying={assetsLoading || assetsRefreshing}
              />

              {assetsPage?.items.length === 0 && !assetsLoading ? (
                <EmptyState
                  title="No assets match the current posture filters"
                  description="Reduce filters or wait for the exposure worker to publish asset posture rows."
                />
              ) : (
                <ExposureAssetTable
                  page={assetsPage}
                  loading={assetsLoading}
                  loadingMore={assetsLoadingMore}
                  refreshing={assetsRefreshing}
                  error={assetsError}
                  compact={assetTablePrefs.compact}
                  pageSize={assetTablePrefs.pageSize}
                  selectedAssetKey={selectedAsset?.asset_key ?? null}
                  onCompactChange={assetTablePrefs.setCompact}
                  onPageSizeChange={assetTablePrefs.setPageSize}
                  onSelect={(asset) => void handleSelectAsset(asset)}
                  onViewGraph={(asset) => handleViewGraph(asset.asset_key)}
                  onLoadMore={() => assetsCursor && void fetchAssets({ cursor: assetsCursor, pageSize: assetTablePrefs.pageSize })}
                  onRetry={() => void fetchAssets({ pageSize: refreshAssetPageSize() })}
                />
              )}
            </div>
          </Card>
        ) : null}

        {tab === "paths" ? (
          <Card
            title="Attack paths"
            right={
              <Button variant="ghost" size="sm" onClick={() => void fetchPaths()}>
                Refresh
              </Button>
            }
          >
            <div className="space-y-4">
              {pathsError ? (
                <DataQueryStateBanner
                  tone="danger"
                  message={pathsError}
                  right={
                    <Button variant="danger" size="sm" onClick={() => void fetchPaths()}>
                      Retry
                    </Button>
                  }
                />
              ) : pathsRefreshing ? (
                <DataQueryStateBanner tone="neutral" message="Refreshing attack paths…" />
              ) : null}

              {pathsPage?.items.length === 0 && !pathsLoading ? (
                <EmptyState
                  title="No attack paths"
                  description="No backend-prioritized attack paths are active for the current exposure corpus."
                />
              ) : (
                <div className="space-y-4">
                  {pathsPage?.items.map((path) => (
                    <div key={path.path_key} className="rounded-lg border border-border/60 bg-background/35 p-4">
                      <div className="mb-3 flex justify-end">
                        <Button variant="ghost" size="sm" onClick={() => handleViewGraph(path.asset_key)}>
                          View graph
                        </Button>
                      </div>
                      <ExposureAttackPathTimeline path={path} />
                    </div>
                  ))}
                  {pathsLoading && !pathsPage?.items.length ? <div className="text-sm text-muted-foreground">Loading attack paths…</div> : null}
                  {pathsPage?.has_more ? (
                    <div className="pt-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="w-full"
                        onClick={() => pathsCursor && void fetchPaths({ cursor: pathsCursor })}
                        disabled={pathsLoadingMore}
                      >
                        {pathsLoadingMore ? "Loading…" : "Load more"}
                      </Button>
                    </div>
                  ) : null}
                </div>
              )}
            </div>
          </Card>
        ) : null}

        {tab === "graph" ? (
          <Card
            title={graphLabel ? `Attack graph · ${graphLabel}` : "Attack graph"}
            right={
              <div className="flex items-center gap-2">
                {graphData ? (
                  <span className="font-mono text-[11px] text-muted-foreground">
                    {graphData.graph_health.node_count} nodes · {graphData.graph_health.edge_count} edges
                  </span>
                ) : null}
                {graphAssetKey ? (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => graphAssetKey && graphLabel && void loadGraph(graphAssetKey, graphLabel, { preserveGraph: true })}
                  >
                    Refresh
                  </Button>
                ) : null}
              </div>
            }
          >
            <div className="space-y-4">
              {graphError ? (
                <DataQueryStateBanner
                  tone="danger"
                  message={graphError}
                  right={
                    graphAssetKey && graphLabel ? (
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => void loadGraph(graphAssetKey, graphLabel, { preserveGraph: true })}
                      >
                        Retry
                      </Button>
                    ) : undefined
                  }
                />
              ) : graphRefreshing ? (
                <DataQueryStateBanner tone="neutral" message="Refreshing graph relationships…" />
              ) : null}

              {!graphData && !graphLoading && graphAssetKey && graphError ? (
                <EmptyState
                  title="Graph unavailable"
                  description={`Unable to load the backend graph for ${graphLabel || graphAssetKey}. ${graphError}`}
                />
              ) : null}
              {!graphData && !graphLoading && !graphAssetKey ? (
                <EmptyState
                  title="No graph selected"
                  description="Use Graph from an asset or attack-path record to load the backend relationship graph here."
                />
              ) : null}
              {graphLoading && !graphData ? <div className="text-sm text-muted-foreground">Loading graph…</div> : null}
              {graphData ? (
                <>
                  <ExposureGraphCanvas graph={graphData} onNodeClick={(node) => void handleGraphNodeInspect(node)} />
                  <ExposureGraphLegend legend={graphData.legend} />
                </>
              ) : null}
            </div>
          </Card>
        ) : null}

        {tab === "findings" ? (
          <Card
            title="Findings"
            right={
              <Button variant="ghost" size="sm" onClick={() => void fetchFindings({ pageSize: refreshFindingsPageSize() })}>
                Refresh
              </Button>
            }
          >
            {findingsPage?.items.length === 0 && !findingsLoading ? (
              <EmptyState
                title="No findings"
                description="No normalized exposure findings are currently attached to the backend posture set."
              />
            ) : (
              <ExposureFindingList
                page={findingsPage}
                loading={findingsLoading}
                loadingMore={findingsLoadingMore}
                refreshing={findingsRefreshing}
                error={findingsError}
                onSelect={setSelectedFinding}
                onLoadMore={() => findingsCursor && void fetchFindings({ cursor: findingsCursor, pageSize: 50 })}
                onRetry={() => void fetchFindings({ pageSize: refreshFindingsPageSize() })}
                selectedFindingKey={selectedFinding?.finding_key ?? null}
              />
            )}
          </Card>
        ) : null}
      </div>

      <ExposureAssetDrawer
        asset={selectedAsset}
        detail={assetDetail}
        detailLoading={assetDetailLoading}
        detailError={assetDetailError}
        onClose={() => {
          setSelectedAsset(null);
          setAssetDetail(null);
          setAssetDetailError(null);
        }}
        onOpenInvestigation={handleOpenInvestigation}
        onCreateTriageAction={handleCreateTriageAction}
        onRefreshAsset={handleRefreshSelectedAsset}
        onViewGraph={(assetKey) => {
          handleViewGraph(assetKey);
          setSelectedAsset(null);
          setAssetDetail(null);
          setAssetDetailError(null);
        }}
        isAdmin={isAdmin}
      />

      <ExposureFindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
}
