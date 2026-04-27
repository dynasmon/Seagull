import { useCallback, useEffect, useRef, useState } from "react";

import { Button } from "@/shared/components/Button";
import { Card } from "@/shared/components/Card";
import EmptyState from "@/shared/components/EmptyState";
import PageHeader from "@/shared/components/PageHeader";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";
import { CursorPage } from "@/shared/types/pagination";
import { useAuth } from "@/features/auth/context";

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
import { ExposureRecommendationsPanel } from "./components/ExposureRecommendationsPanel";
import { ExposureSummaryCards } from "./components/ExposureSummaryCards";
import { DEFAULT_ASSET_FILTERS, AssetFilters } from "./filters";
import {
  ExposureAssetDetail,
  ExposureAssetPosture,
  ExposureAttackPath,
  ExposureFinding,
  ExposureGraph,
  ExposureSummary,
} from "./types";

type Tab = "assets" | "paths" | "graph" | "findings";

export default function ExposurePage() {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const [tab, setTab] = useState<Tab>("assets");
  const [assetFilters, setAssetFilters] = useState<AssetFilters>(DEFAULT_ASSET_FILTERS);
  const filterRef = useRef(assetFilters);
  filterRef.current = assetFilters;

  const [summary, setSummary] = useState<ExposureSummary | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(true);

  const [assetsPage, setAssetsPage] = useState<CursorPage<ExposureAssetPosture> | null>(null);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [assetsCursor, setAssetsCursor] = useState<string | null>(null);

  const [pathsPage, setPathsPage] = useState<CursorPage<ExposureAttackPath> | null>(null);
  const [pathsLoading, setPathsLoading] = useState(false);
  const [pathsCursor, setPathsCursor] = useState<string | null>(null);

  const [findingsPage, setFindingsPage] = useState<CursorPage<ExposureFinding> | null>(null);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsCursor, setFindingsCursor] = useState<string | null>(null);

  const [selectedAsset, setSelectedAsset] = useState<ExposureAssetPosture | null>(null);
  const [assetDetail, setAssetDetail] = useState<ExposureAssetDetail | null>(null);
  const [assetDetailLoading, setAssetDetailLoading] = useState(false);

  const [selectedFinding, setSelectedFinding] = useState<ExposureFinding | null>(null);

  const [graphData, setGraphData] = useState<ExposureGraph | null>(null);
  const [graphLabel, setGraphLabel] = useState<string | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);

  const fetchSummary = useCallback(async (signal?: AbortSignal) => {
    setSummaryLoading(true);
    try {
      const data = await getExposureSummary(signal);
      if (!signal?.aborted) setSummary(data);
    } finally {
      if (!signal?.aborted) setSummaryLoading(false);
    }
  }, []);

  const fetchAssets = useCallback(async (cursor: string | null = null, signal?: AbortSignal) => {
    setAssetsLoading(true);
    const f = filterRef.current;
    try {
      const data = await listExposureAssets({
        cursor,
        q: f.q || undefined,
        severity: f.severity || undefined,
        sort: f.sort,
        has_attack_chain: f.has_attack_chain ?? undefined,
        has_critical_vuln: f.has_critical_vuln ?? undefined,
        has_persistence_signal: f.has_persistence_signal ?? undefined,
        signal,
      });
      if (!signal?.aborted) {
        setAssetsPage((prev) =>
          cursor && prev ? { ...data, items: [...prev.items, ...data.items] } : data,
        );
        setAssetsCursor(data.next_cursor);
      }
    } finally {
      if (!signal?.aborted) setAssetsLoading(false);
    }
  }, []);

  const fetchPaths = useCallback(async (cursor: string | null = null, signal?: AbortSignal) => {
    setPathsLoading(true);
    try {
      const data = await listExposurePaths({ cursor: cursor ?? undefined, signal });
      if (!signal?.aborted) {
        setPathsPage((prev) =>
          cursor && prev ? { ...data, items: [...prev.items, ...data.items] } : data,
        );
        setPathsCursor(data.next_cursor);
      }
    } finally {
      if (!signal?.aborted) setPathsLoading(false);
    }
  }, []);

  const fetchFindings = useCallback(async (cursor: string | null = null, signal?: AbortSignal) => {
    setFindingsLoading(true);
    try {
      const data = await listExposureFindings({ cursor: cursor ?? undefined, signal });
      if (!signal?.aborted) {
        setFindingsPage((prev) =>
          cursor && prev ? { ...data, items: [...prev.items, ...data.items] } : data,
        );
        setFindingsCursor(data.next_cursor);
      }
    } finally {
      if (!signal?.aborted) setFindingsLoading(false);
    }
  }, []);

  useLiveRefresh({
    refresh: useCallback(
      async (ctx) => {
        await Promise.all([fetchSummary(ctx.signal), fetchAssets(null, ctx.signal)]);
      },
      [fetchSummary, fetchAssets],
    ),
  });

  usePortalRealtimeSubscription("exposure.summary.updated", () => {
    void fetchSummary();
  });

  usePortalRealtimeSubscription("exposure.asset.updated", () => {
    void fetchAssets();
  });

  usePortalRealtimeSubscription("exposure.finding.updated", () => {
    void fetchFindings();
  });

  useEffect(() => {
    const ac = new AbortController();
    void fetchSummary(ac.signal);
    void fetchAssets(null, ac.signal);
    return () => ac.abort();
  }, [fetchSummary, fetchAssets]);

  useEffect(() => {
    if (tab === "paths" && !pathsPage) {
      const ac = new AbortController();
      void fetchPaths(null, ac.signal);
      return () => ac.abort();
    }
    if (tab === "findings" && !findingsPage) {
      const ac = new AbortController();
      void fetchFindings(null, ac.signal);
      return () => ac.abort();
    }
  }, [tab, pathsPage, findingsPage, fetchPaths, fetchFindings]);

  useEffect(() => {
    const ac = new AbortController();
    setAssetsPage(null);
    setAssetsCursor(null);
    void fetchAssets(null, ac.signal);
    return () => ac.abort();
  }, [assetFilters, fetchAssets]);

  const handleSelectAsset = useCallback(async (asset: ExposureAssetPosture) => {
    setSelectedAsset(asset);
    setAssetDetail(null);
    setAssetDetailLoading(true);
    try {
      const detail = await getExposureAssetDetail(asset.asset_key);
      setAssetDetail(detail);
    } finally {
      setAssetDetailLoading(false);
    }
  }, []);

  const loadGraph = useCallback(async (assetKey: string, label: string) => {
    setGraphData(null);
    setGraphLabel(label);
    setGraphLoading(true);
    setTab("graph");
    try {
      const data = await getExposureAssetGraph(assetKey);
      setGraphData(data);
    } finally {
      setGraphLoading(false);
    }
  }, []);

  const handleViewGraph = useCallback(
    (assetKey: string) => {
      const label =
        assetsPage?.items.find((a) => a.asset_key === assetKey)?.display_name ?? assetKey;
      void loadGraph(assetKey, label);
    },
    [assetsPage, loadGraph],
  );

  const handleOpenInvestigation = useCallback(
    async (assetKey: string) => {
      if (!isAdmin) return;
      await openAssetInvestigation(assetKey);
    },
    [isAdmin],
  );

  const handleCreateTriageAction = useCallback(
    async (assetKey: string) => {
      if (!isAdmin) return;
      await createAssetTriageAction(assetKey);
    },
    [isAdmin],
  );

  const handleRecalculate = useCallback(async () => {
    if (!isAdmin) return;
    await requestExposureRecalculate();
  }, [isAdmin]);

  const TABS: Array<{ id: Tab; label: string }> = [
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
            <Button variant="subtle" size="lg" onClick={() => void handleRecalculate()}>
              Recalculate
            </Button>
          ) : undefined
        }
      />

      <div className="px-4 sm:px-5">
        <ExposureSummaryCards summary={summary} loading={summaryLoading} />
      </div>

      <div className="px-4 sm:px-5">
        <div className="ui-tab-shell border-b border-border/60">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`ui-tab-item${tab === t.id ? " ui-tab-item-active" : ""}`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div className="px-4 sm:px-5">
        {tab === "assets" && (
          <Card
            title="Asset posture"
            right={
              <Button variant="ghost" size="sm" onClick={() => void fetchAssets()}>
                Refresh
              </Button>
            }
          >
            <div className="space-y-3">
              <ExposureFiltersBar
                filters={assetFilters}
                onChange={(next) => setAssetFilters((prev) => ({ ...prev, ...next }))}
                onReset={() => setAssetFilters(DEFAULT_ASSET_FILTERS)}
              />
              {assetsPage?.items.length === 0 && !assetsLoading ? (
                <EmptyState title="No assets" description="No assets match the current filters." />
              ) : (
                <ExposureAssetTable
                  page={assetsPage}
                  loading={assetsLoading}
                  onSelect={(a) => void handleSelectAsset(a)}
                  onViewGraph={(a) => handleViewGraph(a.asset_key)}
                  onLoadMore={() => assetsCursor && void fetchAssets(assetsCursor)}
                />
              )}
            </div>
          </Card>
        )}

        {tab === "paths" && (
          <Card
            title="Attack paths"
            right={
              <Button variant="ghost" size="sm" onClick={() => void fetchPaths()}>
                Refresh
              </Button>
            }
          >
            {pathsPage?.items.length === 0 && !pathsLoading ? (
              <EmptyState title="No attack paths" description="No active attack paths detected." />
            ) : (
              <div className="space-y-3">
                {pathsPage?.items.map((path) => (
                  <div
                    key={path.path_key}
                    className="rounded-lg border border-border/60 bg-background/40 p-4"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-[12px] font-semibold">{path.risk_score}</span>
                          <span className="font-mono text-[11px] text-muted-foreground">{path.severity}</span>
                          <span className="font-mono text-[11px] text-muted-foreground">
                            conf {path.confidence}%
                          </span>
                        </div>
                        <div className="mt-1 text-sm font-medium">{path.title}</div>
                        {path.summary && (
                          <div className="mt-0.5 text-[12px] text-muted-foreground">{path.summary}</div>
                        )}
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleViewGraph(path.asset_key)}
                      >
                        View graph
                      </Button>
                    </div>
                    {path.stages.length > 0 && (
                      <div className="mt-3">
                        <ExposureAttackPathTimeline stages={path.stages} />
                      </div>
                    )}
                    {path.recommendations.length > 0 && (
                      <div className="mt-3">
                        <ExposureRecommendationsPanel recommendations={path.recommendations.slice(0, 2)} />
                      </div>
                    )}
                  </div>
                ))}

                {pathsLoading && (
                  <div className="py-2 text-center font-mono text-[11px] text-muted-foreground">
                    Loading…
                  </div>
                )}
                {pathsPage?.has_more && !pathsLoading && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="w-full"
                    onClick={() => pathsCursor && void fetchPaths(pathsCursor)}
                  >
                    Load more
                  </Button>
                )}
              </div>
            )}
          </Card>
        )}

        {tab === "graph" && (
          <Card
            title={graphLabel ? `Graph · ${graphLabel}` : "Attack graph"}
            right={
              graphData ? (
                <span className="font-mono text-[11px] text-muted-foreground">
                  {graphData.graph_health.node_count} nodes · {graphData.graph_health.edge_count}{" "}
                  edges
                </span>
              ) : undefined
            }
          >
            {!graphData && !graphLoading && (
              <EmptyState
                title="No graph selected"
                description="Use the Graph button on an asset or attack path to load its relationship graph here."
              />
            )}
            {graphLoading && (
              <div className="py-8 text-center font-mono text-[11px] text-muted-foreground">
                Loading graph…
              </div>
            )}
            {graphData && (
              <div className="space-y-4">
                <ExposureGraphCanvas
                  graph={graphData}
                  onNodeClick={(node) => {
                    if (!node.asset_key) return;
                    const asset = assetsPage?.items.find((a) => a.asset_key === node.asset_key);
                    if (asset) void handleSelectAsset(asset);
                  }}
                />
                <ExposureGraphLegend legend={graphData.legend} />
              </div>
            )}
          </Card>
        )}

        {tab === "findings" && (
          <Card
            title="Findings"
            right={
              <Button variant="ghost" size="sm" onClick={() => void fetchFindings()}>
                Refresh
              </Button>
            }
          >
            {findingsPage?.items.length === 0 && !findingsLoading ? (
              <EmptyState title="No findings" description="No exposure findings found." />
            ) : (
              <ExposureFindingList
                page={findingsPage}
                loading={findingsLoading}
                onSelect={setSelectedFinding}
                onLoadMore={() => findingsCursor && void fetchFindings(findingsCursor)}
              />
            )}
          </Card>
        )}
      </div>

      <ExposureAssetDrawer
        asset={selectedAsset}
        detail={assetDetail}
        detailLoading={assetDetailLoading}
        onClose={() => {
          setSelectedAsset(null);
          setAssetDetail(null);
        }}
        onOpenInvestigation={(key) => void handleOpenInvestigation(key)}
        onCreateTriageAction={(key) => void handleCreateTriageAction(key)}
        onViewGraph={(key) => {
          handleViewGraph(key);
          setSelectedAsset(null);
          setAssetDetail(null);
        }}
        isAdmin={isAdmin}
      />

      <ExposureFindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
