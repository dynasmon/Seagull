import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { createResponseAction, getResponseActionResult, listAgents, listResponseActions } from "@/features/agents/api";
import type { AgentPublic } from "@/features/agents/types";
import { useAuth } from "@/features/auth/context";
import { DataQueryStateBanner } from "@/shared/components/DataView";
import { getErrorMessage } from "@/shared/lib/errors";
import { isAbortError } from "@/shared/lib/http";
import { useLiveRefresh } from "@/shared/realtime";

import {
  getTopologyEdgeDetail,
  getTopologyGraph,
  getTopologyGroupDetail,
  getTopologyNodeDetail,
  getTopologySubnetDetail,
  getTopologySummary,
  listTopologyObservations,
  listTopologySubnets,
  requestTopologyRecalculate,
} from "./api";
import {
  NetworkTopologyDetailDrawer,
  type NetworkTopologyDetailSelection,
} from "./components/NetworkTopologyDetailDrawer";
import { NetworkTopologyDiscoveryPanel } from "./components/NetworkTopologyDiscoveryPanel";
import { NetworkTopologyEvidencePanel } from "./components/NetworkTopologyEvidencePanel";
import { NetworkTopologyInsightsPanel } from "./components/NetworkTopologyInsightsPanel";
import { NetworkTopologyServicesPanel } from "./components/NetworkTopologyServicesPanel";
import TopologyCanvas from "./components/TopologyCanvas";
import { TopologyFilterRail } from "./components/TopologyFilterRail";
import { useNetworkTopologyFilters } from "./hooks/useNetworkTopologyFilters";
import { useNetworkTopologyRealtimeInvalidation } from "./hooks/useNetworkTopologyRealtimeInvalidation";
import { useTopologyWorkspaceState } from "./hooks/useTopologyWorkspaceState";
import {
  filterTopologyGraph,
  resolveTopologyGraphParams,
  resolveTopologyObservationParams,
  resolveTopologySubnetParams,
} from "./lib/filters";
import {
  computeHighlightedKeys,
  graphToConnectionView,
  graphToLocationView,
  type TopologyFocusState,
} from "./lib/graphTransform";
import { resolveTopologyGroups } from "./lib/grouping";
import { searchTopologyGraph } from "./lib/search";
import {
  filtersForSubnetExplore,
  focusedGroupDisplayLabel,
  subnetCidrForGroup,
} from "./lib/subnets";
import type { TopologyGraph, TopologyObservation, TopologySubnet, TopologySummary } from "./types";

function firstRejectedMessage(results: PromiseSettledResult<unknown>[]): string | null {
  for (const result of results) {
    if (result.status === "rejected" && !isAbortError(result.reason)) {
      return getErrorMessage(result.reason, "Failed to load network topology");
    }
  }
  return null;
}

function isTerminalDiscoveryActionStatus(status: string) {
  return ["success", "failed", "cancelled", "expired"].includes(status);
}

export default function NetworkTopologyPage() {
  const { user } = useAuth();
  const isAdmin = String(user?.role || "").toLowerCase() === "admin";

  const {
    appliedFilters,
    draftFilters,
    setDraftFilters,
    applyFilters,
    applyWith,
    resetFilters,
    isDirty,
    appliedKey,
  } = useNetworkTopologyFilters();

  const workspace = useTopologyWorkspaceState();

  const [agents, setAgents] = useState<AgentPublic[]>([]);
  const [summary, setSummary] = useState<TopologySummary | null>(null);
  const [graph, setGraph] = useState<TopologyGraph | null>(null);
  const [subnets, setSubnets] = useState<TopologySubnet[]>([]);
  const [observations, setObservations] = useState<TopologyObservation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [recalculateBusy, setRecalculateBusy] = useState(false);
  const [recalculateMessage, setRecalculateMessage] = useState<string | null>(null);
  const [selectedDiscoveryAgentId, setSelectedDiscoveryAgentId] = useState("");
  const [discoveryConfirmationText, setDiscoveryConfirmationText] = useState("");
  const [discoveryBusy, setDiscoveryBusy] = useState(false);
  const [latestDiscoveryAction, setLatestDiscoveryAction] = useState<{
    id: number;
    status: string;
    requested_at: string;
    result?: Record<string, unknown> | null;
  } | null>(null);
  const [detailSelection, setDetailSelection] = useState<NetworkTopologyDetailSelection>(null);
  const [secondaryOpen, setSecondaryOpen] = useState(false);

  const filtersRef = useRef(appliedFilters);
  const focusedGroupKeyRef = useRef<string | null>(null);
  const loadedOnceRef = useRef(false);
  const detailSeqRef = useRef(0);
  const discoveryActionSeqRef = useRef(0);
  const prevNodeIdsRef = useRef<Set<string>>(new Set());

  const agentOptions = useMemo(
    () =>
      agents.map((agent) => ({
        value: agent.agent_id,
        label: agent.display_name ? `${agent.display_name} (${agent.agent_id})` : agent.agent_id,
      })),
    [agents],
  );

  const agentLabelById = useMemo(
    () => new Map(agents.map((a) => [a.agent_id, a.display_name ?? a.agent_id])),
    [agents],
  );

  const visibleGraph = useMemo(() => filterTopologyGraph(graph, appliedFilters), [appliedFilters, graph]);

  const availableGrouping = useMemo(
    () => resolveTopologyGroups(graph, agentLabelById),
    [graph, agentLabelById],
  );

  const { groups, edges: groupEdges } = useMemo(
    () => resolveTopologyGroups(visibleGraph, agentLabelById),
    [visibleGraph, agentLabelById],
  );

  const focusedGroup = useMemo(
    () => (workspace.focusedGroupKey ? groups.find((g) => g.group_key === workspace.focusedGroupKey) ?? null : null),
    [workspace.focusedGroupKey, groups],
  );

  const focusedGroupLabel = focusedGroupDisplayLabel(focusedGroup);

  const focusState = useMemo((): TopologyFocusState | undefined => {
    if (!focusedGroup || appliedFilters.view_mode !== "connection") return undefined;
    return { focusedNodeKeys: new Set(focusedGroup.node_keys) };
  }, [focusedGroup, appliedFilters.view_mode]);

  useEffect(() => {
    if (workspace.focusedGroupKey && !focusedGroup) {
      workspace.clearFocusedGroup();
    }
  }, [workspace.focusedGroupKey, focusedGroup, workspace.clearFocusedGroup, workspace]);

  const highlightedKeys = useMemo(
    () =>
      computeHighlightedKeys(
        visibleGraph,
        groups,
        workspace.selection?.key ?? null,
        workspace.selection?.kind ?? null,
        groupEdges,
      ),
    [visibleGraph, groups, groupEdges, workspace.selection],
  );

  const selState = useMemo(
    () => ({
      selectedKey: workspace.selection?.key ?? null,
      selectedKind: workspace.selection?.kind ?? null,
      highlightedKeys,
    }),
    [workspace.selection, highlightedKeys],
  );

  const searchResult = useMemo(
    () => searchTopologyGraph(visibleGraph, groups, workspace.searchQuery),
    [visibleGraph, groups, workspace.searchQuery],
  );

  const searchState = useMemo(() => {
    if (!workspace.searchQuery.trim()) return undefined;
    return {
      matchedNodeKeys: searchResult.matchedNodeKeys,
      matchedGroupKeys: searchResult.matchedGroupKeys,
      activeMatchKey: null as string | null,
    };
  }, [workspace.searchQuery, searchResult]);

  const activeMatchKey = useMemo(() => {
    if (!workspace.searchQuery.trim()) return null;
    if (appliedFilters.view_mode === "location") {
      return searchResult.orderedGroupKeys[workspace.searchMatchIndex] ?? null;
    }
    return searchResult.orderedNodeKeys[workspace.searchMatchIndex] ?? null;
  }, [workspace.searchQuery, workspace.searchMatchIndex, appliedFilters.view_mode, searchResult]);

  const searchStateWithActive = useMemo(() => {
    if (!searchState) return undefined;
    return { ...searchState, activeMatchKey };
  }, [searchState, activeMatchKey]);

  const searchTotal = appliedFilters.view_mode === "location"
    ? searchResult.orderedGroupKeys.length
    : searchResult.orderedNodeKeys.length;

  const newNodeIds = new Set(
    graph?.nodes
      .filter((n) => !prevNodeIdsRef.current.has(n.node_key))
      .map((n) => n.node_key) ?? [],
  );
  prevNodeIdsRef.current = new Set(graph?.nodes.map((n) => n.node_key) ?? []);

  const { nodes: rfNodes, edges: rfEdges } = useMemo(() => {
    if (appliedFilters.view_mode === "location") {
      return graphToLocationView(groups, groupEdges, selState, searchStateWithActive);
    }
    return graphToConnectionView(visibleGraph, selState, searchStateWithActive, focusState, groups, groupEdges, newNodeIds);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appliedFilters.view_mode, groups, groupEdges, visibleGraph, selState, searchStateWithActive, focusState]);

  const selectedDiscoveryAgent = useMemo(
    () => agents.find((agent) => agent.agent_id === selectedDiscoveryAgentId) ?? null,
    [agents, selectedDiscoveryAgentId],
  );

  const discoveryMetrics = useMemo(() => {
    const outer = selectedDiscoveryAgent?.metrics ?? {};
    const nested = outer && typeof outer === "object" ? (outer as Record<string, unknown>).metrics : null;
    return nested && typeof nested === "object" ? (nested as Record<string, unknown>) : {};
  }, [selectedDiscoveryAgent]);

  const discoveryAllowedCidrs = Array.isArray(discoveryMetrics.topology_active_discovery_allowed_cidrs)
    ? discoveryMetrics.topology_active_discovery_allowed_cidrs.map((value) => String(value))
    : [];
  const discoveryWarnings = Array.isArray(discoveryMetrics.topology_active_discovery_last_warnings)
    ? discoveryMetrics.topology_active_discovery_last_warnings.map((value) => String(value))
    : [];
  const discoveryDiscoveredHosts = Array.isArray(discoveryMetrics.topology_active_discovery_last_discovered_hosts)
    ? discoveryMetrics.topology_active_discovery_last_discovered_hosts.map((value) => String(value))
    : [];
  const discoveryObservedHosts = Array.isArray(discoveryMetrics.topology_active_discovery_last_observed_hosts)
    ? discoveryMetrics.topology_active_discovery_last_observed_hosts.map((value) => String(value))
    : [];
  const discoveryMode =
    discoveryMetrics.topology_active_discovery_mode === "active_enabled" ? "active_enabled" : "passive_only";

  const refreshTopology = useCallback(async ({ signal }: { signal: AbortSignal }) => {
    const activeFilters = filtersRef.current;
    const activeFocusedGroupKey = focusedGroupKeyRef.current;
    const now = new Date();
    if (!loadedOnceRef.current) setLoading(true);

    const requests = await Promise.allSettled([
      getTopologySummary(signal),
      getTopologyGraph({
        ...resolveTopologyGraphParams(activeFilters, now, { focused_group_key: activeFocusedGroupKey ?? undefined }),
        signal,
      }),
      listTopologySubnets({ ...resolveTopologySubnetParams(activeFilters, now), signal }),
      listTopologyObservations({ ...resolveTopologyObservationParams(activeFilters, now), signal }),
      listAgents({ signal }),
    ]);

    if (signal.aborted) return;

    const [summaryResult, graphResult, subnetResult, observationResult, agentsResult] = requests;
    if (summaryResult.status === "fulfilled") setSummary(summaryResult.value);
    if (graphResult.status === "fulfilled") setGraph(graphResult.value);
    if (subnetResult.status === "fulfilled") setSubnets(subnetResult.value.items);
    if (observationResult.status === "fulfilled") setObservations(observationResult.value.items);
    if (agentsResult.status === "fulfilled") setAgents(agentsResult.value || []);

    setError(firstRejectedMessage(requests.slice(0, 4)));
    loadedOnceRef.current = true;
    setLoading(false);
  }, []);

  const { state: liveState, refreshNow, invalidate } = useLiveRefresh({
    profile: "expensive-operational",
    refresh: refreshTopology,
    onError: (err) => {
      if (!isAbortError(err)) setError(getErrorMessage(err, "Failed to refresh network topology"));
    },
    immediate: true,
  });

  useNetworkTopologyRealtimeInvalidation(() => {
    invalidate("invalidate");
  });

  useEffect(() => {
    filtersRef.current = appliedFilters;
    if (!loadedOnceRef.current) return;
    invalidate("dependency", { immediate: true, supersede: true });
  }, [appliedFilters, appliedKey, invalidate]);

  useEffect(() => {
    focusedGroupKeyRef.current = workspace.focusedGroupKey;
    if (!loadedOnceRef.current) return;
    invalidate("dependency", { immediate: true, supersede: true });
  }, [workspace.focusedGroupKey, invalidate]);

  useEffect(() => {
    if (!selectedDiscoveryAgentId && agents.length > 0) {
      setSelectedDiscoveryAgentId(agents[0].agent_id);
    }
  }, [agents, selectedDiscoveryAgentId]);

  const loadLatestDiscoveryAction = useCallback(async () => {
    const seq = discoveryActionSeqRef.current + 1;
    discoveryActionSeqRef.current = seq;
    if (!isAdmin || !selectedDiscoveryAgentId) {
      setLatestDiscoveryAction(null);
      return;
    }
    try {
      const actions = await listResponseActions({ agent_id: selectedDiscoveryAgentId, limit: 20 });
      const latest = actions.find((action) => action.action_type === "trigger_topology_discovery");
      if (!latest) {
        if (discoveryActionSeqRef.current === seq) setLatestDiscoveryAction(null);
        return;
      }
      let result: Record<string, unknown> | null = null;
      if (latest.status === "success" || latest.status === "failed") {
        try {
          const payload = await getResponseActionResult(latest.id);
          result = payload.result_payload ?? null;
        } catch {
          result = null;
        }
      }
      if (discoveryActionSeqRef.current === seq) {
        setLatestDiscoveryAction({ id: latest.id, status: latest.status, requested_at: latest.requested_at, result });
      }
    } catch {
      if (discoveryActionSeqRef.current === seq) setLatestDiscoveryAction(null);
    }
  }, [isAdmin, selectedDiscoveryAgentId]);

  useEffect(() => {
    void loadLatestDiscoveryAction();
  }, [liveState.lastUpdatedAt, loadLatestDiscoveryAction]);

  useEffect(() => {
    if (!latestDiscoveryAction || isTerminalDiscoveryActionStatus(latestDiscoveryAction.status) || !isAdmin || !selectedDiscoveryAgentId) return;
    const timeout = window.setTimeout(() => void loadLatestDiscoveryAction(), 5000);
    return () => window.clearTimeout(timeout);
  }, [isAdmin, latestDiscoveryAction, loadLatestDiscoveryAction, selectedDiscoveryAgentId]);

  const handleExploreGroupInConnection = useCallback(
    (groupKey: string) => {
      const group = groups.find((g) => g.group_key === groupKey);
      if (!group) return;
      applyWith(filtersForSubnetExplore(appliedFilters));
      workspace.setFocusedGroupKey(groupKey);
      workspace.setSearchQuery("");
      setDetailSelection(null);
      workspace.clearSelection();
    },
    [groups, appliedFilters, applyWith, workspace],
  );

  const handleNodeClick = useCallback(
    async (id: string, kind: "node" | "group") => {
      if (kind === "group") {
        workspace.selectGroup(id);
        const group = groups.find((g) => g.group_key === id) ?? null;
        if (group) {
          const subnetCidr = subnetCidrForGroup(group);
          const memberNodes = (visibleGraph?.nodes ?? [])
            .filter((n) => group.node_keys.includes(n.node_key))
            .slice(0, 20);
          setDetailSelection({
            kind: "group",
            key: id,
            group,
            memberNodes,
            backendDetail: null,
            backendDetailLoading: true,
            backendDetailError: null,
            subnetCidr,
            subnetDetail: null,
            subnetDetailLoading: Boolean(subnetCidr),
            subnetDetailError: null,
            onExploreInConnection: () => handleExploreGroupInConnection(id),
          });
          const seq = detailSeqRef.current + 1;
          detailSeqRef.current = seq;
          void getTopologyGroupDetail(id)
            .then((backendDetail) => {
              if (detailSeqRef.current !== seq) return;
              setDetailSelection((prev) =>
                prev?.kind === "group" && prev.key === id
                  ? { ...prev, backendDetail, backendDetailLoading: false }
                  : prev,
              );
            })
            .catch((err) => {
              if (detailSeqRef.current !== seq) return;
              setDetailSelection((prev) =>
                prev?.kind === "group" && prev.key === id
                  ? { ...prev, backendDetailLoading: false, backendDetailError: getErrorMessage(err, "Failed to load group detail") }
                  : prev,
              );
            });
          if (subnetCidr) {
            void getTopologySubnetDetail(subnetCidr)
              .then((subnetDetail) => {
                if (detailSeqRef.current !== seq) return;
                setDetailSelection((prev) =>
                  prev?.kind === "group" && prev.key === id
                    ? { ...prev, subnetDetail, subnetDetailLoading: false }
                    : prev,
                );
              })
              .catch((err) => {
                if (detailSeqRef.current !== seq) return;
                setDetailSelection((prev) =>
                  prev?.kind === "group" && prev.key === id
                    ? { ...prev, subnetDetailLoading: false, subnetDetailError: getErrorMessage(err, "Failed to load subnet detail") }
                    : prev,
                );
              });
          }
        }
        return;
      }
      workspace.selectNode(id);
      const seq = detailSeqRef.current + 1;
      detailSeqRef.current = seq;
      setDetailSelection({ kind: "node", key: id, detail: null, loading: true, error: null });
      try {
        const detail = await getTopologyNodeDetail(id);
        if (detailSeqRef.current !== seq) return;
        setDetailSelection({ kind: "node", key: id, detail, loading: false, error: null });
      } catch (err) {
        if (detailSeqRef.current !== seq) return;
        setDetailSelection({ kind: "node", key: id, detail: null, loading: false, error: getErrorMessage(err, "Failed to load node detail") });
      }
    },
    [workspace, groups, visibleGraph, handleExploreGroupInConnection],
  );

  const handleEdgeClick = useCallback(
    async (id: string) => {
      workspace.selectEdge(id);
      const seq = detailSeqRef.current + 1;
      detailSeqRef.current = seq;
      setDetailSelection({ kind: "edge", key: id, detail: null, loading: true, error: null });
      try {
        const detail = await getTopologyEdgeDetail(id);
        if (detailSeqRef.current !== seq) return;
        setDetailSelection({ kind: "edge", key: id, detail, loading: false, error: null });
      } catch (err) {
        if (detailSeqRef.current !== seq) return;
        setDetailSelection({ kind: "edge", key: id, detail: null, loading: false, error: getErrorMessage(err, "Failed to load edge detail") });
      }
    },
    [workspace],
  );

  const handleGroupDoubleClick = useCallback(
    (id: string) => {
      handleExploreGroupInConnection(id);
    },
    [handleExploreGroupInConnection],
  );

  const handlePaneClick = useCallback(() => {
    workspace.clearSelection();
    setDetailSelection(null);
  }, [workspace]);

  const handleClearFocus = useCallback(() => {
    workspace.clearFocusedGroup();
  }, [workspace]);

  const handleRecalculate = useCallback(async () => {
    if (!isAdmin || recalculateBusy) return;
    setRecalculateBusy(true);
    setRecalculateMessage(null);
    try {
      const result = await requestTopologyRecalculate();
      setRecalculateMessage(
        `Recalculation accepted: ${result.projected_nodes} nodes, ${result.projected_edges} edges.`,
      );
      invalidate("manual", { immediate: true, supersede: false });
    } catch (err) {
      setError(getErrorMessage(err, "Failed to request topology recalculation"));
    } finally {
      setRecalculateBusy(false);
    }
  }, [isAdmin, invalidate, recalculateBusy]);

  const handleTriggerDiscovery = useCallback(async () => {
    if (!isAdmin || !selectedDiscoveryAgentId || discoveryBusy || discoveryConfirmationText.trim() !== "DISCOVER") return;
    setDiscoveryBusy(true);
    try {
      const action = await createResponseAction({
        action_type: "trigger_topology_discovery",
        agent_id: selectedDiscoveryAgentId,
        payload: { reason: "network_topology_manual_request" },
      });
      setLatestDiscoveryAction({ id: action.id, status: action.status, requested_at: action.requested_at, result: null });
      setDiscoveryConfirmationText("");
    } catch (err) {
      setError(getErrorMessage(err, "Failed to request active discovery"));
    } finally {
      setDiscoveryBusy(false);
    }
  }, [discoveryBusy, discoveryConfirmationText, isAdmin, selectedDiscoveryAgentId]);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        if (workspace.focusedGroupKey) {
          workspace.clearFocusedGroup();
          return;
        }
        if (workspace.searchQuery) {
          workspace.setSearchQuery("");
          return;
        }
        workspace.clearSelection();
        setDetailSelection(null);
        detailSeqRef.current += 1;
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [workspace]);

  return (
    <div
      className="flex min-w-0 flex-col overflow-hidden"
      style={{ height: "calc(100vh - 88px)" }}
    >
      {recalculateMessage && (
        <DataQueryStateBanner tone="success" message={recalculateMessage} />
      )}

      {error && <DataQueryStateBanner tone="danger" message={error} />}

      <div className="flex min-h-0 min-w-0 flex-1 overflow-hidden">
        {workspace.filterRailOpen && (
          <TopologyFilterRail
            filters={draftFilters}
            agentOptions={agentOptions}
            groups={availableGrouping.groups}
            dirty={isDirty}
            applying={liveState.isRefreshing}
            facets={visibleGraph?.facets ?? undefined}
            onChange={(patch) => setDraftFilters((current) => ({ ...current, ...patch }))}
            onViewModeChange={(mode) => applyWith({ ...draftFilters, view_mode: mode })}
            onApply={applyFilters}
            onReset={resetFilters}
          />
        )}

        <div className="relative min-h-0 min-w-0 flex-1">
          <TopologyCanvas
            nodes={rfNodes}
            edges={rfEdges}
            viewMode={appliedFilters.view_mode}
            graph={visibleGraph}
            groups={groups}
            groupEdges={groupEdges}
            summary={summary}
            filters={appliedFilters}
            loading={loading}
            isFullscreen={workspace.isFullscreen}
            filterRailOpen={workspace.filterRailOpen}
            activeMatchKey={activeMatchKey}
            searchQuery={workspace.searchQuery}
            searchTotal={searchTotal}
            searchMatchIndex={workspace.searchMatchIndex}
            focusedGroupLabel={focusedGroupLabel}
            realtimeStatus={liveState.realtimeStatus}
            isRefreshing={liveState.isRefreshing}
            onViewModeChange={(mode) => applyWith({ ...draftFilters, view_mode: mode })}
            onToggleFilterRail={() => workspace.setFilterRailOpen((prev) => !prev)}
            onToggleFullscreen={workspace.toggleFullscreen}
            onRefresh={() => void refreshNow()}
            onSearchChange={(q) => {
              workspace.setSearchQuery(q);
              workspace.setSearchMatchIndex(0);
            }}
            onNodeClick={handleNodeClick}
            onGroupDoubleClick={handleGroupDoubleClick}
            onEdgeClick={handleEdgeClick}
            onPaneClick={handlePaneClick}
            onClearFocus={handleClearFocus}
            onPrevMatch={() => workspace.prevSearchMatch(searchTotal)}
            onNextMatch={() => workspace.nextSearchMatch(searchTotal)}
          />
        </div>
      </div>

      <div className="shrink-0 border-t border-border/30">
        <div className="flex items-center bg-background/40">
          <button
            type="button"
            className="flex min-w-0 flex-1 items-center gap-2 px-4 py-2 text-left"
            onClick={() => setSecondaryOpen((prev) => !prev)}
          >
            <span className={`text-[10px] transition-transform ${secondaryOpen ? "rotate-90" : ""}`}>▶</span>
            <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
              Operational Details
            </span>
            <span className="ml-auto truncate text-[10px] text-muted-foreground/50">
              Services · Insights · Evidence{isAdmin ? " · Discovery" : ""}
            </span>
          </button>
          {isAdmin && (
            <button
              type="button"
              className="mr-4 rounded-[4px] border border-border/40 px-2 py-1 text-[10px] text-muted-foreground transition-colors hover:bg-muted/20 hover:text-foreground disabled:opacity-50"
              onClick={() => void handleRecalculate()}
              disabled={recalculateBusy}
            >
              {recalculateBusy ? "Recalculating…" : "Recalculate"}
            </button>
          )}
        </div>

        {secondaryOpen && (
          <div className="max-h-[480px] overflow-y-auto border-t border-border/30 bg-background/30 px-4 py-4">
            <div className="space-y-4">
              {isAdmin && (
                <NetworkTopologyDiscoveryPanel
                  isAdmin={isAdmin}
                  agents={agentOptions.map((a) => ({ agent_id: a.value, label: a.label }))}
                  selectedAgentId={selectedDiscoveryAgentId}
                  mode={discoveryMode}
                  allowedCidrs={discoveryAllowedCidrs}
                  lastRunAt={
                    typeof discoveryMetrics.topology_active_discovery_last_run_at === "string"
                      ? discoveryMetrics.topology_active_discovery_last_run_at
                      : null
                  }
                  discoveredHosts={discoveryDiscoveredHosts}
                  observedHosts={discoveryObservedHosts}
                  lastError={
                    typeof discoveryMetrics.topology_active_discovery_last_error === "string" &&
                    discoveryMetrics.topology_active_discovery_last_error.trim()
                      ? discoveryMetrics.topology_active_discovery_last_error
                      : null
                  }
                  warnings={discoveryWarnings}
                  confirmationText={discoveryConfirmationText}
                  busy={discoveryBusy}
                  latestAction={latestDiscoveryAction}
                  onSelectAgent={setSelectedDiscoveryAgentId}
                  onConfirmationTextChange={setDiscoveryConfirmationText}
                  onTrigger={() => void handleTriggerDiscovery()}
                />
              )}

              <NetworkTopologyServicesPanel
                graph={visibleGraph}
                loading={loading}
                selectedKey={workspace.selection?.key ?? null}
                onSelectService={(node) => void handleNodeClick(node.node_key, "node")}
              />

              <NetworkTopologyInsightsPanel
                insights={summary?.insights ?? []}
                visibility={summary?.visibility ?? null}
                loading={loading}
              />

              <NetworkTopologyEvidencePanel
                observations={observations}
                subnets={subnets}
                loading={loading}
              />
            </div>
          </div>
        )}
      </div>

      <NetworkTopologyDetailDrawer
        selection={detailSelection}
        onClose={() => {
          detailSeqRef.current += 1;
          setDetailSelection(null);
          workspace.clearSelection();
        }}
      />
    </div>
  );
}
