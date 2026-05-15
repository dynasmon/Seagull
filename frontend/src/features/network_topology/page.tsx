import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { createResponseAction, getResponseActionResult, listAgents, listResponseActions } from "@/features/agents/api";
import type { AgentPublic } from "@/features/agents/types";
import { useAuth } from "@/features/auth/context";
import { Button } from "@/shared/components/Button";
import { DataQueryStateBanner } from "@/shared/components/DataView";
import PageHeader from "@/shared/components/PageHeader";
import { Panel } from "@/shared/components/Panel";
import { getErrorMessage } from "@/shared/lib/errors";
import { isAbortError } from "@/shared/lib/http";
import { useLiveRefresh } from "@/shared/realtime";

import {
  getTopologyEdgeDetail,
  getTopologyGraph,
  getTopologyNodeDetail,
  getTopologySummary,
  listTopologyObservations,
  listTopologySubnets,
  requestTopologyRecalculate,
} from "./api";
import { NetworkTopologyCanvas } from "./components/NetworkTopologyCanvas";
import {
  NetworkTopologyDetailDrawer,
  type NetworkTopologyDetailSelection,
} from "./components/NetworkTopologyDetailDrawer";
import { NetworkTopologyDiscoveryPanel } from "./components/NetworkTopologyDiscoveryPanel";
import { NetworkTopologyEvidencePanel } from "./components/NetworkTopologyEvidencePanel";
import { NetworkTopologyFiltersBar } from "./components/NetworkTopologyFiltersBar";
import { NetworkTopologyInsightsPanel } from "./components/NetworkTopologyInsightsPanel";
import { NetworkTopologySummaryCards } from "./components/NetworkTopologySummaryCards";
import { NetworkTopologyVisibilityBanner } from "./components/NetworkTopologyVisibilityBanner";
import { useNetworkTopologyFilters } from "./hooks/useNetworkTopologyFilters";
import { useNetworkTopologyRealtimeInvalidation } from "./hooks/useNetworkTopologyRealtimeInvalidation";
import {
  filterTopologyGraph,
  resolveTopologyGraphParams,
  resolveTopologyObservationParams,
  resolveTopologySubnetParams,
} from "./lib/filters";
import type { TopologyEdge, TopologyGraph, TopologyObservation, TopologySubnet, TopologySummary } from "./types";

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
    resetFilters,
    isDirty,
    appliedKey,
  } = useNetworkTopologyFilters();

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

  const filtersRef = useRef(appliedFilters);
  const loadedOnceRef = useRef(false);
  const detailSeqRef = useRef(0);
  const discoveryActionSeqRef = useRef(0);

  const agentOptions = useMemo(
    () =>
      agents.map((agent) => ({
        value: agent.agent_id,
        label: agent.display_name ? `${agent.display_name} (${agent.agent_id})` : agent.agent_id,
      })),
    [agents],
  );

  const visibleGraph = useMemo(() => filterTopologyGraph(graph, appliedFilters), [appliedFilters, graph]);
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
    const now = new Date();
    const hasData = loadedOnceRef.current;
    if (!hasData) setLoading(true);

    const requests = await Promise.allSettled([
      getTopologySummary(signal),
      getTopologyGraph({ ...resolveTopologyGraphParams(activeFilters, now), signal }),
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

    const message = firstRejectedMessage(requests.slice(0, 4));
    setError(message);
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
        setLatestDiscoveryAction({
          id: latest.id,
          status: latest.status,
          requested_at: latest.requested_at,
          result,
        });
      }
    } catch {
      if (discoveryActionSeqRef.current === seq) setLatestDiscoveryAction(null);
    }
  }, [isAdmin, selectedDiscoveryAgentId]);

  useEffect(() => {
    void loadLatestDiscoveryAction();
  }, [liveState.lastUpdatedAt, loadLatestDiscoveryAction]);

  useEffect(() => {
    if (
      !latestDiscoveryAction ||
      isTerminalDiscoveryActionStatus(latestDiscoveryAction.status) ||
      !isAdmin ||
      !selectedDiscoveryAgentId
    ) {
      return;
    }
    const timeout = window.setTimeout(() => {
      void loadLatestDiscoveryAction();
    }, 5000);
    return () => window.clearTimeout(timeout);
  }, [isAdmin, latestDiscoveryAction, loadLatestDiscoveryAction, selectedDiscoveryAgentId]);

  const handleSelectNode = useCallback(async (node: { node_key: string }) => {
    const seq = detailSeqRef.current + 1;
    detailSeqRef.current = seq;
    setDetailSelection({ kind: "node", key: node.node_key, detail: null, loading: true, error: null });
    try {
      const detail = await getTopologyNodeDetail(node.node_key);
      if (detailSeqRef.current !== seq) return;
      setDetailSelection({ kind: "node", key: node.node_key, detail, loading: false, error: null });
    } catch (err) {
      if (detailSeqRef.current !== seq) return;
      setDetailSelection({
        kind: "node",
        key: node.node_key,
        detail: null,
        loading: false,
        error: getErrorMessage(err, "Failed to load node detail"),
      });
    }
  }, []);

  const handleSelectEdge = useCallback(async (edge: TopologyEdge) => {
    const seq = detailSeqRef.current + 1;
    detailSeqRef.current = seq;
    setDetailSelection({ kind: "edge", key: edge.edge_key, detail: null, loading: true, error: null });
    try {
      const detail = await getTopologyEdgeDetail(edge.edge_key);
      if (detailSeqRef.current !== seq) return;
      setDetailSelection({ kind: "edge", key: edge.edge_key, detail, loading: false, error: null });
    } catch (err) {
      if (detailSeqRef.current !== seq) return;
      setDetailSelection({
        kind: "edge",
        key: edge.edge_key,
        detail: null,
        loading: false,
        error: getErrorMessage(err, "Failed to load edge detail"),
      });
    }
  }, []);

  const handleRecalculate = useCallback(async () => {
    if (!isAdmin || recalculateBusy) return;
    setRecalculateBusy(true);
    setRecalculateMessage(null);
    try {
      const result = await requestTopologyRecalculate();
      setRecalculateMessage(
        `Recalculation accepted: latest snapshot has ${result.projected_nodes} nodes and ${result.projected_edges} edges.`,
      );
      invalidate("manual", { immediate: true, supersede: false });
    } catch (err) {
      setError(getErrorMessage(err, "Failed to request topology recalculation"));
    } finally {
      setRecalculateBusy(false);
    }
  }, [isAdmin, invalidate, recalculateBusy]);

  const handleTriggerDiscovery = useCallback(async () => {
    if (!isAdmin || !selectedDiscoveryAgentId || discoveryBusy || discoveryConfirmationText.trim() !== "DISCOVER") {
      return;
    }
    setDiscoveryBusy(true);
    try {
      const action = await createResponseAction({
        action_type: "trigger_topology_discovery",
        agent_id: selectedDiscoveryAgentId,
        payload: { reason: "network_topology_manual_request" },
      });
      setLatestDiscoveryAction({
        id: action.id,
        status: action.status,
        requested_at: action.requested_at,
        result: null,
      });
      setDiscoveryConfirmationText("");
    } catch (err) {
      setError(getErrorMessage(err, "Failed to request active discovery"));
    } finally {
      setDiscoveryBusy(false);
    }
  }, [discoveryBusy, discoveryConfirmationText, isAdmin, selectedDiscoveryAgentId]);

  return (
    <div className="min-w-0 space-y-6 overflow-x-hidden">
      <PageHeader
        title="Network Topology"
        breadcrumb={["Assets & Exposure", "Network Topology"]}
        description="Internal network map, observed flows, services, and security context."
        toolbarRight={
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="secondary" size="lg" onClick={() => void refreshNow()} disabled={liveState.isRefreshing}>
              {liveState.isRefreshing ? "Refreshing..." : "Refresh"}
            </Button>
            {isAdmin ? (
              <Button variant="subtle" size="lg" onClick={() => void handleRecalculate()} disabled={recalculateBusy}>
                {recalculateBusy ? "Recalculating..." : "Recalculate"}
              </Button>
            ) : null}
          </div>
        }
      />

      <NetworkTopologySummaryCards summary={summary} loading={loading} />

      <NetworkTopologyVisibilityBanner
        summary={summary}
        graph={graph}
        error={error}
        refreshing={liveState.isRefreshing}
        onRefresh={() => void refreshNow()}
      />

      {recalculateMessage ? <DataQueryStateBanner tone="success" message={recalculateMessage} /> : null}

      <NetworkTopologyDiscoveryPanel
        isAdmin={isAdmin}
        agents={agentOptions.map((agent) => ({ agent_id: agent.value, label: agent.label }))}
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

      <NetworkTopologyFiltersBar
        filters={draftFilters}
        agentOptions={agentOptions}
        dirty={isDirty}
        applying={liveState.isRefreshing}
        onChange={(patch) => setDraftFilters((current) => ({ ...current, ...patch }))}
        onApply={applyFilters}
        onReset={resetFilters}
      />

      <div className="grid min-w-0 gap-4 2xl:grid-cols-[minmax(0,1fr)_340px]">
        <Panel
          title="Topology Canvas"
          subtitle="Agents, inventory, flows, alerts, and exposure signals."
          className="min-w-0"
          bodyClassName="min-w-0"
        >
          <NetworkTopologyCanvas
            graph={visibleGraph}
            loading={loading}
            selected={
              detailSelection
                ? { kind: detailSelection.kind, key: detailSelection.key }
                : null
            }
            onSelectNode={handleSelectNode}
            onSelectEdge={handleSelectEdge}
          />
        </Panel>

        <Panel
          title="Visible Scope"
          subtitle="Current projection bounds and displayed subset."
          className="min-w-0"
        >
          <div className="space-y-3 text-sm">
            <div className="grid grid-cols-2 gap-2">
              <div className="rounded-md border border-border/70 bg-background/35 p-3">
                <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">Shown Nodes</div>
                <div className="mt-1 text-lg font-semibold">{visibleGraph?.nodes.length ?? 0}</div>
              </div>
              <div className="rounded-md border border-border/70 bg-background/35 p-3">
                <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">Shown Edges</div>
                <div className="mt-1 text-lg font-semibold">{visibleGraph?.edges.length ?? 0}</div>
              </div>
            </div>
            <div className="rounded-md border border-border/70 bg-background/35 p-3 text-[12px] text-muted-foreground">
              Agent, time window, type, IP scope, confidence, search, and severity filters are active in this view.
            </div>
            <div className="rounded-md border border-border/70 bg-background/35 p-3 text-[12px] text-muted-foreground">
              Realtime status: <span className="font-semibold text-foreground">{liveState.realtimeStatus}</span>
              {liveState.lastUpdatedAt ? ` · updated ${liveState.lastUpdatedAt.toLocaleTimeString()}` : ""}
            </div>
          </div>
        </Panel>
      </div>

      <NetworkTopologyInsightsPanel
        insights={summary?.insights ?? []}
        visibility={summary?.visibility ?? null}
        loading={loading}
      />

      <NetworkTopologyEvidencePanel observations={observations} subnets={subnets} loading={loading} />

      <NetworkTopologyDetailDrawer
        selection={detailSelection}
        onClose={() => {
          detailSeqRef.current += 1;
          setDetailSelection(null);
        }}
      />
    </div>
  );
}
