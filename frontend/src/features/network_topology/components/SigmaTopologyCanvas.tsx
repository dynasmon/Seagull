import "@react-sigma/core/lib/style.css";

import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Edge, Node } from "@xyflow/react";
import {
  SigmaContainer,
  useCamera,
  useLoadGraph,
  useRegisterEvents,
  useSigma,
} from "@react-sigma/core";
import { useWorkerLayoutForceAtlas2 } from "@react-sigma/layout-forceatlas2";
import { createEdgeCurveProgram } from "@sigma/edge-curve";
import { createNodeBorderProgram } from "@sigma/node-border";

import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import { extractHaloData, rfToSigmaGraph } from "../lib/graphToSigma";
import type {
  SigmaEdgeAttributes,
  SigmaGroupNodeAttributes,
  SigmaNodeAttributes,
} from "../lib/graphToSigma";
import type {
  DeviceNodeData,
  GroupNodeData,
  TopologyEdgeData,
} from "../lib/graphTransform";
import { useTopologyPositions } from "../hooks/useTopologyPositions";
import type {
  TopologyFilters,
  TopologyGraph,
  TopologyGroup,
  TopologyGroupEdge,
  TopologySummary,
  TopologyViewMode,
} from "../types";
import { TopologyContextMenu } from "./TopologyContextMenu";
import TopologyLegend from "./TopologyLegend";
import TopologyStatusStrip from "./TopologyStatusStrip";
import TopologyTooltip, { type TooltipInfo } from "./TopologyTooltip";
import { TopologyTopBar } from "./TopologyTopBar";

const NodeBorderProgram = createNodeBorderProgram<
  SigmaNodeAttributes | SigmaGroupNodeAttributes,
  SigmaEdgeAttributes
>({
  borders: [
    { size: { value: 0.12 }, color: { attribute: "borderColor" } },
    { size: { fill: true }, color: { attribute: "color" } },
  ],
});

const EdgeCurveProgram = createEdgeCurveProgram<
  SigmaNodeAttributes | SigmaGroupNodeAttributes,
  SigmaEdgeAttributes
>();

const SIGMA_SETTINGS = {
  nodeProgramClasses: { border: NodeBorderProgram },
  edgeProgramClasses: {
    curve: EdgeCurveProgram,
  },
  defaultNodeType: "border",
  defaultEdgeType: "curve",
  renderEdgeLabels: false,
  enableEdgeEvents: true,
  labelFont: "Inter, system-ui, sans-serif",
  labelSize: 10,
  labelWeight: "600",
  labelColor: { color: "rgba(148,163,184,0.9)" },
  zoomToSizeRatioFunction: (x: number) => x,
  itemSizesReference: "positions",
  zoomDuration: 200,
  minCameraRatio: 0.05,
  maxCameraRatio: 4,
  allowInvalidContainer: true,
  zIndex: true,
} as const;

type Props = {
  nodes: Node[];
  edges: Edge[];
  viewMode: TopologyViewMode;
  graph: TopologyGraph | null;
  groups: TopologyGroup[];
  groupEdges: TopologyGroupEdge[];
  summary: TopologySummary | null;
  filters: TopologyFilters;
  loading: boolean;
  isFullscreen: boolean;
  filterRailOpen: boolean;
  activeMatchKey: string | null;
  searchQuery: string;
  searchTotal: number;
  searchMatchIndex: number;
  focusedGroupLabel?: string | null;
  realtimeStatus: string;
  isRefreshing: boolean;
  onViewModeChange: (mode: TopologyViewMode) => void;
  onToggleFilterRail: () => void;
  onToggleFullscreen: () => void;
  onRefresh: () => void;
  onSearchChange: (query: string) => void;
  onNodeClick: (id: string, kind: "node" | "group") => void;
  onGroupDoubleClick: (id: string) => void;
  onEdgeClick: (id: string) => void;
  onPaneClick: () => void;
  onClearFocus?: () => void;
  onPrevMatch: () => void;
  onNextMatch: () => void;
};

type ContextMenuState = {
  x: number;
  y: number;
  nodeId: string;
  nodeLabel: string;
  nodeType: "device" | "group";
};

function clientPointFromSigmaEvent(event: {
  x: number;
  y: number;
  original?: Event;
}): {
  x: number;
  y: number;
} {
  const original = event.original;
  if (original instanceof MouseEvent)
    return { x: original.clientX, y: original.clientY };
  return { x: event.x, y: event.y };
}

function SigmaCanvasControls({
  viewMode,
  filterRailOpen,
  hasCustomPositions,
  onViewModeChange,
  onResetLayout,
}: {
  viewMode: TopologyViewMode;
  filterRailOpen: boolean;
  hasCustomPositions: boolean;
  onViewModeChange: (mode: TopologyViewMode) => void;
  onResetLayout: () => void;
}) {
  const { zoomIn, zoomOut, reset } = useCamera({ duration: 180 });

  const iconButtonClass = (active = false) =>
    cx(
      "flex h-8 w-8 items-center justify-center rounded-md text-[13px] transition-colors disabled:cursor-not-allowed disabled:opacity-45",
      active
        ? "bg-primary/18 text-primary"
        : "text-muted-foreground/75 hover:bg-white/6 hover:text-foreground",
    );

  return (
    <>
      {!filterRailOpen && (
        <div className="absolute left-3 top-3 z-20">
          <div
            className="flex items-center gap-2 rounded-xl border border-white/10 px-2.5 py-2 shadow-[0_16px_48px_rgba(0,0,0,0.28)]"
            style={{
              background: "rgba(7,14,25,0.88)",
              backdropFilter: "blur(12px)",
            }}
          >
            <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground/60">
              Show
            </span>
            <div className="flex rounded-md border border-white/10 bg-black/20 p-0.5">
              {(["location", "connection"] as TopologyViewMode[]).map(
                (mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => onViewModeChange(mode)}
                    className={cx(
                      "rounded-[4px] px-2.5 py-1 text-[11px] font-medium transition-colors",
                      viewMode === mode
                        ? "bg-primary/90 text-primary-foreground"
                        : "text-muted-foreground hover:bg-white/5",
                    )}
                  >
                    {mode === "location" ? "Location" : "Connection"}
                  </button>
                ),
              )}
            </div>
          </div>
        </div>
      )}

      <div className="absolute right-3 top-3 z-20">
        <div
          className="flex items-center gap-1.5 rounded-xl border border-white/10 p-1.5 shadow-[0_16px_48px_rgba(0,0,0,0.28)]"
          style={{
            background: "rgba(7,14,25,0.88)",
            backdropFilter: "blur(12px)",
          }}
        >
          <button
            type="button"
            className={iconButtonClass()}
            onClick={() => reset({ duration: 220 })}
            title="Fit view"
          >
            ⊞
          </button>
          {hasCustomPositions && (
            <>
              <div className="mx-0.5 h-6 w-px bg-white/10" />
              <button
                type="button"
                className={iconButtonClass()}
                onClick={() => {
                  onResetLayout();
                  reset({ duration: 260 });
                }}
                title="Reset layout to auto-arranged positions"
              >
                ⟳
              </button>
            </>
          )}
        </div>
      </div>

      <div className="absolute bottom-3 right-3 z-20">
        <div
          className="flex items-center gap-1 rounded-xl border border-white/10 p-1.5 shadow-[0_16px_48px_rgba(0,0,0,0.28)]"
          style={{
            background: "rgba(7,14,25,0.88)",
            backdropFilter: "blur(12px)",
          }}
        >
          <button
            type="button"
            className={iconButtonClass()}
            onClick={() => zoomOut({ duration: 180 })}
            title="Zoom out"
          >
            -
          </button>
          <button
            type="button"
            className={iconButtonClass()}
            onClick={() => reset({ duration: 220 })}
            title="Reset camera"
          >
            ⊙
          </button>
          <button
            type="button"
            className={iconButtonClass()}
            onClick={() => zoomIn({ duration: 180 })}
            title="Zoom in"
          >
            +
          </button>
        </div>
      </div>
    </>
  );
}

function GraphController({
  nodes,
  edges,
  viewMode,
  activeMatchKey,
  onNodeClick,
  onGroupDoubleClick,
  onEdgeClick,
  onPaneClick,
  onTooltipChange,
  onContextMenuRequest,
  onMultiSelectToggle,
  onMultiSelectionClear,
  storedPositions,
  onPositionSave,
}: {
  nodes: Node[];
  edges: Edge[];
  viewMode: TopologyViewMode;
  activeMatchKey: string | null;
  onNodeClick: (id: string, kind: "node" | "group") => void;
  onGroupDoubleClick: (id: string) => void;
  onEdgeClick: (id: string) => void;
  onPaneClick: () => void;
  onTooltipChange: (info: TooltipInfo) => void;
  onContextMenuRequest: (
    x: number,
    y: number,
    nodeId: string,
    nodeLabel: string,
    nodeType: "device" | "group",
  ) => void;
  onMultiSelectToggle: (id: string) => void;
  onMultiSelectionClear: () => void;
  storedPositions: Record<string, { x: number; y: number }>;
  onPositionSave: (id: string, x: number, y: number) => void;
}) {
  const sigma = useSigma<
    SigmaNodeAttributes | SigmaGroupNodeAttributes,
    SigmaEdgeAttributes
  >();
  const loadGraph = useLoadGraph<
    SigmaNodeAttributes | SigmaGroupNodeAttributes,
    SigmaEdgeAttributes
  >();
  const registerEvents = useRegisterEvents<
    SigmaNodeAttributes | SigmaGroupNodeAttributes,
    SigmaEdgeAttributes
  >();
  const { gotoNode } = useCamera({ duration: 350 });
  const { start, stop } = useWorkerLayoutForceAtlas2({
    settings: {
      gravity: 1.2,
      scalingRatio: 6,
      slowDown: 8,
      barnesHutOptimize: true,
      barnesHutTheta: 0.5,
      adjustSizes: true,
      strongGravityMode: false,
    },
  });

  const isDraggingRef = useRef(false);
  const dragNodeRef = useRef<string | null>(null);

  const nodeById = useMemo(
    () => new Map(nodes.map((node) => [node.id, node])),
    [nodes],
  );

  const edgeById = useMemo(
    () => new Map(edges.map((edge) => [edge.id, edge])),
    [edges],
  );

  useEffect(() => {
    const sigmaGraph = rfToSigmaGraph(nodes, edges);

    sigmaGraph.forEachNode((nodeId) => {
      const stored = storedPositions[nodeId];
      if (stored) {
        sigmaGraph.setNodeAttribute(nodeId, "x", stored.x);
        sigmaGraph.setNodeAttribute(nodeId, "y", stored.y);
      }
    });

    loadGraph(sigmaGraph);

    stop();
    start();

    const timer = window.setTimeout(
      () => {
        stop();
      },
      viewMode === "connection" ? 5000 : 2000,
    );

    return () => {
      window.clearTimeout(timer);
      stop();
    };
  }, [nodes, edges, loadGraph, start, stop, storedPositions, viewMode]);

  useEffect(() => {
    if (!activeMatchKey || !sigma.getGraph().hasNode(activeMatchKey)) return;
    gotoNode(activeMatchKey, { duration: 350 });
  }, [activeMatchKey, gotoNode, sigma]);

  useEffect(() => {
    registerEvents({
      clickNode({ node, event }) {
        if (isDraggingRef.current) return;
        const nodeData = nodeById.get(node);
        if (!nodeData) return;

        if (event.original instanceof MouseEvent && event.original.shiftKey) {
          onMultiSelectToggle(node);
          return;
        }

        onMultiSelectionClear();
        onNodeClick(node, nodeData.type === "group" ? "group" : "node");
      },
      doubleClickNode({ node, event }) {
        event.preventSigmaDefault();
        const nodeData = nodeById.get(node);
        if (nodeData?.type === "group") onGroupDoubleClick(node);
      },
      rightClickNode({ node, event }) {
        event.preventSigmaDefault();
        const nodeData = nodeById.get(node);
        if (!nodeData) return;

        const point = clientPointFromSigmaEvent(event);
        const nodeLabel =
          nodeData.type === "group"
            ? (nodeData.data as unknown as GroupNodeData).group.label
            : (nodeData.data as unknown as DeviceNodeData).node.label;
        onContextMenuRequest(
          point.x,
          point.y,
          node,
          nodeLabel,
          nodeData.type === "group" ? "group" : "device",
        );
      },
      clickEdge({ edge }) {
        onMultiSelectionClear();
        onEdgeClick(edge);
      },
      clickStage() {
        onMultiSelectionClear();
        onPaneClick();
      },
      rightClickStage({ event }) {
        event.preventSigmaDefault();
        onPaneClick();
      },
      enterNode({ node, event }) {
        const nodeData = nodeById.get(node);
        if (!nodeData) return;

        const point = clientPointFromSigmaEvent(event);
        if (nodeData.type === "device") {
          const data = nodeData.data as unknown as DeviceNodeData;
          onTooltipChange({
            kind: "node",
            node: data.node,
            x: point.x,
            y: point.y,
          });
        } else if (nodeData.type === "group") {
          const data = nodeData.data as unknown as GroupNodeData;
          onTooltipChange({
            kind: "group",
            group: data.group,
            x: point.x,
            y: point.y,
          });
        }
      },
      leaveNode() {
        onTooltipChange(null);
      },
      enterEdge({ edge, event }) {
        const edgeData = edgeById.get(edge);
        const data = edgeData?.data as Record<string, unknown> | undefined;
        if (!edgeData || !data || !("edge" in data)) return;

        const sourceNode = nodeById.get(edgeData.source);
        const targetNode = nodeById.get(edgeData.target);
        const sourceLabel =
          sourceNode?.type === "device"
            ? (sourceNode.data as unknown as DeviceNodeData).node.label
            : sourceNode?.type === "group"
              ? (sourceNode.data as unknown as GroupNodeData).group.label
              : edgeData.source;
        const targetLabel =
          targetNode?.type === "device"
            ? (targetNode.data as unknown as DeviceNodeData).node.label
            : targetNode?.type === "group"
              ? (targetNode.data as unknown as GroupNodeData).group.label
              : edgeData.target;
        const point = clientPointFromSigmaEvent(event);

        onTooltipChange({
          kind: "edge",
          edge: (data as TopologyEdgeData).edge,
          sourceLabel,
          targetLabel,
          x: point.x,
          y: point.y,
        });
      },
      leaveEdge() {
        onTooltipChange(null);
      },
      downNode({ node, event }) {
        isDraggingRef.current = false;
        dragNodeRef.current = node;
        stop();
        sigma.getCamera().disable();
        event.preventSigmaDefault();
      },
      mousemovebody(event) {
        if (!dragNodeRef.current) return;
        isDraggingRef.current = true;
        const coords = sigma.viewportToGraph({ x: event.x, y: event.y });
        sigma.getGraph().setNodeAttribute(dragNodeRef.current, "x", coords.x);
        sigma.getGraph().setNodeAttribute(dragNodeRef.current, "y", coords.y);
        sigma.refresh({ partialGraph: { nodes: [dragNodeRef.current] } });
      },
      mouseup() {
        if (dragNodeRef.current && isDraggingRef.current) {
          const graph = sigma.getGraph();
          const x = graph.getNodeAttribute(dragNodeRef.current, "x") as number;
          const y = graph.getNodeAttribute(dragNodeRef.current, "y") as number;
          onPositionSave(dragNodeRef.current, x, y);
        }
        dragNodeRef.current = null;
        sigma.getCamera().enable();
        window.setTimeout(() => {
          isDraggingRef.current = false;
        }, 50);
      },
    });
  }, [
    sigma,
    registerEvents,
    nodeById,
    edgeById,
    onNodeClick,
    onGroupDoubleClick,
    onEdgeClick,
    onPaneClick,
    onTooltipChange,
    onContextMenuRequest,
    onMultiSelectToggle,
    onMultiSelectionClear,
    onPositionSave,
    stop,
  ]);

  return null;
}

function SigmaTopologyCanvas({
  nodes,
  edges,
  viewMode,
  graph,
  groups,
  summary,
  filters,
  loading,
  isFullscreen,
  filterRailOpen,
  activeMatchKey,
  searchQuery,
  searchTotal,
  searchMatchIndex,
  focusedGroupLabel,
  realtimeStatus,
  isRefreshing,
  onViewModeChange,
  onToggleFilterRail,
  onToggleFullscreen,
  onRefresh,
  onSearchChange,
  onNodeClick,
  onGroupDoubleClick,
  onEdgeClick,
  onPaneClick,
  onClearFocus,
  onPrevMatch,
  onNextMatch,
}: Props) {
  const [tooltipInfo, setTooltipInfo] = useState<TooltipInfo>(null);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [multiSelection, setMultiSelection] = useState<Set<string>>(new Set());

  const {
    positions: storedPositions,
    setPosition,
    resetPositions,
    hasCustomPositions,
  } = useTopologyPositions(viewMode);

  const haloData = useMemo(() => extractHaloData(nodes), [nodes]);
  const hasNodes = nodes.some((node) => node.type !== "clusterHalo");
  const contextNode = contextMenu
    ? (graph?.nodes.find((node) => node.node_key === contextMenu.nodeId) ??
      null)
    : null;

  const handleMultiSelectToggle = useCallback((id: string) => {
    setMultiSelection((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }, []);

  const handleMultiSelectionClear = useCallback(() => {
    setMultiSelection(new Set());
  }, []);

  const handlePaneClickWrapped = useCallback(() => {
    handleMultiSelectionClear();
    setContextMenu(null);
    onPaneClick();
  }, [handleMultiSelectionClear, onPaneClick]);

  const handleContextMenuRequest = useCallback(
    (
      x: number,
      y: number,
      nodeId: string,
      nodeLabel: string,
      nodeType: "device" | "group",
    ) => {
      setContextMenu({ x, y, nodeId, nodeLabel, nodeType });
    },
    [],
  );

  return (
    <div
      className={cx(
        "relative flex h-full w-full flex-col overflow-hidden",
        isFullscreen && "fixed inset-0 z-50",
      )}
      data-halo-count={haloData.length}
      style={{
        backgroundColor: "#07111f",
        backgroundImage: [
          "radial-gradient(ellipse at 50% 38%, rgba(37,99,235,0.08), transparent 55%)",
          "repeating-linear-gradient(0deg, transparent 0, transparent 79px, rgba(148,163,184,0.014) 80px)",
          "repeating-linear-gradient(90deg, transparent 0, transparent 79px, rgba(148,163,184,0.014) 80px)",
        ].join(", "),
      }}
    >
      <TopologyTopBar
        summary={summary}
        graph={graph}
        filters={filters}
        liveState={{
          isRefreshing,
          realtimeStatus,
          lastUpdatedAt: null,
        }}
        isAdmin={false}
        filterRailOpen={filterRailOpen}
        recalculateBusy={false}
        isFullscreen={isFullscreen}
        searchQuery={searchQuery}
        searchTotal={searchTotal}
        searchMatchIndex={searchMatchIndex}
        focusedGroupLabel={focusedGroupLabel}
        onRefresh={onRefresh}
        onRecalculate={() => undefined}
        onToggleFilterRail={onToggleFilterRail}
        onToggleFullscreen={onToggleFullscreen}
        onSearchChange={onSearchChange}
        onPrevMatch={onPrevMatch}
        onNextMatch={onNextMatch}
        onClearFocus={onClearFocus}
      />

      <div className="relative min-h-0 flex-1">
        {loading && !hasNodes && (
          <div className="absolute inset-0 z-30 flex items-center justify-center">
            <div
              className="h-8 w-8 animate-spin rounded-full border-2"
              style={{
                borderColor: "rgba(96,165,250,0.25)",
                borderTopColor: "#60A5FA",
              }}
              aria-label="Loading topology"
            />
          </div>
        )}

        {!loading && !hasNodes && (
          <div className="absolute inset-0 z-30 flex items-center justify-center">
            <EmptyState
              title="No topology data"
              description={
                viewMode === "location"
                  ? "No groups to display for the current filters."
                  : "No nodes match the current filters."
              }
            />
          </div>
        )}

        <SigmaContainer<
          SigmaNodeAttributes | SigmaGroupNodeAttributes,
          SigmaEdgeAttributes
        >
          style={{ width: "100%", height: "100%", background: "transparent" }}
          settings={SIGMA_SETTINGS}
        >
          <GraphController
            nodes={nodes}
            edges={edges}
            viewMode={viewMode}
            activeMatchKey={activeMatchKey}
            onNodeClick={onNodeClick}
            onGroupDoubleClick={onGroupDoubleClick}
            onEdgeClick={onEdgeClick}
            onPaneClick={handlePaneClickWrapped}
            onTooltipChange={setTooltipInfo}
            onContextMenuRequest={handleContextMenuRequest}
            onMultiSelectToggle={handleMultiSelectToggle}
            onMultiSelectionClear={handleMultiSelectionClear}
            storedPositions={storedPositions}
            onPositionSave={setPosition}
          />

          {viewMode === "connection" && null}
          {/* Phase 3: <SigmaHaloLayer nodes={nodes} groups={groups} /> */}

          <SigmaCanvasControls
            viewMode={viewMode}
            filterRailOpen={filterRailOpen}
            hasCustomPositions={hasCustomPositions}
            onViewModeChange={onViewModeChange}
            onResetLayout={resetPositions}
          />
        </SigmaContainer>
      </div>

      <TopologyLegend viewMode={viewMode} />

      <TopologyStatusStrip
        viewMode={viewMode}
        nodeCount={nodes.filter((node) => node.type !== "clusterHalo").length}
        edgeCount={edges.length}
        groupCount={groups.length}
        filters={filters}
        searchQuery={searchQuery}
        searchTotal={searchTotal}
        focusedGroupLabel={focusedGroupLabel}
        graph={graph}
        summary={summary}
        realtimeStatus={realtimeStatus}
        isRefreshing={isRefreshing}
      />

      <TopologyTooltip info={tooltipInfo} />

      {multiSelection.size > 1 && (
        <div
          className="absolute bottom-16 left-1/2 z-40 flex -translate-x-1/2 items-center gap-2 rounded-lg border px-4 py-2 shadow-xl"
          style={{
            background: "rgba(10,18,32,0.97)",
            borderColor: "rgba(96,165,250,0.25)",
            backdropFilter: "blur(8px)",
          }}
        >
          <span className="text-xs" style={{ color: "rgba(148,163,184,0.7)" }}>
            {multiSelection.size} nodes selected
          </span>
          <div
            className="h-3 w-px"
            style={{ background: "rgba(148,163,184,0.15)" }}
          />
          <button
            className="rounded px-2 py-1 text-xs hover:bg-white/5"
            style={{ color: "rgba(148,163,184,0.5)" }}
            onClick={() => setMultiSelection(new Set())}
          >
            x
          </button>
        </div>
      )}

      {contextMenu && (
        <TopologyContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          nodeLabel={contextMenu.nodeLabel}
          nodeType={contextMenu.nodeType}
          onClose={() => setContextMenu(null)}
          onOpenDetail={() => {
            onNodeClick(
              contextMenu.nodeId,
              contextMenu.nodeType === "group" ? "group" : "node",
            );
            setContextMenu(null);
          }}
          onFocusGroup={
            contextMenu.nodeType === "group"
              ? () => {
                  onGroupDoubleClick(contextMenu.nodeId);
                  setContextMenu(null);
                }
              : undefined
          }
          onIsolate={() => setContextMenu(null)}
          onCopyIp={
            contextMenu.nodeType === "device" && contextNode?.ip
              ? () => {
                  void navigator.clipboard.writeText(contextNode.ip!);
                  setContextMenu(null);
                }
              : undefined
          }
        />
      )}
    </div>
  );
}

export default memo(SigmaTopologyCanvas);
