import "@xyflow/react/dist/style.css";

import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BackgroundVariant,
  BaseEdge,
  type Edge,
  type EdgeProps,
  MiniMap,
  type Node,
  type NodeTypes,
  ReactFlow,
  ReactFlowProvider,
  getBezierPath,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";

import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import type { DeviceNodeData, GroupNodeData, TopologyEdgeData } from "../lib/graphTransform";
import { edgeVisual } from "../lib/visuals";
import type {
  TopologyEdge,
  TopologyFilters,
  TopologyGraph,
  TopologyGroup,
  TopologyGroupEdge,
  TopologySummary,
  TopologyViewMode,
} from "../types";
import TopologyCanvasControls from "./TopologyCanvasControls";
import TopologyClusterHaloNode from "./TopologyClusterHaloNode";
import TopologyDeviceNode from "./TopologyDeviceNode";
import TopologyGroupNode from "./TopologyGroupNode";
import TopologyLegend from "./TopologyLegend";
import TopologyStatusStrip from "./TopologyStatusStrip";
import TopologyTooltip, { type TooltipInfo } from "./TopologyTooltip";

function TopologyFlowEdge(props: EdgeProps) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data } = props;
  const isGroupEdge = data && "groupEdge" in data;
  const edgeObj = isGroupEdge
    ? (data as { groupEdge: TopologyGroupEdge }).groupEdge
    : (data as { edge: TopologyEdge }).edge;

  const edgeType = isGroupEdge
    ? ((edgeObj as TopologyGroupEdge).edge_types[0] ?? "observed_flow")
    : (edgeObj as TopologyEdge).edge_type;
  const confidence = isGroupEdge ? 80 : (edgeObj as TopologyEdge).confidence;

  const visual = edgeVisual({ edge_type: edgeType, confidence });
  const isSelected = Boolean((data as Record<string, unknown>)?.isSelected);
  const isDimmed = Boolean((data as Record<string, unknown>)?.isDimmed);

  const [edgePath] = getBezierPath({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition });

  const opacity = isDimmed ? 0.1 : isSelected ? 1 : visual.opacity;
  const groupEventCount = isGroupEdge ? Number((edgeObj as TopologyGroupEdge).event_count || 0) : 0;
  const groupAlertCount = isGroupEdge ? Number((edgeObj as TopologyGroupEdge).alert_count || 0) : 0;
  const groupBoost = isGroupEdge ? Math.min(1.4, Math.log1p(groupEventCount) / 3) : 0;
  const strokeWidth = isSelected
    ? visual.width + 1
    : isGroupEdge
      ? visual.width + groupBoost
      : visual.width;
  const resolvedOpacity = isDimmed
    ? isGroupEdge ? 0.06 : 0.08
    : isSelected
      ? 1
      : isGroupEdge
        ? Math.min(0.58, 0.16 + groupBoost * 0.24 + (groupAlertCount > 0 ? 0.08 : 0))
        : opacity;

  return (
    <BaseEdge
      id={id}
      path={edgePath}
      style={{
        stroke: visual.stroke,
        strokeWidth,
        strokeDasharray: visual.dashArray,
        opacity: resolvedOpacity,
        transition: "stroke 180ms ease, stroke-width 180ms ease, opacity 180ms ease",
      }}
    />
  );
}

const nodeTypes: NodeTypes = {
  device: TopologyDeviceNode as unknown as NodeTypes["string"],
  group: TopologyGroupNode as unknown as NodeTypes["string"],
  clusterHalo: TopologyClusterHaloNode as unknown as NodeTypes["string"],
};

const edgeTypes = {
  topology: TopologyFlowEdge,
  group: TopologyFlowEdge,
};

type FlowInnerProps = {
  nodes: Node[];
  edges: Edge[];
  viewMode: TopologyViewMode;
  filterRailOpen: boolean;
  activeMatchKey: string | null;
  showMinimap: boolean;
  onToggleMinimap: () => void;
  focusedGroupLabel?: string | null;
  searchQuery: string;
  searchMatchIndex: number;
  searchTotal: number;
  isFullscreen: boolean;
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
  onTooltipChange: (info: TooltipInfo | null) => void;
};

function FlowInner({
  nodes: initialNodes,
  edges: initialEdges,
  viewMode,
  filterRailOpen,
  activeMatchKey,
  showMinimap,
  onToggleMinimap,
  focusedGroupLabel,
  searchQuery,
  searchMatchIndex,
  searchTotal,
  isFullscreen,
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
  onTooltipChange,
}: FlowInnerProps) {
  const { fitView } = useReactFlow();
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const prevKeyRef = useRef<string>("");

  const graphKey = useMemo(
    () =>
      `${viewMode}:${initialNodes
        .map((n) => n.id)
        .sort()
        .join(",")}`,
    [viewMode, initialNodes],
  );

  useEffect(() => {
    if (graphKey !== prevKeyRef.current) {
      prevKeyRef.current = graphKey;
      void requestAnimationFrame(() => fitView({ padding: 0.14, duration: 450 }));
    }
  }, [graphKey, fitView]);

  useEffect(() => {
    setNodes(initialNodes);
  }, [initialNodes, setNodes]);

  useEffect(() => {
    setEdges(initialEdges);
  }, [initialEdges, setEdges]);

  useEffect(() => {
    if (activeMatchKey) {
      void requestAnimationFrame(() =>
        fitView({ nodes: [{ id: activeMatchKey }], padding: 0.35, duration: 350 }),
      );
    }
  }, [activeMatchKey, fitView]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const kind = node.type === "group" ? "group" : "node";
      onNodeClick(node.id, kind);
    },
    [onNodeClick],
  );

  const handleNodeDoubleClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (node.type === "group") onGroupDoubleClick(node.id);
    },
    [onGroupDoubleClick],
  );

  const handleEdgeClick = useCallback(
    (_: React.MouseEvent, edge: Edge) => onEdgeClick(edge.id),
    [onEdgeClick],
  );

  const handleNodeMouseEnter = useCallback(
    (event: React.MouseEvent, node: Node) => {
      if (node.type === "device") {
        const d = node.data as unknown as DeviceNodeData;
        onTooltipChange({ kind: "node", node: d.node, x: event.clientX, y: event.clientY });
      } else if (node.type === "group") {
        const d = node.data as unknown as GroupNodeData;
        onTooltipChange({ kind: "group", group: d.group, x: event.clientX, y: event.clientY });
      }
    },
    [onTooltipChange],
  );

  const handleNodeMouseLeave = useCallback(() => {
    onTooltipChange(null);
  }, [onTooltipChange]);

  const handleEdgeMouseEnter = useCallback(
    (event: React.MouseEvent, edge: Edge) => {
      const data = edge.data as Record<string, unknown>;
      if (!data || (!("edge" in data) && !("groupEdge" in data))) return;

      const srcNode = nodes.find((n) => n.id === edge.source);
      const tgtNode = nodes.find((n) => n.id === edge.target);

      const srcLabel =
        srcNode?.type === "device"
          ? (srcNode.data as unknown as DeviceNodeData).node.label
          : srcNode?.type === "group"
            ? (srcNode.data as unknown as GroupNodeData).group.label
            : edge.source;
      const tgtLabel =
        tgtNode?.type === "device"
          ? (tgtNode.data as unknown as DeviceNodeData).node.label
          : tgtNode?.type === "group"
            ? (tgtNode.data as unknown as GroupNodeData).group.label
            : edge.target;

      if ("edge" in data) {
        onTooltipChange({
          kind: "edge",
          edge: (data as TopologyEdgeData).edge,
          sourceLabel: srcLabel,
          targetLabel: tgtLabel,
          x: event.clientX,
          y: event.clientY,
        });
      }
    },
    [nodes, onTooltipChange],
  );

  const handleEdgeMouseLeave = useCallback(() => {
    onTooltipChange(null);
  }, [onTooltipChange]);

  const miniMapNodeColor = useCallback((node: Node) => {
    if (node.type === "device") {
      const d = node.data as unknown as DeviceNodeData;
      return d.node.is_stale ? "#F97316" : "#4ADE80";
    }
    if (node.type === "group") {
      const d = node.data as unknown as GroupNodeData;
      return d.group.alert_count > 0 ? "#F87171" : "#60A5FA";
    }
    return "#4B5563";
  }, []);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={handleNodeClick}
      onNodeDoubleClick={handleNodeDoubleClick}
      onEdgeClick={handleEdgeClick}
      onPaneClick={onPaneClick}
      onNodeMouseEnter={handleNodeMouseEnter}
      onNodeMouseLeave={handleNodeMouseLeave}
      onEdgeMouseEnter={handleEdgeMouseEnter}
      onEdgeMouseLeave={handleEdgeMouseLeave}
      fitView
      fitViewOptions={{ padding: 0.14 }}
      minZoom={0.07}
      maxZoom={3.5}
      nodesDraggable={false}
      nodesConnectable={false}
      proOptions={{ hideAttribution: true }}
    >
      <Background
        variant={BackgroundVariant.Lines}
        gap={48}
        size={1}
        color="rgba(96,165,250,0.09)"
        style={{ background: "transparent" }}
      />

      <TopologyCanvasControls
        viewMode={viewMode}
        filterRailOpen={filterRailOpen}
        showMinimap={showMinimap}
        isFullscreen={isFullscreen}
        isRefreshing={isRefreshing}
        onViewModeChange={onViewModeChange}
        onToggleFilterRail={onToggleFilterRail}
        onToggleMinimap={onToggleMinimap}
        onToggleFullscreen={onToggleFullscreen}
        onRefresh={onRefresh}
        focusedGroupLabel={focusedGroupLabel}
        onClearFocus={onClearFocus}
        searchQuery={searchQuery}
        searchMatchIndex={searchMatchIndex}
        searchTotal={searchTotal}
        onSearchChange={onSearchChange}
        onPrevMatch={onPrevMatch}
        onNextMatch={onNextMatch}
      />

      {showMinimap && (
        <MiniMap
          position="bottom-right"
          nodeColor={miniMapNodeColor}
          nodeStrokeWidth={0}
          maskColor="rgba(10,15,26,0.65)"
          style={{
            background: "rgba(10,15,26,0.88)",
            border: "1px solid rgba(148,163,184,0.15)",
            borderRadius: 6,
            marginBottom: 68,
            marginRight: 12,
          }}
          pannable
          zoomable
        />
      )}
    </ReactFlow>
  );
}

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

function TopologyCanvas({
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
  const [showMinimap, setShowMinimap] = useState(false);
  const [tooltipInfo, setTooltipInfo] = useState<TooltipInfo>(null);

  const isEmpty = !loading && nodes.length === 0;

  if (loading && nodes.length === 0) {
    return (
      <div className="flex h-full items-center justify-center" style={{ background: "#0d1117" }}>
        <div
          className="h-8 w-8 animate-spin rounded-full border-2"
          style={{ borderColor: "rgba(96,165,250,0.25)", borderTopColor: "#60A5FA" }}
          aria-label="Loading topology"
        />
      </div>
    );
  }

  if (isEmpty) {
    return (
      <div className="flex h-full items-center justify-center" style={{ background: "#0d1117" }}>
        <EmptyState
          title="No topology data"
          description={
            viewMode === "location"
              ? "No groups to display for the current filters."
              : "No nodes match the current filters."
          }
        />
      </div>
    );
  }

  return (
    <div
      className={cx(
        "relative h-full w-full overflow-hidden",
        isFullscreen && "fixed inset-0 z-50",
      )}
      style={{
        backgroundColor: "#07111f",
        backgroundImage: [
          "radial-gradient(circle at 50% 42%, rgba(37,99,235,0.11), transparent 36%)",
          "radial-gradient(circle at 12% 18%, rgba(14,165,233,0.08), transparent 28%)",
          "linear-gradient(rgba(255,255,255,0.012), rgba(255,255,255,0.012))",
          "repeating-linear-gradient(0deg, transparent 0, transparent 95px, rgba(148,163,184,0.025) 96px)",
          "repeating-linear-gradient(90deg, transparent 0, transparent 95px, rgba(148,163,184,0.025) 96px)",
        ].join(", "),
      }}
    >
      <div
        className="pointer-events-none absolute inset-0 z-[1]"
        style={{
          backgroundImage: [
            "linear-gradient(90deg, rgba(255,255,255,0.015), transparent 18%, transparent 82%, rgba(255,255,255,0.015))",
            "repeating-linear-gradient(180deg, transparent 0, transparent 4px, rgba(255,255,255,0.012) 5px)",
          ].join(", "),
          opacity: 0.34,
        }}
      />
      <ReactFlowProvider>
        <FlowInner
          nodes={nodes}
          edges={edges}
          viewMode={viewMode}
          filterRailOpen={filterRailOpen}
          activeMatchKey={activeMatchKey}
          showMinimap={showMinimap}
          onToggleMinimap={() => setShowMinimap((p) => !p)}
          focusedGroupLabel={focusedGroupLabel}
          searchQuery={searchQuery}
          searchMatchIndex={searchMatchIndex}
          searchTotal={searchTotal}
          isFullscreen={isFullscreen}
          isRefreshing={isRefreshing}
          onViewModeChange={onViewModeChange}
          onToggleFilterRail={onToggleFilterRail}
          onToggleFullscreen={onToggleFullscreen}
          onRefresh={onRefresh}
          onSearchChange={onSearchChange}
          onNodeClick={onNodeClick}
          onGroupDoubleClick={onGroupDoubleClick}
          onEdgeClick={onEdgeClick}
          onPaneClick={onPaneClick}
          onClearFocus={onClearFocus}
          onPrevMatch={onPrevMatch}
          onNextMatch={onNextMatch}
          onTooltipChange={setTooltipInfo}
        />
      </ReactFlowProvider>

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
    </div>
  );
}

export default memo(TopologyCanvas);
