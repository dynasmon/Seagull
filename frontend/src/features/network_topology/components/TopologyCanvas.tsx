import "@xyflow/react/dist/style.css";

import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { OnNodeDrag } from "@xyflow/react";
import {
  Background,
  BackgroundVariant,
  BaseEdge,
  type Edge,
  type EdgeProps,
  MiniMap,
  type Node,
  type NodeTypes,
  Position,
  ReactFlow,
  ReactFlowProvider,
  getBezierPath,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";

import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import type { ClusterHaloNodeData, DeviceNodeData, GroupNodeData, TopologyEdgeData } from "../lib/graphTransform";
import { stableTopologyHash } from "../lib/topologyLayoutEngine";
import { edgeVisual } from "../lib/visuals";
import { useTopologyPositions } from "../hooks/useTopologyPositions";
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

function edgeHandlePositions(
  sx: number, sy: number, tx: number, ty: number,
): { sp: Position; tp: Position } {
  const dx = tx - sx;
  const dy = ty - sy;
  if (Math.abs(dx) >= Math.abs(dy) * 0.7) {
    return dx >= 0
      ? { sp: Position.Right, tp: Position.Left }
      : { sp: Position.Left, tp: Position.Right };
  }
  return dy >= 0
    ? { sp: Position.Bottom, tp: Position.Top }
    : { sp: Position.Top, tp: Position.Bottom };
}

function TopologyFlowEdge(props: EdgeProps) {
  const { id, sourceX, sourceY, targetX, targetY, data } = props;
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

  const groupEventCount = isGroupEdge ? Number((edgeObj as TopologyGroupEdge).event_count || 0) : 0;
  const groupAlertCount = isGroupEdge ? Number((edgeObj as TopologyGroupEdge).alert_count || 0) : 0;
  const groupBoost = isGroupEdge ? Math.min(1.4, Math.log1p(groupEventCount) / 3) : 0;

  const parallelShift = isGroupEdge ? ((stableTopologyHash(id) % 5) - 2) * 11 : 0;
  const edgeData = data as unknown as TopologyEdgeData;
  const sourceRadius = isGroupEdge ? 0 : (edgeData.sourceRadius ?? 11);
  const targetRadius = isGroupEdge ? 0 : (edgeData.targetRadius ?? 11);

  const dx = targetX - sourceX;
  const dy = targetY - sourceY;
  const dist = Math.sqrt(dx * dx + dy * dy) || 1;
  const nx = dx / dist;
  const ny = dy / dist;

  const adjSX = sourceX + nx * sourceRadius;
  const adjSY = sourceY + ny * sourceRadius + parallelShift;
  const adjTX = targetX - nx * targetRadius;
  const adjTY = targetY - ny * targetRadius + parallelShift;

  const { sp, tp } = edgeHandlePositions(adjSX, adjSY, adjTX, adjTY);
  const curvature = isGroupEdge ? 0.28 : 0.42;
  const [edgePath] = getBezierPath({
    sourceX: adjSX,
    sourceY: adjSY,
    sourcePosition: sp,
    targetX: adjTX,
    targetY: adjTY,
    targetPosition: tp,
    curvature,
  });

  const strokeWidth = isSelected
    ? visual.width + 1.5
    : isGroupEdge
      ? visual.width + groupBoost
      : visual.width;
  const resolvedOpacity = isDimmed
    ? (isGroupEdge ? 0.05 : 0.07)
    : isSelected
      ? 1
      : isGroupEdge
        ? Math.min(0.62, 0.18 + groupBoost * 0.26 + (groupAlertCount > 0 ? 0.10 : 0))
        : visual.opacity;

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
  hasCustomPositions: boolean;
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
  onResetLayout: () => void;
  onSearchChange: (query: string) => void;
  onNodeClick: (id: string, kind: "node" | "group") => void;
  onGroupDoubleClick: (id: string) => void;
  onEdgeClick: (id: string) => void;
  onPaneClick: () => void;
  onClearFocus?: () => void;
  onPrevMatch: () => void;
  onNextMatch: () => void;
  onPositionSave: (nodeId: string, x: number, y: number) => void;
  onTooltipChange: (info: TooltipInfo | null) => void;
};

function FlowInner({
  nodes: initialNodes,
  edges: initialEdges,
  viewMode,
  filterRailOpen,
  activeMatchKey,
  showMinimap,
  hasCustomPositions,
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
  onResetLayout,
  onSearchChange,
  onNodeClick,
  onGroupDoubleClick,
  onEdgeClick,
  onPaneClick,
  onClearFocus,
  onPrevMatch,
  onNextMatch,
  onPositionSave,
  onTooltipChange,
}: FlowInnerProps) {
  const { fitView } = useReactFlow();
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const prevKeyRef = useRef<string>("");
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;

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
      void requestAnimationFrame(() => fitView({ padding: 0.22, maxZoom: 1.05, duration: 450 }));
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
        fitView({ nodes: [{ id: activeMatchKey }], padding: 0.45, maxZoom: 1.2, duration: 350 }),
      );
    }
  }, [activeMatchKey, fitView]);

  const handleNodeDragStop: OnNodeDrag = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      if (node.draggable === false) return;
      onPositionSave(node.id, node.position.x, node.position.y);

      const nodeData = node.data as unknown as DeviceNodeData;
      if (nodeData.importance !== "anchor" || !nodeData.groupKey) return;

      const haloId = `halo:${nodeData.groupKey}`;
      const haloNode = nodesRef.current.find((n) => n.id === haloId);
      if (!haloNode) return;

      const radius = (haloNode.data as unknown as ClusterHaloNodeData).radius;
      const haloX = node.position.x + 40 - radius;
      const haloY = node.position.y + 40 - radius;
      onPositionSave(haloId, haloX, haloY);
      setNodes((nds) =>
        nds.map((n) => (n.id === haloId ? { ...n, position: { x: haloX, y: haloY } } : n)),
      );
    },
    [onPositionSave, setNodes],
  );

  const handleResetLayout = useCallback(() => {
    onResetLayout();
    setNodes(initialNodes);
    void requestAnimationFrame(() => fitView({ padding: 0.22, maxZoom: 1.05, duration: 450 }));
  }, [onResetLayout, setNodes, initialNodes, fitView]);

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
      onNodeDragStop={handleNodeDragStop}
      onEdgeClick={handleEdgeClick}
      onPaneClick={onPaneClick}
      onNodeMouseEnter={handleNodeMouseEnter}
      onNodeMouseLeave={handleNodeMouseLeave}
      onEdgeMouseEnter={handleEdgeMouseEnter}
      onEdgeMouseLeave={handleEdgeMouseLeave}
      fitView
      fitViewOptions={{ padding: 0.22, maxZoom: 1.05 }}
      minZoom={0.07}
      maxZoom={3.5}
      nodesDraggable={true}
      nodesConnectable={false}
      proOptions={{ hideAttribution: true }}
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={30}
        size={1}
        color="rgba(96,165,250,0.05)"
        style={{ background: "transparent" }}
      />

      <TopologyCanvasControls
        viewMode={viewMode}
        filterRailOpen={filterRailOpen}
        showMinimap={showMinimap}
        isFullscreen={isFullscreen}
        isRefreshing={isRefreshing}
        hasCustomPositions={hasCustomPositions}
        onViewModeChange={onViewModeChange}
        onToggleFilterRail={onToggleFilterRail}
        onToggleMinimap={onToggleMinimap}
        onToggleFullscreen={onToggleFullscreen}
        onRefresh={onRefresh}
        onResetLayout={handleResetLayout}
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
  const { positions: storedPositions, setPosition, resetPositions, hasCustomPositions } = useTopologyPositions(viewMode);

  const mergedNodes = useMemo(
    () => nodes.map((node) => {
      const pos = storedPositions[node.id];
      return pos ? { ...node, position: pos } : node;
    }),
    [nodes, storedPositions],
  );

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
          "radial-gradient(ellipse at 50% 38%, rgba(37,99,235,0.08), transparent 55%)",
          "repeating-linear-gradient(0deg, transparent 0, transparent 79px, rgba(148,163,184,0.014) 80px)",
          "repeating-linear-gradient(90deg, transparent 0, transparent 79px, rgba(148,163,184,0.014) 80px)",
        ].join(", "),
      }}
    >
      <ReactFlowProvider>
        <FlowInner
          nodes={mergedNodes}
          edges={edges}
          viewMode={viewMode}
          filterRailOpen={filterRailOpen}
          activeMatchKey={activeMatchKey}
          showMinimap={showMinimap}
          hasCustomPositions={hasCustomPositions}
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
          onResetLayout={resetPositions}
          onSearchChange={onSearchChange}
          onNodeClick={onNodeClick}
          onGroupDoubleClick={onGroupDoubleClick}
          onEdgeClick={onEdgeClick}
          onPaneClick={onPaneClick}
          onClearFocus={onClearFocus}
          onPrevMatch={onPrevMatch}
          onNextMatch={onNextMatch}
          onPositionSave={setPosition}
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
