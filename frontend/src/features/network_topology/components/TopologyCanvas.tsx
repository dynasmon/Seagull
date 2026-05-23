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
  getSmoothStepPath,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";

import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import { ISOLATED_GHOST_NODE_ID, type ClusterHaloNodeData, type DeviceNodeData, type GroupNodeData, type TopologyEdgeData } from "../lib/graphTransform";
import { stableTopologyHash } from "../lib/topologyLayoutEngine";
import { topologyNodeSetKey } from "../lib/topologyLayoutELK";
import { edgeVisual, severityColor } from "../lib/visuals";
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
import { TopologyContextMenu } from "./TopologyContextMenu";
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

const EDGE_TYPE_SHORT_LABELS: Record<string, string> = {
  observed_flow: "flow",
  alert_related: "alert",
  exposure_related: "exposure",
  listens_on: "listens",
  resolved_dns: "dns",
  member_of_subnet: "subnet",
  route_next_hop: "route",
  inferred_relationship: "inferred",
};

const PILL_SUPPRESSED_EDGE_TYPES = new Set<string>(["member_of_subnet", "same_agent"]);

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function TopologyFlowEdge(props: EdgeProps) {
  const { id, sourceX, sourceY, targetX, targetY, data } = props;
  const [hovered, setHovered] = useState(false);
  const isGroupEdge = data && "groupEdge" in data;
  const edgeObj = isGroupEdge
    ? (data as { groupEdge: TopologyGroupEdge }).groupEdge
    : (data as { edge: TopologyEdge }).edge;

  const edgeType = isGroupEdge
    ? ((edgeObj as TopologyGroupEdge).edge_types[0] ?? "observed_flow")
    : (edgeObj as TopologyEdge).edge_type;
  const confidence = isGroupEdge ? 80 : (edgeObj as TopologyEdge).confidence;
  const eventCount = isGroupEdge
    ? Number((edgeObj as TopologyGroupEdge).event_count || 0)
    : Number((edgeObj as TopologyEdge).event_count || 0);

  const visual = edgeVisual({ edge_type: edgeType, confidence });
  const isSelected = Boolean((data as Record<string, unknown>)?.isSelected);
  const isDimmed = Boolean((data as Record<string, unknown>)?.isDimmed);

  const groupAlertCount = isGroupEdge ? Number((edgeObj as TopologyGroupEdge).alert_count || 0) : 0;
  const groupBoost = isGroupEdge ? Math.min(1.4, Math.log1p(eventCount) / 3) : 0;

  const edgeData = data as unknown as TopologyEdgeData;
  const sourceRadius = isGroupEdge ? 0 : (edgeData.sourceRadius ?? 16);
  const targetRadius = isGroupEdge ? 0 : (edgeData.targetRadius ?? 16);

  const parallelIndex = isGroupEdge ? (stableTopologyHash(id) % 5) - 2 : (edgeData.parallelIndex ?? 0);
  const parallelTotal = isGroupEdge ? 1 : (edgeData.parallelTotal ?? 1);

  const dx = targetX - sourceX;
  const dy = targetY - sourceY;
  const dist = Math.sqrt(dx * dx + dy * dy) || 1;
  const nx = dx / dist;
  const ny = dy / dist;

  const adjSX = sourceX + nx * sourceRadius;
  const adjSY = sourceY + ny * sourceRadius;
  const adjTX = targetX - nx * targetRadius;
  const adjTY = targetY - ny * targetRadius;

  const offset = parallelTotal > 1
    ? (parallelIndex - (parallelTotal - 1) / 2) * 18
    : 0;

  const { sp, tp } = edgeHandlePositions(adjSX, adjSY, adjTX, adjTY);
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX: adjSX,
    sourceY: adjSY,
    sourcePosition: sp,
    targetX: adjTX,
    targetY: adjTY,
    targetPosition: tp,
    borderRadius: 12,
    offset,
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
        ? Math.min(0.62, 0.18 + groupBoost * 0.26 + (groupAlertCount > 0 ? 0.1 : 0))
        : visual.opacity;

  const reducedMotion = prefersReducedMotion();
  const showFlowPulse =
    !isGroupEdge &&
    edgeType === "observed_flow" &&
    eventCount > 200 &&
    !isDimmed &&
    !reducedMotion;

  const showPill = !isDimmed && !PILL_SUPPRESSED_EDGE_TYPES.has(edgeType);
  const pillLabel = EDGE_TYPE_SHORT_LABELS[edgeType] ?? edgeType;
  const pillOpacity = isSelected || hovered ? 1 : 0.45;

  return (
    <>
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
      {showFlowPulse && (
        <path
          d={edgePath}
          fill="none"
          stroke={visual.stroke}
          strokeWidth={strokeWidth + 0.6}
          strokeDasharray="10 14"
          strokeLinecap="round"
          opacity={Math.min(0.85, resolvedOpacity + 0.35)}
          pointerEvents="none"
        >
          <animate
            attributeName="stroke-dashoffset"
            from="0"
            to="-24"
            dur="2.4s"
            repeatCount="indefinite"
          />
        </path>
      )}
      {showPill && (
        <foreignObject
          x={labelX - 30}
          y={labelY - 8}
          width={60}
          height={16}
          style={{ overflow: "visible", pointerEvents: "auto" }}
        >
          <div
            onMouseEnter={() => setHovered(true)}
            onMouseLeave={() => setHovered(false)}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "rgba(7,14,25,0.92)",
              border: `1px solid ${visual.stroke}60`,
              borderRadius: 3,
              padding: "1px 4px",
              fontSize: 8,
              fontWeight: 700,
              color: visual.stroke,
              whiteSpace: "nowrap",
              letterSpacing: "0.02em",
              opacity: pillOpacity,
              transition: "opacity 160ms ease",
              cursor: "default",
            }}
          >
            {pillLabel}
          </div>
        </foreignObject>
      )}
      {parallelTotal > 1 && parallelIndex === 0 && !isDimmed && !isSelected && (
        <foreignObject
          x={(sourceX + targetX) / 2 - 10}
          y={(sourceY + targetY) / 2 - 8}
          width={20}
          height={16}
          style={{ overflow: "visible", pointerEvents: "none" }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "rgba(7,14,25,0.88)",
              border: `1px solid ${visual.stroke}50`,
              borderRadius: 8,
              width: 20,
              height: 16,
              fontSize: 8,
              fontWeight: 700,
              color: visual.stroke,
              lineHeight: 1,
            }}
          >
            {parallelTotal}
          </div>
        </foreignObject>
      )}
    </>
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

function isNodeInsideHalo(
  nodePos: { x: number; y: number },
  haloNode: Node,
  haloRadius: number,
): boolean {
  const nodeCenterX = nodePos.x + 48;
  const nodeCenterY = nodePos.y + 48;
  const haloCenterX = haloNode.position.x + haloRadius;
  const haloCenterY = haloNode.position.y + haloRadius;
  const dist = Math.sqrt(
    Math.pow(nodeCenterX - haloCenterX, 2) +
    Math.pow(nodeCenterY - haloCenterY, 2),
  );
  return dist <= haloRadius;
}

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
  onMultiSelectToggle: (id: string) => void;
  onMultiSelectionClear: () => void;
  onContextMenuRequest: (x: number, y: number, nodeId: string, nodeLabel: string, nodeType: "device" | "group") => void;
  onHaloEscape: (nodeId: string, nodeLabel: string, groupLabel: string, prevPosition: { x: number; y: number }) => void;
  onIsolatedGhostClick: () => void;
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
  onMultiSelectToggle,
  onMultiSelectionClear,
  onContextMenuRequest,
  onHaloEscape,
  onIsolatedGhostClick,
}: FlowInnerProps) {
  const { fitView } = useReactFlow();
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const prevKeyRef = useRef<string>("");
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;
  const prevNodePositionRef = useRef<{ x: number; y: number } | null>(null);

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

  const handleNodeDragStart: OnNodeDrag = useCallback(
    (_event, node) => {
      prevNodePositionRef.current = { x: node.position.x, y: node.position.y };
    },
    [],
  );

  const handleNodeDragStop: OnNodeDrag = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      if (node.draggable === false) return;

      const nodeDataFull = node.data as unknown as DeviceNodeData;
      if (node.type === "device" && nodeDataFull.groupKey) {
        const haloId = `halo:${nodeDataFull.groupKey}`;
        const haloNodeForEscape = nodesRef.current.find((n) => n.id === haloId);
        if (haloNodeForEscape) {
          const haloRadius = (haloNodeForEscape.data as unknown as ClusterHaloNodeData).radius;
          if (!isNodeInsideHalo(node.position, haloNodeForEscape, haloRadius)) {
            const prevPos = prevNodePositionRef.current;
            if (prevPos) {
              const haloData = haloNodeForEscape.data as unknown as ClusterHaloNodeData;
              onHaloEscape(node.id, nodeDataFull.node.label, haloData.group.label, prevPos);
            }
          }
        }
      }

      onPositionSave(node.id, node.position.x, node.position.y);

      const nodeData = node.data as unknown as DeviceNodeData;
      if (nodeData.importance !== "anchor" || !nodeData.groupKey) return;

      const haloId = `halo:${nodeData.groupKey}`;
      const haloNode = nodesRef.current.find((n) => n.id === haloId);
      if (!haloNode) return;

      const radius = (haloNode.data as unknown as ClusterHaloNodeData).radius;
      const haloX = node.position.x + 48 - radius;
      const haloY = node.position.y + 48 - radius;
      onPositionSave(haloId, haloX, haloY);
      setNodes((nds) =>
        nds.map((n) => (n.id === haloId ? { ...n, position: { x: haloX, y: haloY } } : n)),
      );

      const groupMembers = nodesRef.current.filter(
        (n) =>
          n.type === "device" &&
          (n.data as unknown as DeviceNodeData).groupKey === nodeData.groupKey &&
          n.id !== node.id,
      );
      for (const member of groupMembers) {
        onPositionSave(member.id, member.position.x, member.position.y);
      }
    },
    [onPositionSave, setNodes, onHaloEscape],
  );

  const handleResetLayout = useCallback(() => {
    onResetLayout();
    setNodes(initialNodes);
    void requestAnimationFrame(() => fitView({ padding: 0.22, maxZoom: 1.05, duration: 450 }));
  }, [onResetLayout, setNodes, initialNodes, fitView]);

  const handleNodeClick = useCallback(
    (event: React.MouseEvent, node: Node) => {
      if (node.id === ISOLATED_GHOST_NODE_ID) {
        onIsolatedGhostClick();
        return;
      }
      if (event.shiftKey) {
        onMultiSelectToggle(node.id);
        return;
      }
      onMultiSelectionClear();
      if (node.type === "clusterHalo") {
        onNodeClick(node.id.replace(/^halo:/, ""), "group");
        return;
      }
      const kind = node.type === "group" ? "group" : "node";
      onNodeClick(node.id, kind);
    },
    [onMultiSelectToggle, onMultiSelectionClear, onNodeClick, onIsolatedGhostClick],
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

  const handleNodeContextMenu = useCallback(
    (event: React.MouseEvent, node: Node) => {
      event.preventDefault();
      const label =
        node.type === "device"
          ? (node.data as unknown as DeviceNodeData).node.label
          : (node.data as unknown as GroupNodeData).group.label;
      const nodeType: "device" | "group" = node.type === "group" ? "group" : "device";
      onContextMenuRequest(event.clientX, event.clientY, node.id, label, nodeType);
    },
    [onContextMenuRequest],
  );

  const handleNodeMouseEnter = useCallback(
    (event: React.MouseEvent, node: Node) => {
      if (node.id === ISOLATED_GHOST_NODE_ID) return;
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
        const ed = data as TopologyEdgeData;
        onTooltipChange({
          kind: "edge",
          edge: ed.edge,
          sourceLabel: srcLabel,
          targetLabel: tgtLabel,
          isBidirectional: Boolean(ed.isBidirectional),
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
      onNodeDragStart={handleNodeDragStart}
      onNodeDragStop={handleNodeDragStop}
      onNodeContextMenu={handleNodeContextMenu}
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
          nodeStrokeWidth={2}
          nodeStrokeColor={(node) => {
            if (node.type === "device") {
              const d = node.data as unknown as DeviceNodeData;
              return d.node.alert_count > 0 ? severityColor(d.node.severity) : "transparent";
            }
            return "transparent";
          }}
          maskColor="rgba(7,14,25,0.72)"
          style={{
            background: "rgba(7,14,25,0.92)",
            border: "1px solid rgba(148,163,184,0.12)",
            borderRadius: 8,
            marginBottom: 72,
            marginRight: 14,
            width: 160,
            height: 110,
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
  isolatedCount: number;
  showIsolated: boolean;
  onShowIsolated: () => void;
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
  isolatedCount,
  showIsolated,
  onShowIsolated,
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
  const [haloEscapeAlert, setHaloEscapeAlert] = useState<{
    nodeId: string;
    nodeLabel: string;
    groupLabel: string;
    prevPosition: { x: number; y: number };
  } | null>(null);
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    nodeId: string;
    nodeLabel: string;
    nodeType: "device" | "group";
  } | null>(null);
  const [multiSelection, setMultiSelection] = useState<Set<string>>(new Set());

  const topologyKey = useMemo(() => topologyNodeSetKey(graph), [graph]);
  const { positions: storedPositions, setPosition, resetPositions, hasCustomPositions } = useTopologyPositions(viewMode, topologyKey);
  const agentNodeCount = useMemo(() => {
    const stats = summary?.node_type_breakdown ?? [];
    const fromStats = stats.find((s) => s.node_type === "agent")?.count;
    if (typeof fromStats === "number") return fromStats;
    return Number(summary?.agent_count ?? 0);
  }, [summary]);

  const mergedNodes = useMemo(
    () => nodes.map((node) => {
      const pos = storedPositions[node.id];
      if (pos) return { ...node, position: pos };

      if (node.type === "device") {
        const nodeData = node.data as unknown as DeviceNodeData;
        if (nodeData.groupKey) {
          const haloId = `halo:${nodeData.groupKey}`;
          const haloPos = storedPositions[haloId];
          if (haloPos) {
            const haloNode = nodes.find((n) => n.id === haloId);
            const radius = haloNode
              ? (haloNode.data as unknown as ClusterHaloNodeData).radius
              : 150;
            const origHaloCenter = haloNode
              ? { x: haloNode.position.x + radius, y: haloNode.position.y + radius }
              : { x: node.position.x, y: node.position.y };
            const savedHaloCenter = { x: haloPos.x + radius, y: haloPos.y + radius };
            const dx = savedHaloCenter.x - origHaloCenter.x;
            const dy = savedHaloCenter.y - origHaloCenter.y;
            return { ...node, position: { x: node.position.x + dx, y: node.position.y + dy } };
          }
        }
      }
      return node;
    }),
    [nodes, storedPositions],
  );

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

  const handleContextMenuRequest = useCallback(
    (x: number, y: number, nodeId: string, nodeLabel: string, nodeType: "device" | "group") => {
      setContextMenu({ x, y, nodeId, nodeLabel, nodeType });
    },
    [],
  );

  const handleHaloEscape = useCallback(
    (nodeId: string, nodeLabel: string, groupLabel: string, prevPosition: { x: number; y: number }) => {
      setHaloEscapeAlert({ nodeId, nodeLabel, groupLabel, prevPosition });
    },
    [],
  );

  const handlePaneClickWrapped = useCallback(() => {
    setMultiSelection(new Set());
    setContextMenu(null);
    onPaneClick();
  }, [onPaneClick]);

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

  const contextNode = contextMenu
    ? graph?.nodes.find((n) => n.node_key === contextMenu.nodeId) ?? null
    : null;

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
          onPaneClick={handlePaneClickWrapped}
          onClearFocus={onClearFocus}
          onPrevMatch={onPrevMatch}
          onNextMatch={onNextMatch}
          onPositionSave={setPosition}
          onTooltipChange={setTooltipInfo}
          onMultiSelectToggle={handleMultiSelectToggle}
          onMultiSelectionClear={handleMultiSelectionClear}
          onContextMenuRequest={handleContextMenuRequest}
          onHaloEscape={handleHaloEscape}
          onIsolatedGhostClick={onShowIsolated}
        />
      </ReactFlowProvider>

      <TopologyLegend viewMode={viewMode} />

      <TopologyStatusStrip
        viewMode={viewMode}
        nodeCount={nodes.filter((node) => node.type !== "clusterHalo").length}
        edgeCount={edges.length}
        groupCount={groups.length}
        agentNodeCount={agentNodeCount}
        isolatedCount={showIsolated ? 0 : isolatedCount}
        onShowIsolated={isolatedCount > 0 && !showIsolated ? onShowIsolated : undefined}
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
          className="absolute bottom-16 left-1/2 z-40 -translate-x-1/2 flex items-center gap-2 rounded-lg border px-4 py-2 shadow-xl"
          style={{
            background: "rgba(10,18,32,0.97)",
            borderColor: "rgba(96,165,250,0.25)",
            backdropFilter: "blur(8px)",
          }}
        >
          <span className="text-xs" style={{ color: "rgba(148,163,184,0.7)" }}>
            {multiSelection.size} nodes selected
          </span>
          <div className="h-3 w-px" style={{ background: "rgba(148,163,184,0.15)" }} />
          <button
            className="rounded px-2 py-1 text-xs font-medium hover:bg-white/10"
            style={{ color: "#60A5FA" }}
          >
            View alerts
          </button>
          <button
            className="rounded px-2 py-1 text-xs font-medium hover:bg-white/10"
            style={{ color: "#60A5FA" }}
          >
            Export IPs
          </button>
          <button
            className="rounded px-2 py-1 text-xs hover:bg-white/5"
            style={{ color: "rgba(148,163,184,0.5)" }}
            onClick={() => setMultiSelection(new Set())}
          >
            ✕
          </button>
        </div>
      )}

      {haloEscapeAlert && (
        <div
          className="absolute bottom-16 left-1/2 z-50 -translate-x-1/2 flex items-center gap-3 rounded-lg border px-4 py-3 text-sm shadow-xl"
          style={{
            background: "rgba(10,18,32,0.95)",
            borderColor: "rgba(251,191,36,0.45)",
            color: "rgba(226,232,240,0.9)",
            backdropFilter: "blur(8px)",
            minWidth: 320,
          }}
        >
          <span style={{ color: "#FBBF24" }}>⚠</span>
          <span className="flex-1">
            <strong>{haloEscapeAlert.nodeLabel}</strong> left group{" "}
            <strong>{haloEscapeAlert.groupLabel}</strong>
          </span>
          <button
            className="rounded px-2 py-1 text-xs font-medium hover:bg-white/10"
            style={{ color: "#60A5FA" }}
            onClick={() => {
              setPosition(haloEscapeAlert.nodeId, haloEscapeAlert.prevPosition.x, haloEscapeAlert.prevPosition.y);
              setHaloEscapeAlert(null);
            }}
          >
            Undo
          </button>
          <button
            className="rounded px-2 py-1 text-xs font-medium hover:bg-white/10"
            style={{ color: "rgba(148,163,184,0.6)" }}
            onClick={() => setHaloEscapeAlert(null)}
          >
            OK
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
            onNodeClick(contextMenu.nodeId, contextMenu.nodeType === "group" ? "group" : "node");
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
                  void navigator.clipboard.writeText(contextNode!.ip!);
                  setContextMenu(null);
                }
              : undefined
          }
        />
      )}
    </div>
  );
}

export default memo(TopologyCanvas);
