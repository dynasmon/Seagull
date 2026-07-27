import "@xyflow/react/dist/style.css";

import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { OnNodeDrag } from "@xyflow/react";
import {
  Background,
  BackgroundVariant,
  type Edge,
  MiniMap,
  type Node,
  type NodeTypes,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";

import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import {
  ISOLATED_GHOST_NODE_ID,
  type ClusterHaloNodeData,
  type DeviceNodeData,
  type GroupNodeData,
  type TopologyBundleEdgeData,
  type TopologyEdgeData,
  type TopologyGroupEdgeData,
} from "../../lib/graph/graphTransform";
import { MEMBER_H, MEMBER_W } from "../../lib/layout/layoutContainment";
import { AGGREGATE_NODE_PREFIX, topologyNodeSetKey } from "../../lib/layout/topologyLayout";
import { buildAlertsPivotUrl, buildEventsPivotUrl } from "../../lib/details/pivots";
import { NODE_TYPE_LABELS, isExternalNode, riskAccent, severityColor } from "../../lib/presentation/visuals";
import { useTopologyPositions } from "../../hooks/useTopologyPositions";
import type {
  TopologyFilters,
  TopologyGraph,
  TopologyGroup,
  TopologyGroupEdge,
  TopologySummary,
  TopologyViewMode,
} from "../../types";
import TopologyCanvasControls from "./TopologyCanvasControls";
import TopologyClusterHaloNode from "../nodes/TopologyClusterHaloNode";
import { TopologyContextMenu, type TopologyContextAction } from "./TopologyContextMenu";
import TopologyDeviceNode from "../nodes/TopologyDeviceNode";
import { TopologyBundleEdge, TopologyFlowEdge } from "./TopologyEdge";
import TopologyGroupNode from "../nodes/TopologyGroupNode";
import TopologyLegend from "./TopologyLegend";
import TopologyStatusStrip from "./TopologyStatusStrip";
import TopologyTooltip, { type TooltipInfo } from "./TopologyTooltip";

const nodeTypes: NodeTypes = {
  device: TopologyDeviceNode as unknown as NodeTypes["string"],
  group: TopologyGroupNode as unknown as NodeTypes["string"],
  clusterHalo: TopologyClusterHaloNode as unknown as NodeTypes["string"],
};

const edgeTypes = {
  topology: TopologyFlowEdge,
  group: TopologyFlowEdge,
  bundle: TopologyBundleEdge,
};

const FIT_VIEW_OPTIONS = { padding: 0.12, maxZoom: 1.15, minZoom: 0.24 };

function isNodeInsideHalo(
  nodePos: { x: number; y: number },
  haloNode: Node,
  haloWidth: number,
  haloHeight: number,
): boolean {
  const centerX = nodePos.x + MEMBER_W / 2;
  const centerY = nodePos.y + MEMBER_H / 2;
  return (
    centerX >= haloNode.position.x &&
    centerX <= haloNode.position.x + haloWidth &&
    centerY >= haloNode.position.y &&
    centerY <= haloNode.position.y + haloHeight
  );
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
  multiSelection: Set<string>;
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
  onContextMenuRequest: (x: number, y: number, node: Node) => void;
  onHaloEscape: (nodeId: string, nodeLabel: string, groupLabel: string, prevPosition: { x: number; y: number }) => void;
  onIsolatedGhostClick: () => void;
  onExpandAggregate: (groupKey: string) => void;
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
  multiSelection,
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
  onExpandAggregate,
}: FlowInnerProps) {
  const { fitView } = useReactFlow();
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const prevKeyRef = useRef<string>("");
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;
  const prevNodePositionRef = useRef<{ x: number; y: number } | null>(null);

  const graphKey = useMemo(
    () => `${viewMode}:${initialNodes.map((n) => n.id).sort().join(",")}`,
    [viewMode, initialNodes],
  );

  useEffect(() => {
    if (graphKey !== prevKeyRef.current) {
      prevKeyRef.current = graphKey;
      void requestAnimationFrame(() => fitView({ ...FIT_VIEW_OPTIONS, duration: 400 }));
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
        fitView({ nodes: [{ id: activeMatchKey }], padding: 0.45, maxZoom: 1.3, duration: 350 }),
      );
    }
  }, [activeMatchKey, fitView]);

  const handleNodeDragStart: OnNodeDrag = useCallback((_event, node) => {
    prevNodePositionRef.current = { x: node.position.x, y: node.position.y };
  }, []);

  const handleNodeDragStop: OnNodeDrag = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      if (node.draggable === false) return;

      const nodeData = node.data as unknown as DeviceNodeData;
      if (node.type === "device" && nodeData.groupKey) {
        const haloNode = nodesRef.current.find((n) => n.id === `halo:${nodeData.groupKey}`);
        if (haloNode) {
          const haloData = haloNode.data as unknown as ClusterHaloNodeData;
          if (!isNodeInsideHalo(node.position, haloNode, haloData.width, haloData.height)) {
            const prevPos = prevNodePositionRef.current;
            if (prevPos) onHaloEscape(node.id, nodeData.node.label, haloData.group.label, prevPos);
          }
        }
      }

      onPositionSave(node.id, node.position.x, node.position.y);
    },
    [onPositionSave, onHaloEscape],
  );

  const handleResetLayout = useCallback(() => {
    onResetLayout();
    setNodes(initialNodes);
    void requestAnimationFrame(() => fitView({ ...FIT_VIEW_OPTIONS, duration: 400 }));
  }, [onResetLayout, setNodes, initialNodes, fitView]);

  const handleNodeClick = useCallback(
    (event: React.MouseEvent, node: Node) => {
      if (node.id === ISOLATED_GHOST_NODE_ID) {
        onIsolatedGhostClick();
        return;
      }
      if (node.id.startsWith(AGGREGATE_NODE_PREFIX)) {
        onExpandAggregate(node.id.slice(AGGREGATE_NODE_PREFIX.length));
        return;
      }
      if (event.shiftKey && node.type === "device") {
        onMultiSelectToggle(node.id);
        return;
      }
      onMultiSelectionClear();
      if (node.type === "clusterHalo") {
        onNodeClick(node.id.replace(/^halo:/, ""), "group");
        return;
      }
      onNodeClick(node.id, node.type === "group" ? "group" : "node");
    },
    [onMultiSelectToggle, onMultiSelectionClear, onNodeClick, onIsolatedGhostClick, onExpandAggregate],
  );

  const handleNodeDoubleClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (node.type === "group") onGroupDoubleClick(node.id);
      if (node.type === "clusterHalo") onGroupDoubleClick(node.id.replace(/^halo:/, ""));
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
      onContextMenuRequest(event.clientX, event.clientY, node);
    },
    [onContextMenuRequest],
  );

  const handleNodeMouseEnter = useCallback(
    (event: React.MouseEvent, node: Node) => {
      if (node.id === ISOLATED_GHOST_NODE_ID || node.id.startsWith(AGGREGATE_NODE_PREFIX)) return;
      if (node.type === "device") {
        const data = node.data as unknown as DeviceNodeData;
        onTooltipChange({
          kind: "node",
          node: data.node,
          isAgentAsset: data.isAgentAsset,
          x: event.clientX,
          y: event.clientY,
        });
      } else if (node.type === "group") {
        const data = node.data as unknown as GroupNodeData;
        onTooltipChange({ kind: "group", group: data.group, x: event.clientX, y: event.clientY });
      } else if (node.type === "clusterHalo") {
        const data = node.data as unknown as ClusterHaloNodeData;
        onTooltipChange({ kind: "group", group: data.group, x: event.clientX, y: event.clientY });
      }
    },
    [onTooltipChange],
  );

  const handleNodeMouseLeave = useCallback(() => onTooltipChange(null), [onTooltipChange]);

  const handleEdgeMouseEnter = useCallback(
    (event: React.MouseEvent, edge: Edge) => {
      const data = edge.data as Record<string, unknown> | undefined;
      if (!data) return;

      const labelOf = (id: string) => {
        const node = nodes.find((n) => n.id === id);
        if (node?.type === "device") return (node.data as unknown as DeviceNodeData).node.label;
        if (node?.type === "group") return (node.data as unknown as GroupNodeData).group.label;
        return id;
      };

      if ("bundle" in data) {
        const bundleData = data as unknown as TopologyBundleEdgeData;
        onTooltipChange({
          kind: "bundle",
          bundle: bundleData.bundle,
          isExpanded: false,
          x: event.clientX,
          y: event.clientY,
        });
        return;
      }
      if ("groupEdge" in data) {
        onTooltipChange({
          kind: "groupEdge",
          groupEdge: (data as unknown as TopologyGroupEdgeData).groupEdge,
          sourceLabel: labelOf(edge.source),
          targetLabel: labelOf(edge.target),
          x: event.clientX,
          y: event.clientY,
        });
        return;
      }
      if (!("edge" in data)) return;

      const edgeData = data as TopologyEdgeData;
      onTooltipChange({
        kind: "edge",
        edge: edgeData.edge,
        sourceLabel: labelOf(edge.source),
        targetLabel: labelOf(edge.target),
        isBidirectional: Boolean(edgeData.isBidirectional),
        x: event.clientX,
        y: event.clientY,
      });
    },
    [nodes, onTooltipChange],
  );

  const handleEdgeMouseLeave = useCallback(() => onTooltipChange(null), [onTooltipChange]);

  const decoratedNodes = useMemo(() => {
    if (multiSelection.size === 0) return nodes;
    return nodes.map((node) =>
      multiSelection.has(node.id)
        ? { ...node, style: { ...node.style, outline: "1.5px solid #22D3EE", outlineOffset: 2, borderRadius: 10 } }
        : node,
    );
  }, [nodes, multiSelection]);

  const miniMapNodeColor = useCallback((node: Node) => {
    if (node.type === "device") {
      const data = node.data as unknown as DeviceNodeData;
      const accent = riskAccent(data.node);
      if (accent) return accent;
      if (data.node.is_stale) return "#475569";
      return isExternalNode(data.node) ? "#64748B" : "#4ADE80";
    }
    if (node.type === "group") {
      const data = node.data as unknown as GroupNodeData;
      return data.group.alert_count > 0 ? severityColor(data.group.highest_severity) : "#22D3EE";
    }
    return "rgba(148,163,184,0.18)";
  }, []);

  return (
    <ReactFlow
      nodes={decoratedNodes}
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
      fitViewOptions={FIT_VIEW_OPTIONS}
      minZoom={0.12}
      maxZoom={3}
      nodesDraggable
      nodesConnectable={false}
      proOptions={{ hideAttribution: true }}
    >
      <Background variant={BackgroundVariant.Dots} gap={28} size={1} color="rgba(148,163,184,0.06)" style={{ background: "transparent" }} />

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
        onFitView={() => fitView({ ...FIT_VIEW_OPTIONS, duration: 320 })}
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
          nodeStrokeColor={() => "transparent"}
          maskColor="rgba(7,17,31,0.72)"
          style={{
            background: "rgba(7,17,31,0.94)",
            border: "1px solid rgba(148,163,184,0.14)",
            borderRadius: 8,
            marginBottom: 72,
            marginRight: 14,
            width: 168,
            height: 112,
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
  searchMatchTotal: number;
  searchMatchIndex: number;
  focusedGroupLabel?: string | null;
  realtimeStatus: string;
  isRefreshing: boolean;
  isolatedCount: number;
  showIsolated: boolean;
  activeEdgeTypes: string[];
  onEdgeTypeToggle: (edgeType: string) => void;
  onEdgeTypeReset: () => void;
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
  searchMatchTotal,
  searchMatchIndex,
  focusedGroupLabel,
  realtimeStatus,
  isRefreshing,
  isolatedCount,
  showIsolated,
  activeEdgeTypes,
  onEdgeTypeToggle,
  onEdgeTypeReset,
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
  const [toast, setToast] = useState<string | null>(null);
  const [haloEscapeAlert, setHaloEscapeAlert] = useState<{
    nodeId: string;
    nodeLabel: string;
    groupLabel: string;
    prevPosition: { x: number; y: number };
  } | null>(null);
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    title: string;
    subtitle: string | null;
    actions: TopologyContextAction[];
  } | null>(null);
  const [multiSelection, setMultiSelection] = useState<Set<string>>(new Set());

  const topologyKey = useMemo(() => topologyNodeSetKey(graph), [graph]);
  const { positions: storedPositions, setPosition, resetPositions, hasCustomPositions } =
    useTopologyPositions(viewMode, topologyKey);

  const mergedNodes = useMemo(
    () =>
      nodes.map((node) => {
        const position = storedPositions[node.id];
        return position ? { ...node, position } : node;
      }),
    [nodes, storedPositions],
  );

  const deviceNodes = useMemo(
    () => nodes.filter((node) => node.type === "device" && !node.id.startsWith(AGGREGATE_NODE_PREFIX) && node.id !== ISOLATED_GHOST_NODE_ID),
    [nodes],
  );

  const canvasStats = useMemo(() => {
    if (viewMode === "location") {
      const groupNodes = nodes.filter((node) => node.type === "group");
      return {
        primaryCount: groupNodes.length,
        alertNodeCount: groupNodes.filter((node) => (node.data as unknown as GroupNodeData).group.alert_count > 0).length,
        externalCount: groupNodes.reduce(
          (sum, node) => sum + Number((node.data as unknown as GroupNodeData).externalCount ?? 0),
          0,
        ),
      };
    }
    let alertNodeCount = 0;
    let externalCount = 0;
    for (const node of deviceNodes) {
      const data = node.data as unknown as DeviceNodeData;
      if (data.node.alert_count > 0) alertNodeCount += 1;
      if (isExternalNode(data.node)) externalCount += 1;
    }
    return { primaryCount: deviceNodes.length, alertNodeCount, externalCount };
  }, [nodes, deviceNodes, viewMode]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 2600);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const handleMultiSelectToggle = useCallback((id: string) => {
    setMultiSelection((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const handleMultiSelectionClear = useCallback(() => setMultiSelection(new Set()), []);

  const selectedIps = useMemo(() => {
    const byKey = new Map(
      deviceNodes.map((node) => [node.id, (node.data as unknown as DeviceNodeData).node]),
    );
    const ips: string[] = [];
    for (const key of multiSelection) {
      const ip = byKey.get(key)?.ip;
      if (ip && !ips.includes(ip)) ips.push(ip);
    }
    return ips;
  }, [multiSelection, deviceNodes]);

  const copyText = useCallback(async (value: string, message: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setToast(message);
    } catch {
      setToast("Clipboard unavailable in this browser");
    }
  }, []);

  const handleContextMenuRequest = useCallback(
    (x: number, y: number, node: Node) => {
      if (node.id === ISOLATED_GHOST_NODE_ID || node.id.startsWith(AGGREGATE_NODE_PREFIX)) return;

      if (node.type === "group" || node.type === "clusterHalo") {
        const data = node.data as unknown as GroupNodeData | ClusterHaloNodeData;
        const groupKey = node.type === "clusterHalo" ? node.id.replace(/^halo:/, "") : node.id;
        const actions: TopologyContextAction[] = [
          { key: "detail", label: "Open group detail", onSelect: () => onNodeClick(groupKey, "group") },
          { key: "focus", label: "Explore in Connection", onSelect: () => onGroupDoubleClick(groupKey) },
        ];
        if (data.group.cidr) {
          actions.push({
            key: "copy-cidr",
            label: "Copy CIDR",
            hint: data.group.cidr,
            onSelect: () => void copyText(data.group.cidr!, `Copied ${data.group.cidr}`),
          });
        }
        setContextMenu({
          x,
          y,
          title: data.group.label,
          subtitle: `${data.group.node_count} nodes`,
          actions,
        });
        return;
      }

      const data = node.data as unknown as DeviceNodeData;
      const topologyNode = data.node;
      const actions: TopologyContextAction[] = [
        { key: "detail", label: "Open node detail", onSelect: () => onNodeClick(node.id, "node") },
        {
          key: "events",
          label: "Open in Events",
          href: buildEventsPivotUrl({ ip: topologyNode.ip || topologyNode.cidr, agentId: topologyNode.agent_id, port: topologyNode.port }),
        },
        {
          key: "alerts",
          label: "Open in Alerts",
          href: buildAlertsPivotUrl({ ip: topologyNode.ip || topologyNode.cidr }),
        },
      ];
      if (topologyNode.ip) {
        actions.push({
          key: "copy-ip",
          label: "Copy IP",
          hint: topologyNode.ip,
          onSelect: () => void copyText(topologyNode.ip!, `Copied ${topologyNode.ip}`),
        });
      }
      actions.push({
        key: "search",
        label: "Highlight matching nodes",
        onSelect: () => onSearchChange(topologyNode.ip || topologyNode.label),
      });
      setContextMenu({
        x,
        y,
        title: topologyNode.label,
        subtitle: NODE_TYPE_LABELS[topologyNode.node_type] ?? topologyNode.node_type,
        actions,
      });
    },
    [copyText, onGroupDoubleClick, onNodeClick, onSearchChange],
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
      <div className="flex h-full items-center justify-center" style={{ background: "#07111f" }}>
        <div
          className="h-8 w-8 animate-spin rounded-full border-2"
          style={{ borderColor: "rgba(34,211,238,0.22)", borderTopColor: "#22D3EE" }}
          aria-label="Loading topology"
        />
      </div>
    );
  }

  if (isEmpty) {
    return (
      <div className="flex h-full items-center justify-center" style={{ background: "#07111f" }}>
        <EmptyState
          title="Nothing to map for these filters"
          description={
            viewMode === "location"
              ? "No groups matched. Widen the time window, lower the minimum confidence, or include stale nodes."
              : "No nodes matched. Widen the time window, lower the minimum confidence, or include stale nodes."
          }
        />
      </div>
    );
  }

  return (
    <div
      className={cx("relative h-full w-full overflow-hidden", isFullscreen && "fixed inset-0 z-50")}
      style={{
        backgroundColor: "#07111f",
        backgroundImage: [
          "radial-gradient(ellipse at 50% 34%, rgba(34,211,238,0.055), transparent 58%)",
          "repeating-linear-gradient(0deg, transparent 0, transparent 79px, rgba(148,163,184,0.012) 80px)",
          "repeating-linear-gradient(90deg, transparent 0, transparent 79px, rgba(148,163,184,0.012) 80px)",
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
          onToggleMinimap={() => setShowMinimap((prev) => !prev)}
          focusedGroupLabel={focusedGroupLabel}
          searchQuery={searchQuery}
          searchMatchIndex={searchMatchIndex}
          searchTotal={searchTotal}
          isFullscreen={isFullscreen}
          isRefreshing={isRefreshing}
          multiSelection={multiSelection}
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
          onExpandAggregate={onGroupDoubleClick}
        />
      </ReactFlowProvider>

      <TopologyLegend
        viewMode={viewMode}
        activeEdgeTypes={activeEdgeTypes}
        onEdgeTypeToggle={onEdgeTypeToggle}
        onEdgeTypeReset={onEdgeTypeReset}
      />

      <TopologyStatusStrip
        viewMode={viewMode}
        nodeCount={canvasStats.primaryCount}
        edgeCount={edges.length}
        groupCount={groups.length}
        alertNodeCount={canvasStats.alertNodeCount}
        externalCount={canvasStats.externalCount}
        hiddenCount={viewMode === "location" || showIsolated ? 0 : isolatedCount}
        onShowHidden={viewMode === "connection" && isolatedCount > 0 && !showIsolated ? onShowIsolated : undefined}
        filters={filters}
        searchQuery={searchQuery}
        searchTotal={searchTotal}
        searchMatchTotal={searchMatchTotal}
        focusedGroupLabel={focusedGroupLabel}
        graph={graph}
        summary={summary}
        realtimeStatus={realtimeStatus}
        isRefreshing={isRefreshing}
      />

      <TopologyTooltip info={tooltipInfo} />

      {multiSelection.size > 0 && (
        <div
          className="absolute bottom-16 left-1/2 z-40 flex -translate-x-1/2 items-center gap-2 rounded-lg border px-3 py-2 shadow-xl"
          style={{ background: "rgba(10,18,32,0.97)", borderColor: "rgba(34,211,238,0.28)", backdropFilter: "blur(8px)" }}
        >
          <span className="text-xs" style={{ color: "rgba(148,163,184,0.75)" }}>
            {multiSelection.size} selected · {selectedIps.length} with an IP
          </span>
          <div className="h-3 w-px" style={{ background: "rgba(148,163,184,0.18)" }} />
          <button
            type="button"
            className="rounded px-2 py-1 text-xs font-medium hover:bg-white/10 disabled:opacity-40"
            style={{ color: "#22D3EE" }}
            disabled={selectedIps.length === 0}
            onClick={() => void copyText(selectedIps.join("\n"), `Copied ${selectedIps.length} IPs`)}
          >
            Copy IPs
          </button>
          <a
            className={cx(
              "rounded px-2 py-1 text-xs font-medium hover:bg-white/10",
              selectedIps.length === 0 && "pointer-events-none opacity-40",
            )}
            style={{ color: "#22D3EE" }}
            href={buildAlertsPivotUrl({ search: selectedIps[0] ?? "" })}
          >
            View alerts
          </a>
          <button
            type="button"
            className="rounded px-2 py-1 text-xs hover:bg-white/5"
            style={{ color: "rgba(148,163,184,0.6)" }}
            onClick={() => setMultiSelection(new Set())}
            title="Clear selection"
          >
            ✕
          </button>
        </div>
      )}

      {toast && (
        <div
          className="absolute bottom-16 left-1/2 z-50 -translate-x-1/2 rounded-lg border px-3 py-2 text-xs shadow-xl"
          style={{
            background: "rgba(10,18,32,0.97)",
            borderColor: "rgba(34,211,238,0.3)",
            color: "rgba(226,232,240,0.92)",
          }}
          role="status"
        >
          {toast}
        </div>
      )}

      {haloEscapeAlert && (
        <div
          className="absolute bottom-16 left-1/2 z-50 flex -translate-x-1/2 items-center gap-3 rounded-lg border px-4 py-3 text-sm shadow-xl"
          style={{
            background: "rgba(10,18,32,0.96)",
            borderColor: "rgba(250,204,21,0.45)",
            color: "rgba(226,232,240,0.9)",
            backdropFilter: "blur(8px)",
            minWidth: 320,
          }}
        >
          <span style={{ color: "#FACC15" }}>⚠</span>
          <span className="flex-1">
            <strong>{haloEscapeAlert.nodeLabel}</strong> was dragged out of{" "}
            <strong>{haloEscapeAlert.groupLabel}</strong>
          </span>
          <button
            className="rounded px-2 py-1 text-xs font-medium hover:bg-white/10"
            style={{ color: "#22D3EE" }}
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
            Keep
          </button>
        </div>
      )}

      {contextMenu && (
        <TopologyContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          title={contextMenu.title}
          subtitle={contextMenu.subtitle}
          actions={contextMenu.actions}
          onClose={() => setContextMenu(null)}
        />
      )}
    </div>
  );
}

export default memo(TopologyCanvas);
