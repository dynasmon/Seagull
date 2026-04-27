import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Button } from "@/shared/components/Button";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { JsonBlock } from "@/shared/components/JsonBlock";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";
import { TextInput } from "@/shared/components/TextInput";
import { cx } from "@/shared/lib/cx";

import { computeGraphLayout, type LayoutEdge, type LayoutNode } from "../graphLayout";
import { ExposureGraph, ExposureGraphNode } from "../types";
import {
  exposureEdgeLabel,
  exposureNodeLabel,
  exposureSeverityVariant,
  exposureStatusVariant,
  formatExposureConfidence,
  formatExposureScore,
  formatExposureTimestamp,
  sanitizeEvidenceMetadata,
} from "../utils";
import { ExposureEvidenceList } from "./ExposureEvidenceList";

type Props = {
  graph: ExposureGraph;
  onNodeClick?: (node: ExposureGraphNode) => void;
};

type GraphTransform = {
  scale: number;
  offsetX: number;
  offsetY: number;
};

type SelectedGraphItem =
  | { kind: "node"; key: string }
  | { kind: "edge"; key: string }
  | null;

type ThemePalette = {
  background: string;
  border: string;
  muted: string;
  foreground: string;
  primary: string;
  info: string;
  warning: string;
  danger: string;
  success: string;
};

const GRAPH_MIN_HEIGHT = 560;
const GRAPH_PADDING = 72;
const MIN_SCALE = 0.35;
const MAX_SCALE = 2.6;

const NODE_COLOR_TOKEN: Record<string, keyof ThemePalette> = {
  asset: "primary",
  service: "info",
  package: "warning",
  cve: "danger",
  ip: "info",
  protocol: "info",
  process: "warning",
  file: "success",
  alert: "danger",
  attack_chain_case: "danger",
  attack_chain_step: "danger",
  investigation: "primary",
  response_action: "success",
  identity: "primary",
};

const EDGE_COLOR_TOKEN: Record<string, keyof ThemePalette> = {
  has_cve: "danger",
  has_package: "warning",
  has_service: "info",
  communicates_with: "info",
  executed_process: "warning",
  modified_file: "success",
  triggered_alert: "danger",
  part_of_attack_chain: "danger",
  part_of_investigation: "primary",
  triggered_response_action: "success",
  lateral_movement_to: "danger",
  exploited_by: "danger",
};

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function readThemeColor(variable: string, fallback: string): string {
  if (typeof window === "undefined") return fallback;
  const raw = window.getComputedStyle(document.documentElement).getPropertyValue(variable).trim();
  return raw ? `rgb(${raw})` : fallback;
}

function rgba(rgb: string, alpha: number): string {
  const match = rgb.match(/\d+/g);
  if (!match || match.length < 3) return rgb;
  return `rgba(${match[0]}, ${match[1]}, ${match[2]}, ${alpha})`;
}

function distanceToSegment(
  pointX: number,
  pointY: number,
  edge: LayoutEdge,
): number {
  const x1 = edge.x1;
  const y1 = edge.y1;
  const x2 = edge.x2;
  const y2 = edge.y2;
  const dx = x2 - x1;
  const dy = y2 - y1;
  const lenSq = dx * dx + dy * dy;
  if (lenSq === 0) return Math.hypot(pointX - x1, pointY - y1);
  const t = clamp(((pointX - x1) * dx + (pointY - y1) * dy) / lenSq, 0, 1);
  const projX = x1 + t * dx;
  const projY = y1 + t * dy;
  return Math.hypot(pointX - projX, pointY - projY);
}

function useThemePalette(): ThemePalette {
  const [palette, setPalette] = useState<ThemePalette>(() => ({
    background: "rgb(248, 250, 253)",
    border: "rgb(220, 229, 239)",
    muted: "rgb(106, 138, 170)",
    foreground: "rgb(26, 58, 95)",
    primary: "rgb(14, 165, 233)",
    info: "rgb(59, 130, 246)",
    warning: "rgb(245, 158, 11)",
    danger: "rgb(239, 68, 68)",
    success: "rgb(16, 185, 129)",
  }));

  useEffect(() => {
    const update = () =>
      setPalette({
        background: readThemeColor("--card", "rgb(248, 250, 253)"),
        border: readThemeColor("--border", "rgb(220, 229, 239)"),
        muted: readThemeColor("--muted-foreground", "rgb(106, 138, 170)"),
        foreground: readThemeColor("--foreground", "rgb(26, 58, 95)"),
        primary: readThemeColor("--primary", "rgb(14, 165, 233)"),
        info: readThemeColor("--info", "rgb(59, 130, 246)"),
        warning: readThemeColor("--warning", "rgb(245, 158, 11)"),
        danger: readThemeColor("--danger", "rgb(239, 68, 68)"),
        success: readThemeColor("--success", "rgb(16, 185, 129)"),
      });
    update();
    if (typeof MutationObserver === "undefined") return;
    const observer = new MutationObserver(update);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => observer.disconnect();
  }, []);

  return palette;
}

function fitTransform(
  viewportWidth: number,
  viewportHeight: number,
  nodes: LayoutNode[],
): GraphTransform {
  if (nodes.length === 0) {
    return { scale: 1, offsetX: GRAPH_PADDING, offsetY: GRAPH_PADDING };
  }
  const minX = Math.min(...nodes.map((node) => node.x - node.radius)) - GRAPH_PADDING;
  const maxX = Math.max(...nodes.map((node) => node.x + node.radius)) + GRAPH_PADDING;
  const minY = Math.min(...nodes.map((node) => node.y - node.radius)) - GRAPH_PADDING;
  const maxY = Math.max(...nodes.map((node) => node.y + node.radius)) + GRAPH_PADDING;
  const graphWidth = Math.max(1, maxX - minX);
  const graphHeight = Math.max(1, maxY - minY);
  const scale = clamp(
    Math.min(viewportWidth / graphWidth, viewportHeight / graphHeight),
    MIN_SCALE,
    MAX_SCALE,
  );
  return {
    scale,
    offsetX: (viewportWidth - graphWidth * scale) / 2 - minX * scale,
    offsetY: (viewportHeight - graphHeight * scale) / 2 - minY * scale,
  };
}

function centerOnNode(
  transform: GraphTransform,
  node: LayoutNode,
  viewportWidth: number,
  viewportHeight: number,
): GraphTransform {
  const nextScale = clamp(Math.max(transform.scale, 1.1), MIN_SCALE, MAX_SCALE);
  return {
    scale: nextScale,
    offsetX: viewportWidth / 2 - node.x * nextScale,
    offsetY: viewportHeight / 2 - node.y * nextScale,
  };
}

export function ExposureGraphCanvas({ graph, onNodeClick }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const theme = useThemePalette();

  const [viewport, setViewport] = useState({ width: 1200, height: GRAPH_MIN_HEIGHT });
  const [search, setSearch] = useState("");
  const [filterMatches, setFilterMatches] = useState(false);
  const [selected, setSelected] = useState<SelectedGraphItem>(null);
  const [transform, setTransform] = useState<GraphTransform>({
    scale: 1,
    offsetX: GRAPH_PADDING,
    offsetY: GRAPH_PADDING,
  });

  const dragStateRef = useRef<{
    pointerId: number;
    lastX: number;
    lastY: number;
    moved: boolean;
  } | null>(null);

  useEffect(() => {
    const element = containerRef.current;
    if (!element) return;
    const observer = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (!rect) return;
      setViewport((prev) => ({
        width: Math.max(320, Math.round(rect.width)),
        height: prev.height,
      }));
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const layout = useMemo(
    () => computeGraphLayout(graph.root_node_key, graph.nodes, graph.edges, viewport.width),
    [graph.edges, graph.nodes, graph.root_node_key, viewport.width],
  );

  const nodeByKey = useMemo(
    () => new Map(layout.nodes.map((node) => [node.node_key, node])),
    [layout.nodes],
  );
  const edgeByKey = useMemo(
    () => new Map(layout.edges.map((edge) => [edge.edge_key, edge])),
    [layout.edges],
  );

  const matchingNodeKeys = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return new Set<string>();
    return new Set(
      layout.nodes
        .filter((node) => {
          const typeLabel = exposureNodeLabel(node.node_type).toLowerCase();
          return (
            node.label.toLowerCase().includes(needle) ||
            node.node_key.toLowerCase().includes(needle) ||
            typeLabel.includes(needle)
          );
        })
        .map((node) => node.node_key),
    );
  }, [layout.nodes, search]);

  const visibleNodeKeys = useMemo(() => {
    if (!filterMatches || matchingNodeKeys.size === 0) {
      return new Set(layout.nodes.map((node) => node.node_key));
    }
    const expanded = new Set<string>([graph.root_node_key, ...matchingNodeKeys]);
    for (const edge of layout.edges) {
      if (matchingNodeKeys.has(edge.source_node_key) || matchingNodeKeys.has(edge.target_node_key)) {
        expanded.add(edge.source_node_key);
        expanded.add(edge.target_node_key);
      }
    }
    return expanded;
  }, [filterMatches, graph.root_node_key, layout.edges, layout.nodes, matchingNodeKeys]);

  const visibleNodes = useMemo(
    () => layout.nodes.filter((node) => visibleNodeKeys.has(node.node_key)),
    [layout.nodes, visibleNodeKeys],
  );
  const visibleEdges = useMemo(
    () =>
      layout.edges.filter(
        (edge) =>
          visibleNodeKeys.has(edge.source_node_key) &&
          visibleNodeKeys.has(edge.target_node_key),
      ),
    [layout.edges, visibleNodeKeys],
  );

  useEffect(() => {
    const selectedNode = selected?.kind === "node" ? nodeByKey.get(selected.key) : null;
    const selectedEdge = selected?.kind === "edge" ? edgeByKey.get(selected.key) : null;
    if (selectedNode || selectedEdge) return;
    setSelected({ kind: "node", key: graph.root_node_key });
  }, [edgeByKey, graph.root_node_key, nodeByKey, selected]);

  useEffect(() => {
    setTransform(fitTransform(viewport.width, viewport.height, visibleNodes));
  }, [graph.root_node_key, viewport.height, viewport.width, visibleNodes]);

  const selectedNode = selected?.kind === "node" ? nodeByKey.get(selected.key) ?? null : null;
  const selectedEdge = selected?.kind === "edge" ? edgeByKey.get(selected.key) ?? null : null;

  const selectNode = useCallback((nodeKey: string) => {
    setSelected({ kind: "node", key: nodeKey });
  }, []);

  const selectEdge = useCallback((edgeKey: string) => {
    setSelected({ kind: "edge", key: edgeKey });
  }, []);

  const focusSelected = useCallback(() => {
    const node = selectedNode ?? (selectedEdge ? nodeByKey.get(selectedEdge.target_node_key) : null);
    if (!node) return;
    setTransform((prev) => centerOnNode(prev, node, viewport.width, viewport.height));
  }, [nodeByKey, selectedEdge, selectedNode, viewport.height, viewport.width]);

  const fitGraph = useCallback(() => {
    setTransform(fitTransform(viewport.width, viewport.height, visibleNodes));
  }, [viewport.height, viewport.width, visibleNodes]);

  const zoom = useCallback((factor: number) => {
    setTransform((prev) => {
      const nextScale = clamp(prev.scale * factor, MIN_SCALE, MAX_SCALE);
      const centerX = viewport.width / 2;
      const centerY = viewport.height / 2;
      const worldX = (centerX - prev.offsetX) / prev.scale;
      const worldY = (centerY - prev.offsetY) / prev.scale;
      return {
        scale: nextScale,
        offsetX: centerX - worldX * nextScale,
        offsetY: centerY - worldY * nextScale,
      };
    });
  }, [viewport.height, viewport.width]);

  const screenToWorld = useCallback(
    (clientX: number, clientY: number) => {
      const rect = canvasRef.current?.getBoundingClientRect();
      if (!rect) return null;
      const localX = clientX - rect.left;
      const localY = clientY - rect.top;
      return {
        x: (localX - transform.offsetX) / transform.scale,
        y: (localY - transform.offsetY) / transform.scale,
      };
    },
    [transform.offsetX, transform.offsetY, transform.scale],
  );

  const pickGraphItem = useCallback(
    (clientX: number, clientY: number): SelectedGraphItem => {
      const point = screenToWorld(clientX, clientY);
      if (!point) return null;

      for (const node of [...visibleNodes].sort((a, b) => b.risk_score - a.risk_score)) {
        const radius = node.radius + (node.node_key === graph.root_node_key ? 10 : 6);
        if (Math.hypot(point.x - node.x, point.y - node.y) <= radius) {
          return { kind: "node", key: node.node_key };
        }
      }

      let closestEdge: LayoutEdge | null = null;
      let closestDistance = Number.POSITIVE_INFINITY;
      for (const edge of visibleEdges) {
        const distance = distanceToSegment(point.x, point.y, edge);
        if (distance < closestDistance) {
          closestDistance = distance;
          closestEdge = edge;
        }
      }
      if (closestEdge && closestDistance <= 8 / transform.scale) {
        return { kind: "edge", key: closestEdge.edge_key };
      }
      return null;
    },
    [graph.root_node_key, screenToWorld, transform.scale, visibleEdges, visibleNodes],
  );

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const devicePixelRatio = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    canvas.width = Math.round(viewport.width * devicePixelRatio);
    canvas.height = Math.round(viewport.height * devicePixelRatio);
    canvas.style.width = `${viewport.width}px`;
    canvas.style.height = `${viewport.height}px`;

    const context = canvas.getContext("2d");
    if (!context) return;

    context.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
    context.clearRect(0, 0, viewport.width, viewport.height);
    context.fillStyle = rgba(theme.background, 0.35);
    context.fillRect(0, 0, viewport.width, viewport.height);

    context.save();
    context.translate(transform.offsetX, transform.offsetY);
    context.scale(transform.scale, transform.scale);

    const connectedKeys = new Set<string>();
    if (selectedNode) {
      connectedKeys.add(selectedNode.node_key);
      for (const edge of visibleEdges) {
        if (edge.source_node_key === selectedNode.node_key || edge.target_node_key === selectedNode.node_key) {
          connectedKeys.add(edge.source_node_key);
          connectedKeys.add(edge.target_node_key);
        }
      }
    }

    const showAllEdgeLabels = visibleEdges.length <= 36;

    for (const edge of visibleEdges) {
      const isSelected = selectedEdge?.edge_key === edge.edge_key;
      const selectedNodeKey = selectedNode?.node_key;
      const isConnected =
        Boolean(selectedNodeKey) &&
        (edge.source_node_key === selectedNodeKey || edge.target_node_key === selectedNodeKey);
      const token = EDGE_COLOR_TOKEN[edge.edge_type] || "muted";
      const color = theme[token] || theme.muted;

      context.strokeStyle = isSelected
        ? rgba(color, 0.95)
        : isConnected
          ? rgba(color, 0.78)
          : rgba(color, 0.34);
      context.lineWidth = isSelected ? 2.8 : isConnected ? 2.1 : 1.2 + Math.min(1.4, edge.weight * 0.35);
      context.beginPath();
      context.moveTo(edge.x1, edge.y1);
      context.lineTo(edge.x2, edge.y2);
      context.stroke();

      const angle = Math.atan2(edge.y2 - edge.y1, edge.x2 - edge.x1);
      const arrowX = edge.x2 - Math.cos(angle) * 18;
      const arrowY = edge.y2 - Math.sin(angle) * 18;
      context.fillStyle = context.strokeStyle;
      context.beginPath();
      context.moveTo(arrowX, arrowY);
      context.lineTo(
        arrowX - Math.cos(angle - Math.PI / 6) * 8,
        arrowY - Math.sin(angle - Math.PI / 6) * 8,
      );
      context.lineTo(
        arrowX - Math.cos(angle + Math.PI / 6) * 8,
        arrowY - Math.sin(angle + Math.PI / 6) * 8,
      );
      context.closePath();
      context.fill();

      if (showAllEdgeLabels || isSelected || isConnected) {
        const label = exposureEdgeLabel(edge.edge_type);
        const midX = (edge.x1 + edge.x2) / 2;
        const midY = (edge.y1 + edge.y2) / 2;
        context.font = "11px Inter, sans-serif";
        const metrics = context.measureText(label);
        const width = metrics.width + 10;
        const height = 18;
        context.fillStyle = rgba(theme.background, 0.92);
        context.strokeStyle = rgba(theme.border, 0.85);
        context.lineWidth = 1;
        context.beginPath();
        context.roundRect(midX - width / 2, midY - height / 2, width, height, 4);
        context.fill();
        context.stroke();
        context.fillStyle = theme.foreground;
        context.textAlign = "center";
        context.textBaseline = "middle";
        context.fillText(label, midX, midY + 0.5);
      }
    }

    for (const node of visibleNodes) {
      const token = NODE_COLOR_TOKEN[node.node_type] || "muted";
      const color = theme[token] || theme.muted;
      const isRoot = node.node_key === graph.root_node_key;
      const isSelected = selectedNode?.node_key === node.node_key;
      const isRecommended = graph.recommended_focus_node_keys.includes(node.node_key);
      const isSearchMatch = matchingNodeKeys.has(node.node_key);
      const riskBump = Math.min(8, Math.round(node.risk_score / 18));
      const radius = node.radius + riskBump + (isRoot ? 8 : 0);

      if (isRoot || isSelected || isRecommended) {
        context.strokeStyle = isSelected ? rgba(color, 0.95) : rgba(color, 0.5);
        context.lineWidth = isSelected ? 3 : 2;
        context.beginPath();
        context.arc(node.x, node.y, radius + 8, 0, Math.PI * 2);
        context.stroke();
      }

      context.fillStyle = rgba(color, isSearchMatch ? 0.28 : 0.18);
      context.strokeStyle = isSelected ? rgba(color, 0.95) : rgba(color, isRoot ? 0.88 : 0.72);
      context.lineWidth = isSelected ? 3 : isRoot ? 2.4 : 1.8;
      context.beginPath();
      context.arc(node.x, node.y, radius, 0, Math.PI * 2);
      context.fill();
      context.stroke();

      context.fillStyle = theme.foreground;
      context.textAlign = "center";
      context.textBaseline = "middle";
      context.font = `${isRoot ? 12 : 11}px Inter, sans-serif`;
      const label = node.label.length > 22 ? `${node.label.slice(0, 21)}…` : node.label;
      context.fillText(label, node.x, node.y - 3);

      context.fillStyle = rgba(theme.muted, 0.95);
      context.font = "10px IBM Plex Mono, monospace";
      context.fillText(
        `${exposureNodeLabel(node.node_type)} · ${formatExposureScore(node.risk_score)} · ${formatExposureConfidence(node.confidence)}`,
        node.x,
        node.y + 13,
      );
    }

    context.restore();
  }, [
    graph.recommended_focus_node_keys,
    graph.root_node_key,
    matchingNodeKeys,
    selectedEdge,
    selectedNode,
    theme,
    transform.offsetX,
    transform.offsetY,
    transform.scale,
    viewport.height,
    viewport.width,
    visibleEdges,
    visibleNodes,
  ]);

  const selectedNodeProperties = useMemo(() => {
    if (!selectedNode) return null;
    const properties = sanitizeEvidenceMetadata(selectedNode.properties);
    if (!properties || typeof properties !== "object") return null;
    return properties;
  }, [selectedNode]);

  const selectedEdgeProperties = useMemo(() => {
    if (!selectedEdge) return null;
    const properties = sanitizeEvidenceMetadata(selectedEdge.properties);
    if (!properties || typeof properties !== "object") return null;
    return properties;
  }, [selectedEdge]);

  const onPointerDown = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    dragStateRef.current = {
      pointerId: event.pointerId,
      lastX: event.clientX,
      lastY: event.clientY,
      moved: false,
    };
    event.currentTarget.setPointerCapture(event.pointerId);
  }, []);

  const onPointerMove = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    const drag = dragStateRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    const deltaX = event.clientX - drag.lastX;
    const deltaY = event.clientY - drag.lastY;
    if (Math.abs(deltaX) > 1 || Math.abs(deltaY) > 1) {
      drag.moved = true;
      setTransform((prev) => ({
        ...prev,
        offsetX: prev.offsetX + deltaX,
        offsetY: prev.offsetY + deltaY,
      }));
      drag.lastX = event.clientX;
      drag.lastY = event.clientY;
    }
  }, []);

  const completePointer = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    const drag = dragStateRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    event.currentTarget.releasePointerCapture(event.pointerId);
    dragStateRef.current = null;
    if (drag.moved) return;
    const hit = pickGraphItem(event.clientX, event.clientY);
    if (!hit) {
      setSelected(null);
      return;
    }
    if (hit.kind === "node") selectNode(hit.key);
    if (hit.kind === "edge") selectEdge(hit.key);
  }, [pickGraphItem, selectEdge, selectNode]);

  const onWheel = useCallback(
    (event: React.WheelEvent<HTMLCanvasElement>) => {
      event.preventDefault();
      const rect = canvasRef.current?.getBoundingClientRect();
      if (!rect) return;
      const localX = event.clientX - rect.left;
      const localY = event.clientY - rect.top;
      const factor = event.deltaY > 0 ? 0.92 : 1.08;
      setTransform((prev) => {
        const nextScale = clamp(prev.scale * factor, MIN_SCALE, MAX_SCALE);
        const worldX = (localX - prev.offsetX) / prev.scale;
        const worldY = (localY - prev.offsetY) / prev.scale;
        return {
          scale: nextScale,
          offsetX: localX - worldX * nextScale,
          offsetY: localY - worldY * nextScale,
        };
      });
    },
    [],
  );

  const matchList = useMemo(
    () =>
      layout.nodes
        .filter((node) => matchingNodeKeys.has(node.node_key))
        .sort((a, b) => b.risk_score - a.risk_score || b.confidence - a.confidence)
        .slice(0, 12),
    [layout.nodes, matchingNodeKeys],
  );

  if (graph.nodes.length === 0) {
    return (
      <EmptyState
        title="No graph relationships"
        description="The selected asset does not currently have graphable exposure nodes or edges above the backend confidence threshold."
      />
    );
  }

  return (
    <div className="space-y-4">
      {(graph.graph_health.nodes_truncated || graph.graph_health.edges_truncated) ? (
        <InlineAlert tone="warning">
          Graph bounds applied by backend: {graph.graph_health.node_count} nodes / {graph.graph_health.max_nodes_applied} max,{" "}
          {graph.graph_health.edge_count} edges / {graph.graph_health.max_edges_applied} max. Narrow scope or increase backend limits to inspect more relationships.
        </InlineAlert>
      ) : null}

      {(graph.graph_health.stale_agent || graph.graph_health.stale_inventory) ? (
        <InlineAlert tone="info">
          {graph.graph_health.stale_agent ? "Agent telemetry is stale for this graph. " : ""}
          {graph.graph_health.stale_inventory ? "Inventory evidence is stale for this graph." : ""}
        </InlineAlert>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr),320px]">
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <TextInput
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search graph nodes"
              className="h-8 min-w-[240px] font-mono text-xs"
            />
            <label className="inline-flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              <input
                type="checkbox"
                checked={filterMatches}
                onChange={(event) => setFilterMatches(event.target.checked)}
                className="h-3.5 w-3.5 accent-primary"
              />
              Filter matches
            </label>
            <Button variant="ghost" size="sm" onClick={fitGraph}>
              Fit graph
            </Button>
            <Button variant="ghost" size="sm" onClick={focusSelected} disabled={!selectedNode && !selectedEdge}>
              Focus selected
            </Button>
            <Button variant="ghost" size="sm" onClick={() => zoom(1.12)}>
              Zoom in
            </Button>
            <Button variant="ghost" size="sm" onClick={() => zoom(0.88)}>
              Zoom out
            </Button>
            <span className="ml-auto text-[11px] font-mono text-muted-foreground">
              {visibleNodes.length} visible nodes · {visibleEdges.length} visible edges
            </span>
          </div>

          {search.trim() && matchingNodeKeys.size === 0 ? (
            <EmptyState
              title="No matching nodes"
              description="Try a different hostname, node type, or risk artifact label."
            />
          ) : (
            <div
              ref={containerRef}
              className="relative overflow-hidden rounded-lg border border-border/60 bg-background/35"
              style={{ minHeight: GRAPH_MIN_HEIGHT }}
            >
              <canvas
                ref={canvasRef}
                width={viewport.width}
                height={viewport.height}
                className={cx("block w-full touch-none", filterMatches && matchingNodeKeys.size > 0 ? "cursor-grab" : "cursor-default")}
                aria-label="Exposure attack graph"
                onPointerDown={onPointerDown}
                onPointerMove={onPointerMove}
                onPointerUp={completePointer}
                onPointerCancel={completePointer}
                onDoubleClick={() => {
                  if (selectedNode) onNodeClick?.(selectedNode);
                }}
                onWheel={onWheel}
              />
            </div>
          )}

          {matchList.length > 0 ? (
            <div className="rounded-lg border border-border/60 bg-background/30 p-3">
              <div className="mb-2 text-[10px] font-mono uppercase tracking-[0.16em] text-muted-foreground">
                Search results
              </div>
              <div className="flex flex-wrap gap-2">
                {matchList.map((node) => (
                  <button
                    key={node.node_key}
                    type="button"
                    className="rounded-md border border-border/60 bg-background/35 px-2.5 py-1.5 text-left text-[11px] hover:bg-muted/20"
                    onClick={() => {
                      selectNode(node.node_key);
                      setTransform((prev) => centerOnNode(prev, node, viewport.width, viewport.height));
                    }}
                  >
                    <div className="font-medium text-foreground">{node.label}</div>
                    <div className="mt-0.5 font-mono text-muted-foreground">
                      {exposureNodeLabel(node.node_type)} · {formatExposureScore(node.risk_score)} · {formatExposureConfidence(node.confidence)}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          ) : null}
        </div>

        <div className="space-y-3">
          <div className="rounded-lg border border-border/60 bg-background/30 p-4">
            <div className="mb-3 text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground">
              Selection
            </div>
            {!selectedNode && !selectedEdge ? (
              <p className="text-sm text-muted-foreground">Select a node or edge to inspect risk, confidence, evidence, and linked context.</p>
            ) : null}

            {selectedNode ? (
              <div className="space-y-3">
                <div>
                  <div className="text-sm font-semibold text-foreground">{selectedNode.label}</div>
                  <div className="mt-1 font-mono text-[11px] text-muted-foreground">{selectedNode.node_key}</div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <SeverityPill variant={exposureSeverityVariant(selectedNode.severity)}>
                    {selectedNode.severity}
                  </SeverityPill>
                  <StatusPill variant={exposureStatusVariant(selectedNode.node_type === "asset" ? String(selectedNode.properties.status || "active") : "active")}>
                    {exposureNodeLabel(selectedNode.node_type)}
                  </StatusPill>
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="rounded-md border border-border/50 bg-background/35 px-2.5 py-2">
                    <div className="font-mono uppercase tracking-[0.12em] text-muted-foreground">Risk</div>
                    <div className="mt-1 text-sm font-semibold text-foreground">{formatExposureScore(selectedNode.risk_score)}</div>
                  </div>
                  <div className="rounded-md border border-border/50 bg-background/35 px-2.5 py-2">
                    <div className="font-mono uppercase tracking-[0.12em] text-muted-foreground">Confidence</div>
                    <div className="mt-1 text-sm font-semibold text-foreground">{formatExposureConfidence(selectedNode.confidence)}</div>
                  </div>
                </div>
                <div className="space-y-1 text-[11px] text-muted-foreground">
                  <div>Asset: <span className="font-mono text-foreground">{selectedNode.asset_key || "-"}</span></div>
                  <div>Agent: <span className="font-mono text-foreground">{selectedNode.agent_id || "-"}</span></div>
                  <div>Last seen: <span className="font-mono text-foreground">{formatExposureTimestamp(selectedNode.last_seen_at)}</span></div>
                  <div>Updated: <span className="font-mono text-foreground">{formatExposureTimestamp(selectedNode.updated_at)}</span></div>
                </div>
                {onNodeClick && selectedNode.asset_key ? (
                  <Button variant="secondary" size="sm" onClick={() => onNodeClick(selectedNode)}>
                    Open asset drawer
                  </Button>
                ) : null}
                {selectedNode.source_refs.length > 0 ? (
                  <div className="border-t border-border/50 pt-3">
                    <div className="mb-2 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
                      Source evidence
                    </div>
                    <ExposureEvidenceList refs={selectedNode.source_refs} compact />
                  </div>
                ) : null}
                {selectedNodeProperties ? (
                  <div className="border-t border-border/50 pt-3">
                    <div className="mb-2 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
                      Properties
                    </div>
                    <JsonBlock value={selectedNodeProperties} maxHeight="220px" showControls={false} />
                  </div>
                ) : null}
              </div>
            ) : null}

            {selectedEdge ? (
              <div className="space-y-3">
                <div>
                  <div className="text-sm font-semibold text-foreground">{exposureEdgeLabel(selectedEdge.edge_type)}</div>
                  <div className="mt-1 font-mono text-[11px] text-muted-foreground">{selectedEdge.edge_key}</div>
                </div>
                <div className="space-y-1 text-[11px] text-muted-foreground">
                  <div>From: <span className="font-mono text-foreground">{selectedEdge.source_node_key}</span></div>
                  <div>To: <span className="font-mono text-foreground">{selectedEdge.target_node_key}</span></div>
                  <div>Confidence: <span className="font-mono text-foreground">{formatExposureConfidence(selectedEdge.confidence)}</span></div>
                  <div>Weight: <span className="font-mono text-foreground">{selectedEdge.weight.toFixed(2)}</span></div>
                  <div>Updated: <span className="font-mono text-foreground">{formatExposureTimestamp(selectedEdge.updated_at)}</span></div>
                </div>
                {selectedEdge.evidence_refs.length > 0 ? (
                  <div className="border-t border-border/50 pt-3">
                    <div className="mb-2 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
                      Evidence
                    </div>
                    <ExposureEvidenceList refs={selectedEdge.evidence_refs} compact />
                  </div>
                ) : null}
                {selectedEdgeProperties ? (
                  <div className="border-t border-border/50 pt-3">
                    <div className="mb-2 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
                      Properties
                    </div>
                    <JsonBlock value={selectedEdgeProperties} maxHeight="220px" showControls={false} />
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}
