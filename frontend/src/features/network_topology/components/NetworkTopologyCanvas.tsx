import { useMemo } from "react";

import EmptyState from "@/shared/components/EmptyState";
import { Badge } from "@/shared/components/Badge";
import { cx } from "@/shared/lib/cx";

import { computeTopologyLayout } from "../lib/layout";
import { toTitleLabel, topologySeverityVariant } from "../lib/labels";
import type { TopologyEdge, TopologyGraph, TopologyNode } from "../types";

type Selection =
  | { kind: "node"; key: string }
  | { kind: "edge"; key: string }
  | null;

const nodeTone: Record<string, string> = {
  agent: "fill-primary/20 stroke-primary",
  host: "fill-success/15 stroke-success",
  interface: "fill-info/15 stroke-info",
  subnet: "fill-muted/45 stroke-muted-foreground",
  service: "fill-warning/15 stroke-warning",
  external_ip: "fill-danger/12 stroke-danger",
  gateway: "fill-warning/15 stroke-warning",
  docker_network: "fill-info/12 stroke-info",
  unknown: "fill-muted/35 stroke-border",
};

function edgeStroke(edge: TopologyEdge): string {
  const type = String(edge.edge_type || "");
  if (type === "alert_related" || type === "exposure_related") return "stroke-danger";
  if (type === "observed_flow") return "stroke-info";
  if (type === "listens_on") return "stroke-warning";
  return "stroke-muted-foreground";
}

function nodeSubtitle(node: TopologyNode): string {
  if (node.ip) return node.port ? `${node.ip}:${node.port}` : node.ip;
  if (node.cidr) return node.cidr;
  if (node.protocol) return node.protocol.toUpperCase();
  return toTitleLabel(node.node_type);
}

export function NetworkTopologyCanvas({
  graph,
  loading,
  selected,
  onSelectNode,
  onSelectEdge,
}: {
  graph: TopologyGraph | null;
  loading?: boolean;
  selected: Selection;
  onSelectNode: (node: TopologyNode) => void;
  onSelectEdge: (edge: TopologyEdge) => void;
}) {
  const layout = useMemo(() => computeTopologyLayout(graph), [graph]);

  if (loading && !graph) {
    return (
      <div className="flex min-h-[420px] items-center justify-center rounded-md border border-border/70 bg-background/35">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary/30 border-t-primary" aria-label="Loading topology" />
      </div>
    );
  }

  if (!graph || layout.nodes.length === 0) {
    return (
      <div className="flex min-h-[420px] items-center justify-center rounded-md border border-border/70 bg-background/35">
        <EmptyState title="No topology data" description="No projected nodes are available for the current query." />
      </div>
    );
  }

  return (
    <div className="min-w-0 overflow-hidden rounded-md border border-border/70 bg-background/35">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/70 bg-surface-2/70 px-3 py-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Badge variant="info">{layout.nodes.length} nodes</Badge>
          <Badge>{layout.edges.length} edges</Badge>
          {graph.graph_health.nodes_truncated || graph.graph_health.edges_truncated ? <Badge variant="medium">Truncated</Badge> : null}
        </div>
        <div className="text-[10px] font-mono uppercase tracking-[0.08em] text-muted-foreground">
          Evidence-linked projection
        </div>
      </div>

      <div className="relative h-[520px] min-w-0 overflow-hidden">
        <svg
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          className="h-full w-full"
          role="img"
          aria-label="Network topology graph"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            <marker id="topology-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M0 0 10 5 0 10z" className="fill-muted-foreground" />
            </marker>
          </defs>

          {layout.edges.map((edge) => {
            if (!edge.source || !edge.target) return null;
            const selectedEdge = selected?.kind === "edge" && selected.key === edge.edge_key;
            return (
              <g key={edge.edge_key}>
                <g
                  role="button"
                  tabIndex={0}
                  className="cursor-pointer outline-none"
                  onClick={() => onSelectEdge(edge)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") onSelectEdge(edge);
                  }}
                  aria-label={`Inspect ${toTitleLabel(edge.edge_type)} edge`}
                >
                  <line
                    x1={edge.source.x}
                    y1={edge.source.y}
                    x2={edge.target.x}
                    y2={edge.target.y}
                    markerEnd="url(#topology-arrow)"
                    className={cx(edgeStroke(edge), selectedEdge ? "stroke-[4]" : "stroke-[2] opacity-70")}
                    strokeDasharray={edge.confidence < 50 ? "8 8" : undefined}
                  />
                </g>
              </g>
            );
          })}

          {layout.nodes.map((node) => {
            const selectedNode = selected?.kind === "node" && selected.key === node.node_key;
            return (
              <g key={node.node_key} transform={`translate(${node.x} ${node.y})`}>
                <g
                  role="button"
                  tabIndex={0}
                  className="cursor-pointer outline-none"
                  onClick={() => onSelectNode(node)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") onSelectNode(node);
                  }}
                  aria-label={`Inspect ${node.label}`}
                >
                  <circle
                    r={node.radius + (selectedNode ? 5 : 0)}
                    className={cx(nodeTone[node.node_type] ?? nodeTone.unknown, selectedNode ? "stroke-[4]" : "stroke-[2]")}
                  />
                  <circle r={Math.max(5, node.radius / 3)} className="fill-card/80" />
                </g>
                <text
                  y={node.radius + 16}
                  textAnchor="middle"
                  className="pointer-events-none fill-foreground text-[12px] font-semibold"
                >
                  {node.label.length > 24 ? `${node.label.slice(0, 21)}...` : node.label}
                </text>
                <text
                  y={node.radius + 30}
                  textAnchor="middle"
                  className="pointer-events-none fill-muted-foreground text-[10px]"
                >
                  {nodeSubtitle(node).slice(0, 28)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <div className="grid gap-2 border-t border-border/70 bg-surface-2/50 px-3 py-2 text-[11px] text-muted-foreground md:grid-cols-3">
        <div className="min-w-0 truncate">Risk and confidence are sourced from projection metadata.</div>
        <div className="min-w-0 truncate">Edges reflect flows, ownership, alerts, and exposure context.</div>
        <div className="flex min-w-0 flex-wrap gap-1">
          {["critical", "high", "medium", "low"].map((severity) => (
            <Badge key={severity} variant={topologySeverityVariant(severity)} className="shrink-0">
              {severity}
            </Badge>
          ))}
        </div>
      </div>
    </div>
  );
}
