import { useMemo } from "react";

import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";

import { computeTopologyLayout } from "../lib/layout";
import { toTitleLabel } from "../lib/labels";
import type { TopologyEdge, TopologyGraph, TopologyNode } from "../types";

type Selection = { kind: "node"; key: string } | { kind: "edge"; key: string } | null;

const NODE_COLOR: Record<string, { stroke: string; fill: string }> = {
  agent:          { stroke: "#60A5FA", fill: "rgba(96,165,250,0.13)" },
  gateway:        { stroke: "#60A5FA", fill: "rgba(96,165,250,0.13)" },
  host:           { stroke: "#4ADE80", fill: "rgba(74,222,128,0.13)" },
  interface:      { stroke: "#38BDF8", fill: "rgba(56,189,248,0.13)" },
  subnet:         { stroke: "#FBBF24", fill: "rgba(251,191,36,0.13)" },
  service:        { stroke: "#C084FC", fill: "rgba(192,132,252,0.13)" },
  external_ip:    { stroke: "#F87171", fill: "rgba(248,113,113,0.13)" },
  docker_network: { stroke: "#22D3EE", fill: "rgba(34,211,238,0.13)" },
  unknown:        { stroke: "#9CA3AF", fill: "rgba(156,163,175,0.08)" },
};

// Offline agents get a distinct orange instead of just fading like other stale nodes.
const OFFLINE_AGENT_COLOR = { stroke: "#F97316", fill: "rgba(249,115,22,0.13)" };

function colorFor(node: { node_type: string; is_stale?: boolean } | string) {
  if (typeof node !== "string" && node.node_type === "agent" && node.is_stale) {
    return OFFLINE_AGENT_COLOR;
  }
  const t = typeof node === "string" ? node : node.node_type;
  return NODE_COLOR[t] ?? NODE_COLOR.unknown;
}

type EdgeStyle = { stroke: string; marker: string; dashArray?: string; width: number };
function edgeVisual(edge: TopologyEdge): EdgeStyle {
  const lowConf = edge.confidence < 50;
  const t = edge.edge_type;
  if (t === "alert_related")
    return { stroke: "#F87171", marker: "topo-arr-red",    width: 1.8 };
  if (t === "exposure_related")
    return { stroke: "#F87171", marker: "topo-arr-red",    dashArray: "5 3", width: 1.5 };
  if (t === "observed_flow")
    return { stroke: "#60A5FA", marker: "topo-arr-blue",   dashArray: lowConf ? "5 4" : undefined, width: 1.8 };
  if (t === "listens_on")
    return { stroke: "#FBBF24", marker: "topo-arr-amber",  dashArray: lowConf ? "5 4" : undefined, width: 1.2 };
  if (t === "resolved_dns")
    return { stroke: "#C084FC", marker: "topo-arr-purple", dashArray: "6 4", width: 1.2 };
  if (t === "member_of_subnet")
    return { stroke: "#FBBF24", marker: "topo-arr-amber",  dashArray: "3 3", width: 1.0 };
  return { stroke: "#4B5563", marker: "topo-arr-gray", dashArray: "3 3", width: 1.0 };
}

// Shorten a line by r pixels on each end so edges don't overlap node icons.
function shortenLine(x1: number, y1: number, x2: number, y2: number, r: number) {
  const dx = x2 - x1, dy = y2 - y1;
  const d = Math.sqrt(dx * dx + dy * dy);
  if (d <= r * 2.5) return { x1, y1, x2, y2 };
  const ux = dx / d, uy = dy / d;
  return { x1: x1 + ux * r, y1: y1 + uy * r, x2: x2 - ux * r, y2: y2 - uy * r };
}

// ─── Device icons ─────────────────────────────────────────────────────────────
// All drawn centered at (0,0), max bounding ±12 px.
// Parent <g> sets stroke/fill via currentColor.

function RouterIcon() {
  return (
    <>
      {/* Cisco-style cylinder/drum: top face + body + bottom face */}
      <ellipse cx="0" cy="-3.5" rx="8" ry="2.2" fill="none" strokeWidth="1.4" />
      <ellipse cx="0" cy="3.5" rx="8" ry="2.2" fill="none" strokeWidth="1.4" />
      <line x1="-8" y1="-3.5" x2="-8" y2="3.5" strokeWidth="1.4" />
      <line x1="8" y1="-3.5" x2="8" y2="3.5" strokeWidth="1.4" />
      {/* 4 port stubs */}
      <line x1="8"  y1="0"    x2="12"  y2="0"    strokeWidth="1.2" />
      <line x1="-8" y1="0"    x2="-12" y2="0"    strokeWidth="1.2" />
      <line x1="0"  y1="-5.7" x2="0"   y2="-9.5" strokeWidth="1.2" />
      <line x1="0"  y1="5.7"  x2="0"   y2="9.5"  strokeWidth="1.2" />
    </>
  );
}

function SwitchIcon() {
  return (
    <>
      {/* Flat switch body */}
      <rect x="-11" y="-4.5" width="22" height="9" rx="2" fill="none" strokeWidth="1.4" />
      {/* 6 port sockets on top */}
      {([-8, -5, -2, 1, 4, 7] as const).map((px) => (
        <rect key={px} x={px} y="-7.5" width="2" height="3" rx="0.4"
          fill="currentColor" stroke="none" opacity="0.65" />
      ))}
      {/* Status LEDs */}
      <circle cx="9.5" cy="-1.5" r="1.2" fill="currentColor" stroke="none" />
      <circle cx="9.5" cy="1.5"  r="1.2" fill="currentColor" stroke="none" opacity="0.35" />
      {/* Through-arrow */}
      <line x1="-7" y1="0" x2="5.5" y2="0" strokeWidth="1.1" />
      <path d="M3.5,-1.8 L6,0 L3.5,1.8" fill="none" strokeWidth="1.1" />
    </>
  );
}

function HostIcon() {
  return (
    <>
      {/* Monitor screen */}
      <rect x="-9" y="-9.5" width="18" height="12" rx="1.5" fill="none" strokeWidth="1.4" />
      {/* Screen glass */}
      <rect x="-6.5" y="-7.5" width="13" height="7.5" rx="0.8"
        fill="currentColor" stroke="none" opacity="0.12" />
      {/* Stand */}
      <line x1="0" y1="2.5" x2="0" y2="6.5" strokeWidth="1.5" />
      {/* Base */}
      <line x1="-4.5" y1="6.5" x2="4.5" y2="6.5" strokeWidth="2" />
    </>
  );
}

function ServerIcon() {
  return (
    <>
      {/* Rack body */}
      <rect x="-10" y="-9" width="20" height="18" rx="1.5" fill="none" strokeWidth="1.4" />
      {/* Row dividers */}
      <line x1="-10" y1="-3" x2="5" y2="-3" strokeWidth="0.9" opacity="0.5" />
      <line x1="-10" y1="2"  x2="5" y2="2"  strokeWidth="0.9" opacity="0.5" />
      <line x1="-10" y1="7"  x2="5" y2="7"  strokeWidth="0.9" opacity="0.5" />
      {/* LEDs */}
      <circle cx="8" cy="-6"   r="1.4" fill="currentColor" stroke="none" />
      <circle cx="8" cy="-0.5" r="1.4" fill="currentColor" stroke="none" opacity="0.75" />
      <circle cx="8" cy="5"    r="1.4" fill="currentColor" stroke="none" opacity="0.45" />
      <circle cx="8" cy="8.5"  r="1.4" fill="currentColor" stroke="none" opacity="0.25" />
    </>
  );
}

function ServerClusterIcon() {
  return (
    <>
      {/* Three compact stacked server racks to signal "group" */}
      <rect x="-10" y="-9.5" width="14" height="5" rx="1" fill="none" strokeWidth="1.2" />
      <rect x="-10" y="-3.5" width="14" height="5" rx="1" fill="none" strokeWidth="1.2" />
      <rect x="-10" y="2.5"  width="14" height="5" rx="1" fill="none" strokeWidth="1.2" />
      {/* LED column */}
      <circle cx="6.5" cy="-7"  r="1.3" fill="currentColor" stroke="none" />
      <circle cx="6.5" cy="-1"  r="1.3" fill="currentColor" stroke="none" opacity="0.7" />
      <circle cx="6.5" cy="5"   r="1.3" fill="currentColor" stroke="none" opacity="0.45" />
    </>
  );
}

function CloudIcon() {
  return (
    <path
      d="M -7,5 Q -11,5 -11,1 Q -11,-4 -6.5,-3.5 Q -6,-9 0,-8 Q 6,-9 7,-3.5 Q 11,-4 11,1 Q 11,5 6,5 Z"
      fill="none"
      strokeWidth="1.4"
      strokeLinejoin="round"
    />
  );
}

function ContainerIcon() {
  return (
    <>
      {/* 3 stacked container boxes */}
      <rect x="-9" y="-10"  width="18" height="5.5" rx="1" fill="none" strokeWidth="1.3" />
      <rect x="-9" y="-3.5" width="18" height="5.5" rx="1" fill="none" strokeWidth="1.3" />
      <rect x="-9" y="3"    width="18" height="5.5" rx="1" fill="none" strokeWidth="1.3" />
      {/* Port handles */}
      <line x1="-9" y1="-7.2" x2="-11.5" y2="-7.2" strokeWidth="1.2" />
      <line x1="-9" y1="-0.7" x2="-11.5" y2="-0.7" strokeWidth="1.2" />
      <line x1="-9" y1="5.8"  x2="-11.5" y2="5.8"  strokeWidth="1.2" />
    </>
  );
}

function InterfaceIcon() {
  return (
    <>
      {/* NIC card body */}
      <rect x="-8" y="-9" width="16" height="14" rx="1.5" fill="none" strokeWidth="1.4" />
      {/* 2 RJ45 port slots */}
      <rect x="-6" y="2.5" width="4" height="4" rx="0.6" fill="none" strokeWidth="1.1" />
      <rect x="2"  y="2.5" width="4" height="4" rx="0.6" fill="none" strokeWidth="1.1" />
      {/* Trace lines */}
      <line x1="-4" y1="-5" x2="4" y2="-5" strokeWidth="1" opacity="0.5" />
      <line x1="-4" y1="-2" x2="2" y2="-2" strokeWidth="1" opacity="0.5" />
    </>
  );
}

function UnknownIcon() {
  return (
    <>
      <rect x="-9" y="-9" width="18" height="18" rx="2.5" fill="none" strokeWidth="1.4" />
      <text textAnchor="middle" y="4" fontSize="12" fontWeight="bold"
        fill="currentColor" opacity="0.5">?</text>
    </>
  );
}

function DeviceIcon({ nodeType, isCluster }: { nodeType: string; isCluster?: boolean }) {
  switch (nodeType) {
    case "agent":
    case "gateway":        return <RouterIcon />;
    case "host":           return <HostIcon />;
    case "interface":      return <InterfaceIcon />;
    case "subnet":         return <SwitchIcon />;
    case "service":        return isCluster ? <ServerClusterIcon /> : <ServerIcon />;
    case "external_ip":    return <CloudIcon />;
    case "docker_network": return <ContainerIcon />;
    default:               return <UnknownIcon />;
  }
}

// ─── Service name chips rendered below a service cluster node ─────────────────

function ServiceNameChips({ names, extra, y }: { names: string[]; extra: number; y: number }) {
  const shown = names.slice(0, 3);
  const chipH = 10, gap = 2;
  // Dynamic chip width based on text length (approx 5.5px per char + 8px padding)
  const chipWidths = shown.map((n) => Math.max(28, Math.min(52, n.length * 5.5 + 8)));
  const totalW = chipWidths.reduce((s, w) => s + w, 0) + (shown.length - 1) * gap;
  const startX = -totalW / 2;

  let curX = startX;
  return (
    <g transform={`translate(0 ${y})`}>
      {shown.map((name, i) => {
        const cw = chipWidths[i];
        const x = curX;
        curX += cw + gap;
        return (
          <g key={name}>
            <rect
              x={x} y={-chipH / 2}
              width={cw} height={chipH} rx="2.5"
              fill="rgba(124,58,237,0.18)" stroke="#8B5CF6" strokeWidth="0.6"
            />
            <text
              x={x + cw / 2} textAnchor="middle" y="3.5"
              fontSize="6.5" fill="#C084FC"
              className="pointer-events-none select-none">
              {name.length > 8 ? name.slice(0, 7) + "…" : name}
            </text>
          </g>
        );
      })}
      {extra > 0 && (
        <text
          x={curX + 2}
          textAnchor="start" y="3.5"
          fontSize="7" fill="rgba(192,132,252,0.55)"
          className="pointer-events-none select-none">
          +{extra}
        </text>
      )}
    </g>
  );
}

// ─── Legend labels ─────────────────────────────────────────────────────────────

const NODE_LABEL: Record<string, string> = {
  agent: "Router/Agent", gateway: "Gateway", host: "Host",
  interface: "Interface", subnet: "Switch/Subnet", service: "Server",
  external_ip: "External IP", docker_network: "Container Net", unknown: "Unknown",
};

function nodeSubtitle(node: TopologyNode): string {
  if (node.ip) return node.port ? `${node.ip}:${node.port}` : node.ip;
  if (node.cidr) return node.cidr;
  if (node.protocol) return node.protocol.toUpperCase();
  return toTitleLabel(node.node_type);
}

// ─── Main canvas ───────────────────────────────────────────────────────────────

const ICON_R = 15; // icon half-size used for line shortening

export function NetworkTopologyCanvas({
  graph, loading, selected, onSelectNode, onSelectEdge,
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
      <div className="flex min-h-[480px] items-center justify-center rounded-md border border-border/70 bg-background/35">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary/30 border-t-primary" aria-label="Loading topology" />
      </div>
    );
  }

  if (!graph || layout.nodes.length === 0) {
    return (
      <div className="flex min-h-[480px] items-center justify-center rounded-md border border-border/70 bg-background/35">
        <EmptyState title="No topology data" description="No projected nodes are available for the current query." />
      </div>
    );
  }

  const presentTypes = [...new Set(layout.nodes.map((n) => n.node_type))];
  const hasOfflineAgents = layout.nodes.some((n) => n.node_type === "agent" && n.is_stale);

  return (
    <div className="min-w-0 overflow-hidden rounded-md border border-border/70 bg-background/40">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 bg-surface-2/60 px-3 py-2">
        <div className="flex min-w-0 items-center gap-1.5 text-[11px] text-muted-foreground">
          <span className="font-semibold tabular-nums text-foreground">{layout.nodes.length}</span> nodes ·
          <span className="font-semibold tabular-nums text-foreground">{layout.edges.length}</span> edges
          {(graph.graph_health.nodes_truncated || graph.graph_health.edges_truncated) && (
            <span className="ml-1 text-warning">· truncated</span>
          )}
        </div>
        <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground/50">
          Evidence-linked projection
        </span>
      </div>

      {/* SVG canvas */}
      <div className="relative h-[620px] min-w-0 overflow-hidden">
        <svg
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          className="h-full w-full"
          role="img"
          aria-label="Network topology diagram"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            {/* Dot grid background */}
            <pattern id="topo-dot-grid" x="0" y="0" width="28" height="28" patternUnits="userSpaceOnUse">
              <circle cx="0" cy="0" r="0.85" fill="rgba(148,163,184,0.14)" />
            </pattern>
            {/* Arrow markers per edge color */}
            {(
              [
                ["topo-arr-blue",   "#60A5FA"],
                ["topo-arr-red",    "#F87171"],
                ["topo-arr-amber",  "#FBBF24"],
                ["topo-arr-purple", "#C084FC"],
                ["topo-arr-gray",   "#4B5563"],
              ] as [string, string][]
            ).map(([id, color]) => (
              <marker key={id} id={id}
                viewBox="0 0 8 8" refX="7" refY="4"
                markerWidth="4.5" markerHeight="4.5"
                orient="auto">
                <path d="M0 0 8 4 0 8z" fill={color} />
              </marker>
            ))}
          </defs>

          {/* Background */}
          <rect width={layout.width} height={layout.height} fill="url(#topo-dot-grid)" />

          {/* ── Edges ─────────────────────────────────────────── */}
          {layout.edges.map((edge) => {
            if (!edge.source || !edge.target) return null;
            const isSel = selected?.kind === "edge" && selected.key === edge.edge_key;
            const { stroke, marker, dashArray, width } = edgeVisual(edge);
            const { x1, y1, x2, y2 } = shortenLine(
              edge.source.x, edge.source.y,
              edge.target.x, edge.target.y,
              ICON_R,
            );
            return (
              <g key={edge.edge_key}>
                <line
                  x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke={stroke}
                  strokeWidth={isSel ? width + 1.5 : width}
                  strokeDasharray={dashArray}
                  markerEnd={`url(#${marker})`}
                  opacity={isSel ? 1 : 0.6}
                />
                {/* Wide transparent hit area */}
                <line
                  x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke="transparent" strokeWidth={14}
                  className="cursor-pointer"
                  role="button" tabIndex={0}
                  onClick={() => onSelectEdge(edge)}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") onSelectEdge(edge); }}
                  aria-label={`Inspect ${toTitleLabel(edge.edge_type)} edge`}
                />
              </g>
            );
          })}

          {/* ── Nodes ─────────────────────────────────────────── */}
          {layout.nodes.map((node) => {
            const isSel = selected?.kind === "node" && selected.key === node.node_key;
            const { stroke, fill } = colorFor(node);
            const stale = node.is_stale;
            const isOfflineAgent = node.node_type === "agent" && stale;
            const isCluster = node.node_type === "service" && Boolean(node.metadata?._is_service_cluster);
            const clusterCount = isCluster ? Number(node.metadata!._cluster_count) : 0;
            const clusterNames = isCluster ? ((node.metadata!._cluster_service_names as string[]) ?? []) : [];
            const clusterExtra = Math.max(0, clusterCount - clusterNames.length);
            const hasAlert = node.alert_count > 0;

            // Stale fading applies to non-agent stale nodes; offline agents stay full opacity (color is the signal).
            const backdropOpacity = stale && !isOfflineAgent ? 0.4 : 1;
            const iconOpacity = stale && !isOfflineAgent ? 0.5 : 1;

            const IW = 16, IH = 14; // icon backdrop half-dimensions

            return (
              <g key={node.node_key} transform={`translate(${node.x} ${node.y})`}>
                {/* Selection ring */}
                {isSel && (
                  <rect
                    x={-(IW + 5)} y={-(IH + 5)}
                    width={(IW + 5) * 2} height={(IH + 5) * 2}
                    rx="7"
                    fill="none"
                    stroke={stroke}
                    strokeWidth="2.5"
                    opacity="0.85"
                  />
                )}

                {/* Icon backdrop */}
                <rect
                  x={-IW} y={-IH}
                  width={IW * 2} height={IH * 2}
                  rx="4"
                  style={{ fill }}
                  stroke={stroke}
                  strokeWidth={isSel ? "1.8" : "1"}
                  opacity={backdropOpacity}
                />

                {/* Device icon — stroke via currentColor */}
                <g stroke={stroke} fill="none" opacity={iconOpacity}>
                  <DeviceIcon nodeType={node.node_type} isCluster={isCluster} />
                </g>

                {/*
                  Top-right corner indicator — priority:
                    1. Service cluster count badge
                    2. Offline agent indicator (orange) or alert dot (red) if agent has alerts
                    3. Alert dot for normal nodes with alerts
                    4. Gray stale dot for other stale nodes
                */}
                {isCluster ? (
                  <g transform={`translate(${IW - 3} ${-(IH - 4)})`}>
                    <circle r="7" fill="#7C3AED" stroke="rgba(0,0,0,0.35)" strokeWidth="0.7" />
                    <text
                      textAnchor="middle" y="3" fontSize="8" fontWeight="bold" fill="white"
                      className="pointer-events-none select-none">
                      {clusterCount > 99 ? "99+" : clusterCount}
                    </text>
                  </g>
                ) : isOfflineAgent ? (
                  <circle
                    cx={IW - 4} cy={-(IH - 4)} r="4.5"
                    fill={hasAlert ? "#F87171" : "#F97316"}
                    stroke="none"
                  />
                ) : (
                  <>
                    {hasAlert && !stale && (
                      <circle cx={IW - 4} cy={-(IH - 4)} r="4.5" fill="#F87171" stroke="none" />
                    )}
                    {stale && (
                      <circle cx={IW - 4} cy={-(IH - 4)} r="4.5" fill="#6B7280" stroke="none" />
                    )}
                  </>
                )}

                {/* Transparent click target */}
                <rect
                  x={-(IW + 2)} y={-(IH + 2)}
                  width={(IW + 2) * 2} height={(IH + 2) * 2}
                  rx="5"
                  fill="transparent"
                  className="cursor-pointer outline-none"
                  role="button" tabIndex={0}
                  onClick={() => onSelectNode(node)}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") onSelectNode(node); }}
                  aria-label={`Inspect ${node.label}`}
                />

                {/* Labels */}
                <text y={IH + 13} textAnchor="middle"
                  fontSize="10.5" fontWeight="600"
                  fill={stroke}
                  className="pointer-events-none select-none">
                  {node.label.length > 20 ? `${node.label.slice(0, 18)}…` : node.label}
                </text>
                <text y={IH + 24} textAnchor="middle"
                  fontSize="9" fill="rgba(148,163,184,0.75)"
                  className="pointer-events-none select-none">
                  {isCluster
                    ? `${clusterCount} service${clusterCount !== 1 ? "s" : ""}`
                    : nodeSubtitle(node).slice(0, 24)}
                </text>

                {/* Service name chips for clusters */}
                {isCluster && clusterNames.length > 0 && (
                  <ServiceNameChips names={clusterNames} extra={clusterExtra} y={IH + 34} />
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Legend */}
      <div className={cx(
        "flex flex-wrap items-center gap-x-4 gap-y-1.5",
        "border-t border-border/60 bg-surface-2/40 px-3 py-2.5",
      )}>
        {presentTypes.map((t) => {
          const { stroke } = colorFor(t);
          return (
            <div key={t} className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: stroke }} />
              {NODE_LABEL[t] ?? toTitleLabel(t)}
            </div>
          );
        })}

        {/* Extra legend entries for states that override node-type colors */}
        {hasOfflineAgents && (
          <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <span className="h-2 w-2 shrink-0 rounded-full bg-[#F97316]" />
            Offline Agent
          </div>
        )}

        <div className="ml-auto flex shrink-0 items-center gap-3 text-[10px] text-muted-foreground/55">
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-px w-5 bg-[#60A5FA] opacity-80" />
            flow
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-px w-5 border-t border-dashed border-[#F87171] opacity-80" />
            alert / exposure
          </span>
        </div>
      </div>
    </div>
  );
}
