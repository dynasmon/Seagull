import { memo } from "react";
import type { NodeProps } from "@xyflow/react";
import { Handle, Position, useStore } from "@xyflow/react";

import { cx } from "@/shared/lib/cx";

import type { DeviceNodeData } from "../../lib/graph/graphTransform";
import {
  NODE_TYPE_LABELS,
  isAgentAssetNode,
  isExternalNode,
  nodeVisual,
  riskAccent,
  severityColor,
} from "../../lib/presentation/visuals";
import { toTitleLabel } from "../../lib/presentation/labels";
import type { TopologyNode } from "../../types";

const NODE_W = 92;
const NODE_H = 84;
const MARKER_CENTER_Y = 24;

const ZOOM_LABEL = 0.34;
const ZOOM_DETAIL = 0.62;

function zoomTierSelector(state: { transform: [number, number, number] }): number {
  const zoom = state.transform[2];
  if (zoom < ZOOM_LABEL) return 0;
  if (zoom >= ZOOM_DETAIL) return 2;
  return 1;
}

let keyframesInjected = false;
function ensureKeyframes() {
  if (typeof document === "undefined" || keyframesInjected) return;
  keyframesInjected = true;
  const style = document.createElement("style");
  style.textContent =
    "@keyframes topology-node-pulse{0%{box-shadow:0 0 0 0 rgba(34,211,238,0.55)}70%{box-shadow:0 0 0 12px rgba(34,211,238,0)}100%{box-shadow:0 0 0 0 rgba(34,211,238,0)}}";
  document.head.appendChild(style);
}

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function RouterIcon() {
  return (
    <>
      <ellipse cx="0" cy="-3" rx="7" ry="2" fill="none" strokeWidth="1.4" />
      <ellipse cx="0" cy="3" rx="7" ry="2" fill="none" strokeWidth="1.4" />
      <line x1="-7" y1="-3" x2="-7" y2="3" strokeWidth="1.4" />
      <line x1="7" y1="-3" x2="7" y2="3" strokeWidth="1.4" />
      <line x1="7" y1="0" x2="11" y2="0" strokeWidth="1.2" />
      <line x1="-7" y1="0" x2="-11" y2="0" strokeWidth="1.2" />
    </>
  );
}

function SensorIcon() {
  return (
    <>
      <circle cx="0" cy="2" r="2.4" fill="currentColor" stroke="none" />
      <path d="M-4.5,-1.5 A6.4,6.4 0 0 1 4.5,-1.5" fill="none" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M-8,-5 A11,11 0 0 1 8,-5" fill="none" strokeWidth="1.4" strokeLinecap="round" />
      <line x1="0" y1="2" x2="0" y2="9" strokeWidth="1.4" />
    </>
  );
}

function HostIcon() {
  return (
    <>
      <rect x="-9" y="-9" width="18" height="13" rx="2" fill="none" strokeWidth="1.8" />
      <line x1="-3" y1="4" x2="3" y2="4" strokeWidth="1.6" />
      <rect x="-5" y="4" width="10" height="3" rx="1" fill="none" strokeWidth="1.4" />
    </>
  );
}

function ServiceIcon() {
  return (
    <>
      <rect x="-9" y="-9" width="18" height="18" rx="2" fill="none" strokeWidth="1.8" />
      <rect x="-7" y="-6" width="10" height="3.5" rx="1" fill="none" strokeWidth="1.2" />
      <rect x="-7" y="-1" width="10" height="3.5" rx="1" fill="none" strokeWidth="1.2" />
      <rect x="-7" y="4" width="10" height="3.5" rx="1" fill="none" strokeWidth="1.2" />
      <circle cx="5.5" cy="-4.5" r="1.5" fill="currentColor" stroke="none" />
      <circle cx="5.5" cy="0.5" r="1.5" fill="currentColor" stroke="none" opacity="0.7" />
      <circle cx="5.5" cy="5.5" r="1.5" fill="currentColor" stroke="none" opacity="0.4" />
    </>
  );
}

function SubnetIcon() {
  return (
    <>
      <rect x="-9" y="-4" width="18" height="8" rx="1.5" fill="none" strokeWidth="1.4" />
      {([-6, -3, 0, 3, 6] as const).map((px) => (
        <rect key={px} x={px} y="-7" width="2" height="3" rx="0.4" fill="currentColor" stroke="none" opacity="0.7" />
      ))}
    </>
  );
}

function GlobeIcon() {
  return (
    <>
      <circle cx="0" cy="0" r="8.5" fill="none" strokeWidth="1.4" />
      <ellipse cx="0" cy="0" rx="3.6" ry="8.5" fill="none" strokeWidth="1.2" />
      <line x1="-8.5" y1="0" x2="8.5" y2="0" strokeWidth="1.2" />
      <path d="M-7.4,-4.4 A11,11 0 0 0 7.4,-4.4" fill="none" strokeWidth="1" opacity="0.75" />
      <path d="M-7.4,4.4 A11,11 0 0 1 7.4,4.4" fill="none" strokeWidth="1" opacity="0.75" />
    </>
  );
}

function ContainerIcon() {
  return (
    <>
      <rect x="-8" y="-8" width="16" height="5" rx="1" fill="none" strokeWidth="1.3" />
      <rect x="-8" y="-2" width="16" height="5" rx="1" fill="none" strokeWidth="1.3" />
      <rect x="-8" y="4" width="16" height="5" rx="1" fill="none" strokeWidth="1.3" />
    </>
  );
}

function InterfaceIcon() {
  return (
    <>
      <rect x="-7" y="-7" width="14" height="11" rx="1.5" fill="none" strokeWidth="1.4" />
      <rect x="-5" y="2" width="3.5" height="3.5" rx="0.5" fill="none" strokeWidth="1.1" />
      <rect x="1.5" y="2" width="3.5" height="3.5" rx="0.5" fill="none" strokeWidth="1.1" />
    </>
  );
}

function UnknownIcon() {
  return (
    <>
      <rect x="-8" y="-8" width="16" height="16" rx="2" fill="none" strokeWidth="1.4" />
      <text textAnchor="middle" y="3.5" fontSize="10" fontWeight="bold" fill="currentColor" opacity="0.6">?</text>
    </>
  );
}

function ClusterIcon() {
  return (
    <>
      <rect x="-9" y="-8" width="12" height="4" rx="1" fill="none" strokeWidth="1.2" />
      <rect x="-9" y="-3" width="12" height="4" rx="1" fill="none" strokeWidth="1.2" />
      <rect x="-9" y="2" width="12" height="4" rx="1" fill="none" strokeWidth="1.2" />
      <circle cx="5.5" cy="-6" r="1.3" fill="currentColor" stroke="none" />
      <circle cx="5.5" cy="-1" r="1.3" fill="currentColor" stroke="none" opacity="0.6" />
      <circle cx="5.5" cy="4" r="1.3" fill="currentColor" stroke="none" opacity="0.35" />
    </>
  );
}

function DeviceIcon({ nodeType, isCluster }: { nodeType: string; isCluster?: boolean }) {
  if (isCluster) return <ClusterIcon />;
  switch (nodeType) {
    case "agent":          return <SensorIcon />;
    case "gateway":        return <RouterIcon />;
    case "host":           return <HostIcon />;
    case "interface":      return <InterfaceIcon />;
    case "subnet":         return <SubnetIcon />;
    case "service":        return <ServiceIcon />;
    case "external_ip":    return <GlobeIcon />;
    case "docker_network": return <ContainerIcon />;
    default:               return <UnknownIcon />;
  }
}

function humanizeCount(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

function truncate(label: string, max: number): string {
  return label.length > max ? `${label.slice(0, max - 1)}…` : label;
}

function interfaceName(node: TopologyNode): string {
  return String(node.metadata?.interface_name ?? "").trim();
}

function primaryLabelFor(node: TopologyNode): string {
  if (node.node_type === "service" && node.port != null) {
    const name = String(node.metadata?.service_name ?? node.label ?? "").trim();
    return truncate(name || `${node.port}`, 13);
  }
  if (node.node_type === "interface") {
    return truncate(interfaceName(node) || node.label || node.node_key, 13);
  }
  // Inventory projects one host node per interface, all sharing the hostname:
  // the address is what tells them apart.
  if (node.node_type === "host" && node.ip && interfaceName(node)) {
    return truncate(node.ip, 15);
  }
  return truncate(node.label || node.node_key, 13);
}

function secondaryLabelFor(node: TopologyNode): string | null {
  if (node.node_type === "service") {
    if (node.port == null) return node.ip;
    return `${node.port}/${String(node.protocol ?? "tcp").toUpperCase()}`;
  }
  if (node.node_type === "interface") return node.ip;
  if (node.node_type === "host" && node.ip && interfaceName(node)) {
    return truncate(interfaceName(node), 14);
  }
  if (node.ip && node.ip !== node.label) return node.ip;
  if (node.cidr) return node.cidr;
  if (node.ip) return null;
  return NODE_TYPE_LABELS[node.node_type] ?? toTitleLabel(node.node_type);
}

type StatusBadge = { key: string; text: string; color: string; bg: string; border: string };

function buildStatusBadges(node: TopologyNode): StatusBadge[] {
  const badges: StatusBadge[] = [];
  if (node.alert_count > 0) {
    const color = severityColor(node.severity);
    badges.push({
      key: "alerts",
      text: `${node.alert_count > 99 ? "99+" : node.alert_count} alert${node.alert_count === 1 ? "" : "s"}`,
      color,
      bg: `${color}22`,
      border: `${color}66`,
    });
  }
  if (node.metadata?.peer_group_deviation) {
    const peer = node.metadata.peer_group_deviation as Record<string, unknown>;
    const color = severityColor(String(peer.severity ?? node.severity ?? "high"));
    badges.push({ key: "peer", text: "peer dev", color, bg: `${color}20`, border: `${color}55` });
  }
  if (badges.length === 0 && node.event_count > 0) {
    badges.push({
      key: "events",
      text: `${humanizeCount(node.event_count)} ev`,
      color: "#7DA6D9",
      bg: "rgba(96,165,250,0.10)",
      border: "rgba(96,165,250,0.26)",
    });
  }
  if (badges.length === 0 && node.is_stale) {
    badges.push({
      key: "stale",
      text: "stale",
      color: "#F97316",
      bg: "rgba(249,115,22,0.12)",
      border: "rgba(249,115,22,0.34)",
    });
  }
  return badges.slice(0, 2);
}

function ChipNode({
  width,
  opacity,
  borderColor,
  background,
  title,
  dashed,
  children,
}: {
  width: number;
  opacity: number;
  borderColor: string;
  background: string;
  title: string;
  dashed?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="flex select-none items-center justify-center" style={{ width: NODE_W, height: NODE_H, opacity }}>
      <div
        className={cx("flex flex-col items-center gap-0.5 rounded-lg border px-2.5 py-1.5", dashed && "border-dashed")}
        style={{ borderColor, background, minWidth: width, cursor: "pointer" }}
        title={title}
      >
        {children}
      </div>
    </div>
  );
}

function TopologyDeviceNode({ data: rawData }: NodeProps) {
  const data = rawData as unknown as DeviceNodeData;
  const { node, isSelected, isHighlighted, isDimmed, importance } = data;
  const zoomTier = useStore(zoomTierSelector);
  const visual = nodeVisual(node);
  const accent = riskAccent(node);
  const isCluster = node.node_type === "service" && Boolean(node.metadata?._is_service_cluster);
  const clusterCount = isCluster ? Number(node.metadata?._cluster_count ?? 0) : 0;
  const isIsolatedGhost = Boolean(data.isIsolatedGhost);
  const isSelfAsset = data.isAgentAsset ?? isAgentAssetNode(node);
  const isExternal = isExternalNode(node);
  const reducedMotion = prefersReducedMotion();

  if (node.metadata?._aggregate) {
    const aggregateCount = Number(node.metadata?._aggregate_count ?? 0);
    return (
      <ChipNode
        width={84}
        opacity={isDimmed ? 0.32 : 1}
        borderColor={`${visual.stroke}55`}
        background="rgba(13,20,34,0.94)"
        title={`${aggregateCount} more ${NODE_TYPE_LABELS[node.node_type] ?? "nodes"} in this group — click to expand`}
      >
        <div className="flex items-center gap-1.5" style={{ color: visual.stroke }}>
          <svg width="15" height="15" viewBox="-14 -14 28 28" stroke="currentColor" fill="none">
            <ClusterIcon />
          </svg>
          <span className="text-[14px] font-bold leading-none tabular-nums">+{humanizeCount(aggregateCount)}</span>
        </div>
        <span className="text-[8px] uppercase tracking-[0.1em]" style={{ color: "rgba(148,163,184,0.7)" }}>
          more · expand
        </span>
      </ChipNode>
    );
  }

  if (isIsolatedGhost) {
    const isolatedCount = Number(node.metadata?._isolated_count ?? 0);
    return (
      <ChipNode
        width={100}
        opacity={isDimmed ? 0.4 : 1}
        borderColor="rgba(148,163,184,0.4)"
        background="rgba(13,20,34,0.9)"
        title={`${isolatedCount} nodes with no observed relationship — click to show`}
        dashed
      >
        <span className="text-[8px] font-bold uppercase tracking-[0.12em]" style={{ color: "rgba(148,163,184,0.7)" }}>
          No links
        </span>
        <span className="text-[15px] font-bold leading-none tabular-nums" style={{ color: "rgba(226,232,240,0.92)" }}>
          {humanizeCount(isolatedCount)}
        </span>
        <span className="text-[8px]" style={{ color: "rgba(125,211,252,0.9)" }}>click to show</span>
      </ChipNode>
    );
  }

  ensureKeyframes();

  const opacity = isDimmed ? 0.26 : node.is_stale && node.node_type !== "agent" ? 0.5 : 1;
  const markerSize = importance === "anchor" ? 44 : importance === "elevated" ? 38 : 32;
  const iconSize = importance === "anchor" ? 24 : importance === "elevated" ? 21 : 18;
  const markerTop = MARKER_CENTER_Y - markerSize / 2;
  const labelTop = MARKER_CENTER_Y + markerSize / 2 + 4;

  const showLabel = isSelected || data.isSearchMatch || (data.showLabel && zoomTier >= 1) || zoomTier >= 2;
  const showSecondary = showLabel && zoomTier >= 1;
  const badges = zoomTier >= 1 || isSelected ? buildStatusBadges(node) : buildStatusBadges(node).filter((b) => b.key === "alerts");

  const primaryLabel = isCluster ? `${clusterCount} services` : primaryLabelFor(node);
  const rawSecondary = isCluster ? null : secondaryLabelFor(node);
  const secondaryLabel = rawSecondary && rawSecondary !== primaryLabel ? rawSecondary : null;
  const centerHandle = { opacity: 0 as const, left: "50%", top: "50%", transform: "translate(-50%, -50%)" };

  const ringColor = isSelected ? "#7DD3FC" : accent ?? null;

  return (
    <div className="group relative select-none" style={{ opacity, width: NODE_W, height: NODE_H }}>
      <Handle type="target" position={Position.Left} style={centerHandle} />
      <Handle type="source" position={Position.Right} style={centerHandle} />

      {ringColor && (
        <div
          className="pointer-events-none absolute left-1/2 -translate-x-1/2 rounded-full"
          style={{
            top: markerTop - 5,
            width: markerSize + 10,
            height: markerSize + 10,
            border: `1.5px solid ${ringColor}${isSelected ? "" : "aa"}`,
            boxShadow: `0 0 14px ${ringColor}40`,
          }}
        />
      )}

      <div
        className="absolute left-1/2 -translate-x-1/2 flex items-center justify-center rounded-full transition-all duration-150"
        style={{
          top: markerTop,
          width: markerSize,
          height: markerSize,
          background: visual.fill,
          border: `${importance === "normal" ? 1.2 : 1.6}px ${isExternal ? "dashed" : "solid"} ${visual.stroke}`,
          color: visual.stroke,
          boxShadow: isHighlighted && !ringColor ? `0 0 14px ${visual.stroke}3a` : "none",
          animation: data.isNew && !reducedMotion ? "topology-node-pulse 0.7s ease-out 3" : undefined,
        }}
      >
        <svg width={iconSize} height={iconSize} viewBox="-14 -14 28 28" stroke="currentColor" fill="none">
          <DeviceIcon nodeType={node.node_type} isCluster={isCluster} />
        </svg>

        {isSelfAsset && node.node_type !== "agent" && (
          <span
            className="absolute -left-[3px] -top-[3px] h-[9px] w-[9px] rounded-full border-[1.5px] border-[#07111f]"
            style={{ background: "#22D3EE" }}
            title="Part of the monitored host"
          />
        )}
        {node.is_stale && node.node_type === "agent" && (
          <span
            className="absolute -right-[1px] -top-[1px] h-[7px] w-[7px] rounded-full border-[1.5px] border-[#07111f]"
            style={{ background: "#F97316" }}
          />
        )}
      </div>

      {showLabel && (
        <div className="pointer-events-none absolute left-0 right-0 text-center leading-tight" style={{ top: labelTop }}>
          <div
            className="truncate px-0.5 text-[10px] font-semibold"
            style={{ color: isSelected ? "#E2E8F0" : "rgba(226,232,240,0.88)" }}
            title={node.label}
          >
            {primaryLabel}
          </div>
          {showSecondary && secondaryLabel && (
            <div className="truncate px-0.5 text-[9px] tabular-nums" style={{ color: "rgba(148,163,184,0.72)" }}>
              {secondaryLabel}
            </div>
          )}
        </div>
      )}

      {badges.length > 0 && zoomTier >= 1 && (
        <div
          className="pointer-events-none absolute left-1/2 -translate-x-1/2 flex items-center justify-center gap-[3px]"
          style={{ bottom: 0, height: 13, maxWidth: NODE_W }}
        >
          {badges.map((badge) => (
            <span
              key={badge.key}
              className="inline-flex items-center justify-center rounded-[3px] px-[3px] text-[8px] font-semibold leading-none"
              style={{
                color: badge.color,
                background: badge.bg,
                border: `1px solid ${badge.border}`,
                height: 12,
                whiteSpace: "nowrap",
              }}
            >
              {badge.text}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default memo(TopologyDeviceNode);
