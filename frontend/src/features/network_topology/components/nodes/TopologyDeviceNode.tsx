import { memo } from "react";
import type { NodeProps } from "@xyflow/react";
import { Handle, Position, useStore } from "@xyflow/react";

import { cx } from "@/shared/lib/cx";

import type { DeviceNodeData } from "../../lib/graph/graphTransform";
import { nodeVisual, NODE_TYPE_LABELS, severityColor } from "../../lib/presentation/visuals";
import { toTitleLabel } from "../../lib/presentation/labels";
import type { TopologyNode } from "../../types";

const NODE_H = 96;
const NODE_W = 96;
const ICON_CENTER_Y = 30;
const LABEL_FAR_ZOOM = 0.45;
const LABEL_NEAR_ZOOM = 0.95;

function zoomTierSelector(state: { transform: [number, number, number] }): number {
  const zoom = state.transform[2];
  if (zoom < LABEL_FAR_ZOOM) return 0;
  if (zoom >= LABEL_NEAR_ZOOM) return 2;
  return 1;
}

let pulseKeyframeInjected = false;
function ensurePulseKeyframe() {
  if (typeof document === "undefined" || pulseKeyframeInjected) return;
  pulseKeyframeInjected = true;
  const style = document.createElement("style");
  style.textContent = `@keyframes topology-node-pulse{0%{box-shadow:0 0 0 0 rgba(96,165,250,0.7)}70%{box-shadow:0 0 0 14px rgba(96,165,250,0)}100%{box-shadow:0 0 0 0 rgba(96,165,250,0)}}@keyframes topology-anchor-ring{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`;
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

function HostIcon() {
  return (
    <>
      <rect x="-9" y="-9" width="18" height="13" rx="2" fill="none" strokeWidth="1.8" />
      <line x1="-3" y1="4" x2="3" y2="4" strokeWidth="1.6" />
      <rect x="-5" y="4" width="10" height="3" rx="1" fill="none" strokeWidth="1.4" />
    </>
  );
}

function ServerIcon() {
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

function SwitchIcon() {
  return (
    <>
      <rect x="-9" y="-4" width="18" height="8" rx="1.5" fill="none" strokeWidth="1.4" />
      {([-6, -3, 0, 3, 6] as const).map((px) => (
        <rect key={px} x={px} y="-7" width="2" height="3" rx="0.4" fill="currentColor" stroke="none" opacity="0.7" />
      ))}
    </>
  );
}

function CloudIcon() {
  return (
    <path
      d="M-6,4 Q-9,4 -9,1 Q-9,-3 -5.5,-3 Q-5,-7 0,-6.5 Q5,-7 6,-3 Q9,-3 9,1 Q9,4 5,4 Z"
      fill="none"
      strokeWidth="1.4"
      strokeLinejoin="round"
    />
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

function ServerClusterIcon() {
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
  if (isCluster) return <ServerClusterIcon />;
  switch (nodeType) {
    case "agent":
    case "gateway":      return <RouterIcon />;
    case "host":         return <HostIcon />;
    case "interface":    return <InterfaceIcon />;
    case "subnet":       return <SwitchIcon />;
    case "service":      return <ServerIcon />;
    case "external_ip":  return <CloudIcon />;
    case "docker_network": return <ContainerIcon />;
    default:             return <UnknownIcon />;
  }
}

function humanizeCount(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

function truncateLabel(label: string, max: number): string {
  return label.length > max ? `${label.slice(0, max - 1)}…` : label;
}

function nodeSubtitleFallback(node: TopologyNode): string {
  if (node.cidr) return node.cidr;
  if (node.protocol) return node.protocol.toUpperCase();
  return NODE_TYPE_LABELS[node.node_type] ?? toTitleLabel(node.node_type);
}

type StatusBadge = {
  key: string;
  text: string;
  color: string;
  bg: string;
  border: string;
};

function buildStatusBadges(node: TopologyNode): StatusBadge[] {
  const badges: StatusBadge[] = [];
  if (node.alert_count > 0) {
    const color = severityColor(node.severity);
    badges.push({
      key: "alerts",
      text: `${node.alert_count > 99 ? "99+" : node.alert_count}⚑`,
      color,
      bg: `${color}22`,
      border: `${color}55`,
    });
  }
  if (node.event_count > 0) {
    badges.push({
      key: "events",
      text: humanizeCount(node.event_count),
      color: "#60A5FA",
      bg: "rgba(96,165,250,0.10)",
      border: "rgba(96,165,250,0.30)",
    });
  }
  if (node.confidence < 60) {
    badges.push({
      key: "confidence",
      text: `~${Math.max(0, Math.round(node.confidence))}%`,
      color: "#FBBF24",
      bg: "rgba(251,191,36,0.12)",
      border: "rgba(251,191,36,0.35)",
    });
  }
  if (node.is_stale) {
    badges.push({
      key: "stale",
      text: "STALE",
      color: "#F97316",
      bg: "rgba(249,115,22,0.14)",
      border: "rgba(249,115,22,0.4)",
    });
  }
  return badges;
}

function TopologyDeviceNode({ data: rawData }: NodeProps) {
  const data = rawData as unknown as DeviceNodeData;
  const { node, isSelected, isHighlighted, isDimmed, importance } = data;
  const zoomTier = useStore(zoomTierSelector);
  const visual = nodeVisual(node);
  const hasAlert = node.alert_count > 0;
  const isCluster = node.node_type === "service" && Boolean(node.metadata?._is_service_cluster);
  const clusterCount = isCluster ? Number(node.metadata?._cluster_count ?? 0) : 0;
  const isLiveAgent = node.node_type === "agent" && !node.is_stale;
  const isIsolatedGhost = Boolean(data.isIsolatedGhost);
  const reducedMotion = prefersReducedMotion();

  const alwaysLabel = isSelected || data.isSearchMatch || isIsolatedGhost;
  const showLabel = alwaysLabel || (data.showLabel && zoomTier >= 1) || zoomTier >= 2;
  const showDetailBadges = zoomTier >= 1 || isSelected;

  if (node.metadata?._aggregate) {
    const aggregateCount = Number(node.metadata?._aggregate_count ?? 0);
    return (
      <div
        className="group flex select-none items-center justify-center"
        style={{ width: NODE_W, height: NODE_H, opacity: isDimmed ? 0.2 : 1 }}
      >
        <div
          className="flex flex-col items-center gap-0.5 rounded-xl border px-3 py-1.5"
          style={{
            borderColor: `${visual.stroke}55`,
            background: "rgba(13,20,34,0.92)",
            minWidth: 88,
            cursor: "pointer",
          }}
          title={`${aggregateCount} more ${NODE_TYPE_LABELS[node.node_type] ?? "nodes"} — click to expand`}
        >
          <div className="flex items-center gap-1.5" style={{ color: visual.stroke }}>
            <svg width="15" height="15" viewBox="-14 -14 28 28" stroke="currentColor" fill="none">
              <DeviceIcon nodeType={node.node_type} isCluster />
            </svg>
            <span className="text-[14px] font-bold leading-none tabular-nums">+{humanizeCount(aggregateCount)}</span>
          </div>
          <span className="text-[8px] uppercase tracking-[0.1em]" style={{ color: "rgba(148,163,184,0.65)" }}>
            more · expand
          </span>
        </div>
      </div>
    );
  }

  if (isIsolatedGhost) {
    const isolatedCount = Number(node.metadata?._isolated_count ?? 0);
    return (
      <div
        className="group flex select-none items-center justify-center"
        style={{ width: NODE_W, height: NODE_H, opacity: isDimmed ? 0.4 : 1 }}
      >
        <div
          className="flex flex-col items-center gap-0.5 rounded-xl border border-dashed px-3 py-2"
          style={{
            borderColor: "rgba(148,163,184,0.4)",
            background: "rgba(13,20,34,0.9)",
            minWidth: 104,
            cursor: "pointer",
          }}
          title={`${isolatedCount} isolated hosts — click to show`}
        >
          <span className="text-[8px] font-bold uppercase tracking-[0.12em]" style={{ color: "rgba(148,163,184,0.7)" }}>
            Isolated
          </span>
          <span className="text-[15px] font-bold leading-none tabular-nums" style={{ color: "rgba(226,232,240,0.92)" }}>
            {humanizeCount(isolatedCount)}
          </span>
          <span className="text-[8px]" style={{ color: "rgba(96,165,250,0.85)" }}>
            click to show
          </span>
        </div>
      </div>
    );
  }

  ensurePulseKeyframe();

  const opacity = isDimmed ? 0.11 : node.is_stale && node.node_type !== "agent" ? 0.45 : 1;

  const baseBoost = isSelected ? 4 : 0;
  const markerSize =
    importance === "anchor"   ? 48 + baseBoost :
    importance === "elevated" ? 38 + baseBoost : 32 + baseBoost;
  const iconSize =
    importance === "anchor"   ? 26 :
    importance === "elevated" ? 21 : 17;

  const circleTop = ICON_CENTER_Y - markerSize / 2;
  const labelTop = ICON_CENTER_Y + markerSize / 2 + 3;

  const primaryLabel = isCluster ? `${clusterCount} svc` : truncateLabel(node.label, 14);
  const secondaryText = isCluster ? null : node.ip;
  const fallbackSubtitle = isCluster ? null : nodeSubtitleFallback(node);

  const allBadges = buildStatusBadges(node);
  const badges = showDetailBadges ? allBadges : allBadges.filter((badge) => badge.key === "alerts");

  const centerHandle = { opacity: 0 as const, left: "50%", top: "50%", transform: "translate(-50%, -50%)" };

  return (
    <div
      className="group relative select-none"
      style={{ opacity, width: NODE_W, height: NODE_H }}
    >
      <Handle type="target" position={Position.Left}  style={centerHandle} />
      <Handle type="source" position={Position.Right} style={centerHandle} />

      <div
        className={cx(
          "absolute left-1/2 -translate-x-1/2 flex items-center justify-center rounded-full transition-all duration-200",
          isSelected && "ring-2 ring-offset-1 ring-offset-[#07111f]",
        )}
        style={{
          top: circleTop,
          width: markerSize,
          height: markerSize,
          background: visual.fill,
          border: `${isSelected ? "2px" : importance === "normal" ? "1.2px" : "1.5px"} solid ${visual.stroke}`,
          color: visual.stroke,
          boxShadow: isSelected
            ? `0 0 22px ${visual.stroke}50`
            : isHighlighted
              ? `0 0 16px ${visual.stroke}38`
              : hasAlert
                ? `0 0 12px ${severityColor(node.severity)}28`
                : "none",
          animation: data.isNew && !reducedMotion ? "topology-node-pulse 0.7s ease-out 3" : undefined,
        }}
      >
        {isLiveAgent && (
          <svg
            width={markerSize + 24}
            height={markerSize + 24}
            viewBox="-40 -40 80 80"
            style={{
              position: "absolute",
              inset: -12,
              pointerEvents: "none",
              animation: reducedMotion ? undefined : "topology-anchor-ring 8s linear infinite",
              transformOrigin: "50% 50%",
            }}
          >
            <circle
              cx="0"
              cy="0"
              r="36"
              fill="none"
              stroke={visual.stroke}
              strokeOpacity="0.45"
              strokeWidth="1"
              strokeDasharray="2 4"
            />
          </svg>
        )}

        <svg width={iconSize} height={iconSize} viewBox="-14 -14 28 28" stroke="currentColor" fill="none">
          <DeviceIcon nodeType={node.node_type} isCluster={isCluster} />
        </svg>

        {node.is_stale && node.node_type === "agent" && (
          <span
            className="absolute -right-[1px] -top-[1px] h-[7px] w-[7px] rounded-full border-[1.5px] border-[#07111f]"
            style={{ background: "#F97316" }}
          />
        )}
      </div>

      {showLabel && (
        <div
          className="pointer-events-none absolute left-0 right-0 overflow-hidden text-center leading-tight"
          style={{ top: labelTop }}
        >
          <div
            className="truncate px-0.5 text-[10px] font-semibold"
            style={{ color: visual.stroke }}
            title={node.label}
          >
            {primaryLabel}
          </div>
          {secondaryText && zoomTier >= 1 && (
            <div
              className="truncate px-0.5 text-[9px]"
              style={{ color: "rgba(148,163,184,0.78)", opacity: 0.5 }}
            >
              {secondaryText}
            </div>
          )}
          {!secondaryText && fallbackSubtitle && importance === "anchor" && zoomTier >= 1 && (
            <div
              className="truncate px-0.5 text-[9px]"
              style={{ color: "rgba(148,163,184,0.78)", opacity: 0.5 }}
            >
              {fallbackSubtitle}
            </div>
          )}
        </div>
      )}

      {badges.length > 0 && (
        <div
          className="pointer-events-none absolute left-1/2 -translate-x-1/2 flex items-center justify-center gap-[3px]"
          style={{ bottom: 2, height: 14, maxWidth: NODE_W - 4 }}
        >
          {badges.map((badge) => (
            <span
              key={badge.key}
              className="inline-flex items-center justify-center rounded-[3px] px-[3px] text-[8px] font-bold leading-none"
              style={{
                color: badge.color,
                background: badge.bg,
                border: `1px solid ${badge.border}`,
                height: 12,
                minWidth: 14,
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
