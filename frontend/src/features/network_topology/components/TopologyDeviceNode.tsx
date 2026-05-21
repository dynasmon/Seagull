import { memo } from "react";
import type { NodeProps } from "@xyflow/react";
import { Handle, Position } from "@xyflow/react";

import { cx } from "@/shared/lib/cx";

import type { DeviceNodeData } from "../lib/graphTransform";
import { nodeVisual, NODE_TYPE_LABELS, severityColor } from "../lib/visuals";
import { toTitleLabel } from "../lib/labels";
import type { TopologyNode } from "../types";

const NODE_H = 96;
const NODE_W = 96;
const CIRCLE_CENTER_Y = NODE_H / 2;

let pulseKeyframeInjected = false;
function ensurePulseKeyframe() {
  if (typeof document === "undefined" || pulseKeyframeInjected) return;
  pulseKeyframeInjected = true;
  const style = document.createElement("style");
  style.textContent = `@keyframes topology-node-pulse{0%{box-shadow:0 0 0 0 rgba(96,165,250,0.7)}70%{box-shadow:0 0 0 14px rgba(96,165,250,0)}100%{box-shadow:0 0 0 0 rgba(96,165,250,0)}}`;
  document.head.appendChild(style);
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

function nodeSubtitle(node: TopologyNode): string {
  if (node.ip) return node.port ? `${node.ip}:${node.port}` : node.ip;
  if (node.cidr) return node.cidr;
  if (node.protocol) return node.protocol.toUpperCase();
  return NODE_TYPE_LABELS[node.node_type] ?? toTitleLabel(node.node_type);
}

function TopologyDeviceNode({ data: rawData }: NodeProps) {
  const data = rawData as unknown as DeviceNodeData;
  const { node, isSelected, isHighlighted, isDimmed, showLabel, importance, isSearchMatch } = data;
  const visual = nodeVisual(node);
  const hasAlert = node.alert_count > 0;
  const isCluster = node.node_type === "service" && Boolean(node.metadata?._is_service_cluster);
  const clusterCount = isCluster ? Number(node.metadata?._cluster_count ?? 0) : 0;

  if (data.isNew) ensurePulseKeyframe();

  const opacity = isDimmed ? 0.11 : node.is_stale && node.node_type !== "agent" ? 0.38 : 1;

  const baseBoost = isSelected ? 5 : 0;
  const markerSize =
    importance === "anchor"   ? 52 + baseBoost :
    importance === "elevated" ? 40 + baseBoost : 32 + baseBoost;
  const iconSize =
    importance === "anchor"   ? 28 :
    importance === "elevated" ? 22 : 17;

  const circleTop = CIRCLE_CENTER_Y - markerSize / 2;
  const labelTop = CIRCLE_CENTER_Y + markerSize / 2 + 4;

  const label = node.label.length > 18 ? `${node.label.slice(0, 16)}…` : node.label;
  const subtitle = isCluster
    ? `${clusterCount} service${clusterCount !== 1 ? "s" : ""}`
    : nodeSubtitle(node).slice(0, 22);

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
          animation: data.isNew ? "topology-node-pulse 0.7s ease-out 3" : undefined,
        }}
      >
        <svg width={iconSize} height={iconSize} viewBox="-14 -14 28 28" stroke="currentColor" fill="none">
          <DeviceIcon nodeType={node.node_type} isCluster={isCluster} />
        </svg>

        {node.is_stale && node.node_type === "agent" && (
          <span
            className="absolute -right-[1px] -top-[1px] h-[7px] w-[7px] rounded-full border-[1.5px] border-[#07111f]"
            style={{ background: "#F97316" }}
          />
        )}
        {hasAlert && node.alert_count > 0 && (
          <span
            className="absolute -right-2 -top-2 flex h-4 min-w-[16px] items-center justify-center rounded-full border border-[#07111f] px-1 text-[8px] font-bold"
            style={{ background: severityColor(node.severity), color: "#fff" }}
          >
            {node.alert_count > 9 ? "9+" : node.alert_count}
          </span>
        )}
      </div>

      <div
        className={cx(
          "pointer-events-none absolute left-0 right-0 overflow-hidden text-center leading-none transition-opacity duration-150 group-hover:opacity-100",
          (showLabel || importance === "anchor") ? "opacity-100" : "opacity-0",
        )}
        style={{ top: labelTop }}
      >
        <div
          className="truncate px-0.5 text-[10px] font-semibold"
          style={{ color: visual.stroke }}
        >
          {label}
        </div>
        {(isSelected || isSearchMatch || importance === "anchor") && (
          <div className="truncate px-0.5 text-[9px]" style={{ color: "rgba(148,163,184,0.65)" }}>
            {subtitle}
          </div>
        )}
      </div>
    </div>
  );
}

export default memo(TopologyDeviceNode);
