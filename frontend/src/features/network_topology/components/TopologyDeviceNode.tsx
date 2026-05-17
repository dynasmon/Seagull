import { memo } from "react";
import type { NodeProps } from "@xyflow/react";
import { Handle, Position } from "@xyflow/react";

import { cx } from "@/shared/lib/cx";

import type { DeviceNodeData } from "../lib/graphTransform";
import { nodeVisual, NODE_TYPE_LABELS, severityColor } from "../lib/visuals";
import { toTitleLabel } from "../lib/labels";
import type { TopologyNode } from "../types";

function RouterIcon() {
  return (
    <>
      <ellipse cx="0" cy="-3" rx="7" ry="2" fill="none" strokeWidth="1.3" />
      <ellipse cx="0" cy="3" rx="7" ry="2" fill="none" strokeWidth="1.3" />
      <line x1="-7" y1="-3" x2="-7" y2="3" strokeWidth="1.3" />
      <line x1="7" y1="-3" x2="7" y2="3" strokeWidth="1.3" />
      <line x1="7" y1="0" x2="10" y2="0" strokeWidth="1.1" />
      <line x1="-7" y1="0" x2="-10" y2="0" strokeWidth="1.1" />
    </>
  );
}

function HostIcon() {
  return (
    <>
      <rect x="-8" y="-8" width="16" height="11" rx="1.5" fill="none" strokeWidth="1.3" />
      <line x1="0" y1="3" x2="0" y2="6" strokeWidth="1.4" />
      <line x1="-4" y1="6" x2="4" y2="6" strokeWidth="1.8" />
    </>
  );
}

function ServerIcon() {
  return (
    <>
      <rect x="-8" y="-8" width="16" height="16" rx="1.5" fill="none" strokeWidth="1.3" />
      <line x1="-8" y1="-3" x2="4" y2="-3" strokeWidth="0.9" opacity="0.5" />
      <line x1="-8" y1="2" x2="4" y2="2" strokeWidth="0.9" opacity="0.5" />
      <circle cx="6.5" cy="-5.5" r="1.3" fill="currentColor" stroke="none" />
      <circle cx="6.5" cy="-0.5" r="1.3" fill="currentColor" stroke="none" opacity="0.7" />
      <circle cx="6.5" cy="4.5" r="1.3" fill="currentColor" stroke="none" opacity="0.4" />
    </>
  );
}

function SwitchIcon() {
  return (
    <>
      <rect x="-9" y="-4" width="18" height="8" rx="1.5" fill="none" strokeWidth="1.3" />
      {([-6, -3, 0, 3, 6] as const).map((px) => (
        <rect key={px} x={px} y="-7" width="1.8" height="3" rx="0.4" fill="currentColor" stroke="none" opacity="0.6" />
      ))}
    </>
  );
}

function CloudIcon() {
  return (
    <path
      d="M-6,4 Q-9,4 -9,1 Q-9,-3 -5.5,-3 Q-5,-7 0,-6.5 Q5,-7 6,-3 Q9,-3 9,1 Q9,4 5,4 Z"
      fill="none"
      strokeWidth="1.3"
      strokeLinejoin="round"
    />
  );
}

function ContainerIcon() {
  return (
    <>
      <rect x="-8" y="-8" width="16" height="5" rx="1" fill="none" strokeWidth="1.2" />
      <rect x="-8" y="-2" width="16" height="5" rx="1" fill="none" strokeWidth="1.2" />
      <rect x="-8" y="4" width="16" height="5" rx="1" fill="none" strokeWidth="1.2" />
    </>
  );
}

function InterfaceIcon() {
  return (
    <>
      <rect x="-7" y="-7" width="14" height="11" rx="1.5" fill="none" strokeWidth="1.3" />
      <rect x="-5" y="2" width="3.5" height="3.5" rx="0.5" fill="none" strokeWidth="1" />
      <rect x="1.5" y="2" width="3.5" height="3.5" rx="0.5" fill="none" strokeWidth="1" />
    </>
  );
}

function UnknownIcon() {
  return (
    <>
      <rect x="-8" y="-8" width="16" height="16" rx="2" fill="none" strokeWidth="1.3" />
      <text textAnchor="middle" y="3.5" fontSize="10" fontWeight="bold" fill="currentColor" opacity="0.5">?</text>
    </>
  );
}

function DeviceIcon({ nodeType, isCluster }: { nodeType: string; isCluster?: boolean }) {
  if (isCluster) return <ServerClusterIcon />;
  switch (nodeType) {
    case "agent":
    case "gateway":     return <RouterIcon />;
    case "host":        return <HostIcon />;
    case "interface":   return <InterfaceIcon />;
    case "subnet":      return <SwitchIcon />;
    case "service":     return <ServerIcon />;
    case "external_ip": return <CloudIcon />;
    case "docker_network": return <ContainerIcon />;
    default:            return <UnknownIcon />;
  }
}

function ServerClusterIcon() {
  return (
    <>
      <rect x="-9" y="-8" width="12" height="4" rx="1" fill="none" strokeWidth="1.1" />
      <rect x="-9" y="-3" width="12" height="4" rx="1" fill="none" strokeWidth="1.1" />
      <rect x="-9" y="2" width="12" height="4" rx="1" fill="none" strokeWidth="1.1" />
      <circle cx="5.5" cy="-6" r="1.2" fill="currentColor" stroke="none" />
      <circle cx="5.5" cy="-1" r="1.2" fill="currentColor" stroke="none" opacity="0.6" />
      <circle cx="5.5" cy="4" r="1.2" fill="currentColor" stroke="none" opacity="0.35" />
    </>
  );
}

function nodeSubtitle(node: TopologyNode): string {
  if (node.ip) return node.port ? `${node.ip}:${node.port}` : node.ip;
  if (node.cidr) return node.cidr;
  if (node.protocol) return node.protocol.toUpperCase();
  return NODE_TYPE_LABELS[node.node_type] ?? toTitleLabel(node.node_type);
}

function TopologyDeviceNode({ data: rawData }: NodeProps) {
  const data = rawData as unknown as DeviceNodeData;
  const { node, isSelected, isHighlighted, isDimmed, showLabel, importance } = data;
  const visual = nodeVisual(node);
  const hasAlert = node.alert_count > 0;
  const isCluster = node.node_type === "service" && Boolean(node.metadata?._is_service_cluster);
  const clusterCount = isCluster ? Number(node.metadata?._cluster_count ?? 0) : 0;

  const opacity = isDimmed ? 0.16 : node.is_stale && node.node_type !== "agent" ? 0.42 : 1;
  const markerSize = isSelected ? 30 : importance === "anchor" ? 26 : importance === "elevated" ? 22 : 14;
  const iconSize = importance === "normal" ? 0 : importance === "anchor" ? 18 : 15;

  const label = node.label.length > 18 ? `${node.label.slice(0, 16)}…` : node.label;
  const subtitle = isCluster
    ? `${clusterCount} service${clusterCount !== 1 ? "s" : ""}`
    : nodeSubtitle(node).slice(0, 22);

  return (
    <div
      className="group relative flex select-none flex-col items-center justify-center"
      style={{ opacity, width: 76, height: 48 }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

      <div
        className={cx(
          "relative flex items-center justify-center rounded-full transition-all duration-200",
          isSelected && "ring-2 ring-offset-1 ring-offset-[#07111f]",
        )}
        style={{
          width: markerSize,
          height: markerSize,
          background: visual.fill,
          border: `${isSelected ? "1.8px" : importance === "normal" ? "1px" : "1.2px"} solid ${visual.stroke}`,
          color: visual.stroke,
          boxShadow: isSelected
            ? `0 0 20px ${visual.stroke}42`
            : isHighlighted
              ? `0 0 14px ${visual.stroke}30`
              : hasAlert
                ? `0 0 14px ${severityColor(node.severity)}24`
                : "none",
        }}
      >
        {importance === "normal" ? (
          <span
            className="h-[5px] w-[5px] rounded-full"
            style={{ background: visual.stroke }}
          />
        ) : (
          <svg width={iconSize} height={iconSize} viewBox="-12 -12 24 24" stroke="currentColor" fill="none">
            <DeviceIcon nodeType={node.node_type} isCluster={isCluster} />
          </svg>
        )}
      </div>

      {(hasAlert || node.is_stale) && (
        <span
          className="absolute left-1/2 top-[5px] h-[8px] w-[8px] translate-x-[8px] rounded-full border border-[#07111f]"
          style={{
            background:
              node.is_stale && node.node_type === "agent"
                ? "#F97316"
                : hasAlert
                  ? severityColor(node.severity)
                  : "#6B7280",
          }}
        />
      )}

      <div
        className={cx(
          "pointer-events-none absolute top-[36px] w-[76px] text-center leading-none transition-opacity duration-150 group-hover:opacity-100",
          showLabel ? "opacity-100" : "opacity-0",
        )}
      >
        <div
          className="truncate px-0.5 text-[9px] font-semibold"
          style={{ color: visual.stroke }}
        >
          {label}
        </div>
        <div className="truncate px-0.5 text-[8px]" style={{ color: "rgba(148,163,184,0.6)" }}>
          {subtitle}
        </div>
      </div>
    </div>
  );
}

export default memo(TopologyDeviceNode);
