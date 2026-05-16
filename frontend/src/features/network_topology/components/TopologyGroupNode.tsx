import { memo } from "react";
import type { NodeProps } from "@xyflow/react";
import { Handle, Position } from "@xyflow/react";

import { cx } from "@/shared/lib/cx";

import type { GroupNodeData } from "../lib/graphTransform";
import { nodeVisualByType, severityColor } from "../lib/visuals";

function TopologyGroupNode({ data: rawData }: NodeProps) {
  const data = rawData as unknown as GroupNodeData;
  const { group, isSelected, isDimmed } = data;

  const visual = nodeVisualByType(
    group.group_type === "agent" ? "agent" :
    group.group_type === "subnet" ? "subnet" : "unknown",
  );

  const opacity = isDimmed ? 0.22 : group.is_stale ? 0.55 : 1;
  const hasSevere = group.alert_count > 0;
  const sevColor = severityColor(group.highest_severity);

  const labelTrunc = group.label.length > 28 ? `${group.label.slice(0, 26)}…` : group.label;

  return (
    <div
      className={cx(
        "relative flex select-none flex-col justify-between rounded-[8px] px-3 py-2 transition-all",
        isSelected && "ring-1",
      )}
      style={{
        width: 168,
        height: 88,
        opacity,
        background: `linear-gradient(135deg, ${visual.fill} 0%, rgba(15,23,42,0.55) 100%)`,
        border: `${isSelected ? "1.5px" : "1px"} solid ${visual.stroke}`,
        color: visual.stroke,
        boxShadow: isSelected
          ? `0 0 14px 2px ${visual.stroke}33`
          : hasSevere
            ? `0 0 8px 1px ${sevColor}22`
            : "none",
      }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

      <div>
        <div
          className="truncate text-[11px] font-bold tracking-tight"
          style={{ color: visual.stroke }}
          title={group.label}
        >
          {labelTrunc}
        </div>
        <div className="mt-0.5 text-[9px]" style={{ color: "rgba(148,163,184,0.65)" }}>
          {group.group_type === "agent" && "Agent group"}
          {group.group_type === "subnet" && (group.cidr ?? "Subnet")}
          {(group.group_type === "scope" || group.group_type === "ip_scope") && "IP scope"}
          {group.group_type === "ungrouped" && "Ungrouped"}
        </div>
      </div>

      <div className="flex items-end justify-between">
        <div className="flex items-baseline gap-2">
          <span className="text-[18px] font-bold leading-none" style={{ color: visual.stroke }}>
            {group.node_count}
          </span>
          <span className="text-[9px]" style={{ color: "rgba(148,163,184,0.55)" }}>
            node{group.node_count !== 1 ? "s" : ""}
          </span>
        </div>

        {hasSevere && (
          <div
            className="flex items-center gap-1 rounded-[4px] px-1.5 py-0.5"
            style={{ background: `${sevColor}22`, border: `1px solid ${sevColor}55` }}
          >
            <span className="h-[6px] w-[6px] rounded-full" style={{ background: sevColor }} />
            <span className="text-[9px] font-semibold" style={{ color: sevColor }}>
              {group.alert_count}
            </span>
          </div>
        )}

        {group.is_stale && (
          <span
            className="rounded-[4px] px-1.5 py-0.5 text-[9px]"
            style={{ background: "rgba(107,114,128,0.2)", color: "#9CA3AF", border: "1px solid rgba(107,114,128,0.4)" }}
          >
            stale
          </span>
        )}
      </div>
    </div>
  );
}

export default memo(TopologyGroupNode);
