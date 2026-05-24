import { memo } from "react";
import type { NodeProps } from "@xyflow/react";

import type { ClusterHaloNodeData } from "../lib/graphTransform";
import { REGION_HEADER } from "../lib/layoutContainment";
import { severityColor } from "../lib/visuals";

function groupTypeLabel(groupType: string): string {
  if (groupType === "agent") return "Agent";
  if (groupType === "subnet") return "Subnet";
  if (groupType === "scope" || groupType === "ip_scope") return "Scope";
  if (groupType === "ungrouped") return "Unassigned";
  return "Group";
}

function TopologyClusterHaloNode({ data: rawData }: NodeProps) {
  const data = rawData as unknown as ClusterHaloNodeData;
  const { group, width, height, isCentral, isSelected, isDimmed } = data;
  const risky = group.alert_count > 0 || group.risk_score >= 70;
  const accent = risky ? severityColor(group.highest_severity) : isCentral ? "#7DD3FC" : "#60A5FA";

  const borderColor = isSelected
    ? `${accent}cc`
    : risky
      ? `${accent}55`
      : isCentral
        ? "rgba(125,211,252,0.34)"
        : "rgba(96,165,250,0.18)";
  const borderWidth = isSelected ? 1.5 : isCentral ? 1.25 : 1;
  const boxShadow = isSelected
    ? `0 0 0 1px ${accent}55, 0 0 28px ${accent}1f`
    : risky
      ? `0 0 22px ${accent}14`
      : "none";

  return (
    <div
      className="pointer-events-none relative"
      style={{ width, height, opacity: isDimmed ? 0.07 : 1, transition: "opacity 200ms ease" }}
    >
      <div
        className="absolute inset-0 rounded-2xl"
        style={{
          border: `${borderWidth}px solid ${borderColor}`,
          background: risky
            ? `linear-gradient(180deg, ${accent}0d 0%, rgba(7,14,25,0) 45%)`
            : isCentral
              ? "linear-gradient(180deg, rgba(125,211,252,0.06) 0%, rgba(7,14,25,0) 42%)"
              : "rgba(96,165,250,0.025)",
          boxShadow,
        }}
      />
      <div
        className="absolute inset-x-0 top-0 flex items-center gap-2 px-4"
        style={{ height: REGION_HEADER, pointerEvents: "auto", cursor: "pointer" }}
      >
        <span
          className="shrink-0 rounded-[3px] px-1.5 py-[2px] text-[8.5px] font-bold uppercase tracking-[0.08em]"
          style={{
            color: risky ? accent : isCentral ? "#7DD3FC" : "rgba(148,163,184,0.78)",
            background: risky ? `${accent}1c` : isCentral ? "rgba(125,211,252,0.12)" : "rgba(148,163,184,0.1)",
          }}
        >
          {groupTypeLabel(group.group_type)}
        </span>
        <span
          className="min-w-0 flex-1 truncate text-[12px] font-semibold"
          style={{ color: isSelected || risky ? accent : "rgba(226,232,240,0.92)" }}
          title={group.label}
        >
          {group.label}
        </span>
        {isCentral && !risky && (
          <span
            className="shrink-0 rounded-[3px] px-1.5 py-[2px] text-[8px] font-bold uppercase tracking-[0.1em]"
            style={{ color: "#7DD3FC", background: "rgba(125,211,252,0.14)" }}
          >
            Local
          </span>
        )}
        <span
          className="shrink-0 rounded-full px-2 py-[2px] text-[9px] font-bold tabular-nums"
          style={{
            color: risky ? accent : "#60A5FA",
            background: risky ? `${accent}20` : "rgba(96,165,250,0.14)",
          }}
        >
          {group.node_count}
        </span>
        {group.alert_count > 0 && (
          <span
            className="shrink-0 rounded-full px-2 py-[2px] text-[9px] font-bold tabular-nums"
            style={{ color: accent, background: `${accent}22` }}
          >
            {group.alert_count > 99 ? "99+" : group.alert_count}⚑
          </span>
        )}
      </div>
    </div>
  );
}

export default memo(TopologyClusterHaloNode);
