import { memo } from "react";
import type { NodeProps } from "@xyflow/react";

import type { ClusterHaloNodeData } from "../lib/graphTransform";
import { severityColor } from "../lib/visuals";

function TopologyClusterHaloNode({ data: rawData }: NodeProps) {
  const data = rawData as unknown as ClusterHaloNodeData;
  const { group, radius, isSelected, isDimmed } = data;
  const risky = group.alert_count > 0 || group.risk_score >= 70;
  const accent = risky ? severityColor(group.highest_severity) : "#60A5FA";
  const size = radius * 2;

  return (
    <div
      className="pointer-events-none relative rounded-full transition-opacity"
      style={{
        width: size,
        height: size,
        opacity: isDimmed ? 0.05 : isSelected ? 0.88 : 0.68,
        border: `1px solid ${isSelected ? `${accent}66` : risky ? `${accent}2e` : "rgba(96,165,250,0.1)"}`,
        background: `radial-gradient(circle, ${risky ? `${accent}0d` : "rgba(96,165,250,0.04)"} 0%, rgba(7,14,25,0) 68%)`,
        boxShadow: isSelected
          ? `0 0 28px ${accent}20`
          : risky
            ? `0 0 18px ${accent}0e`
            : "none",
      }}
    >
      <div
        className="absolute left-1/2 top-3 -translate-x-1/2 max-w-[144px] truncate rounded-full border px-2 py-0.5 text-[10px]"
        style={{
          color: risky ? accent : "rgba(148,163,184,0.65)",
          background: "rgba(7,14,25,0.78)",
          borderColor: risky ? `${accent}28` : "rgba(148,163,184,0.1)",
        }}
      >
        {group.label} · {group.node_count}
      </div>
    </div>
  );
}

export default memo(TopologyClusterHaloNode);
