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
      className="pointer-events-none relative rounded-full"
      style={{
        width: size,
        height: size,
        opacity: isDimmed ? 0.04 : 1,
        transition: "opacity 200ms ease",
      }}
    >
      <div
        className="absolute inset-0 rounded-full"
        style={{
          border: `${isSelected ? "2px" : "1px"} solid ${isSelected ? `${accent}88` : risky ? `${accent}40` : "rgba(96,165,250,0.18)"}`,
          boxShadow: isSelected
            ? `0 0 32px ${accent}28, inset 0 0 32px ${accent}08`
            : risky
              ? `0 0 20px ${accent}14`
              : "none",
        }}
      />
      <div
        className="absolute rounded-full"
        style={{
          inset: size * 0.075,
          border: `1px dashed ${risky ? `${accent}20` : "rgba(96,165,250,0.08)"}`,
        }}
      />
      <div
        className="absolute inset-0 rounded-full"
        style={{
          background: `radial-gradient(circle at 50% 40%, ${risky ? `${accent}10` : "rgba(96,165,250,0.05)"} 0%, transparent 70%)`,
        }}
      />
      <div
        className="absolute left-1/2 top-5 -translate-x-1/2 flex items-center gap-1.5 rounded-full border px-3 py-1"
        style={{
          color: risky ? accent : "rgba(148,163,184,0.75)",
          background: "rgba(7,14,25,0.85)",
          borderColor: risky ? `${accent}35` : "rgba(148,163,184,0.12)",
          backdropFilter: "blur(4px)",
          whiteSpace: "nowrap",
          fontSize: 11,
          fontWeight: 600,
          maxWidth: radius * 1.4,
        }}
      >
        <span className="truncate">{group.label}</span>
        <span
          className="shrink-0 rounded-full px-1.5 py-0.5 text-[9px] font-bold"
          style={{
            background: risky ? `${accent}25` : "rgba(96,165,250,0.15)",
            color: risky ? accent : "#60A5FA",
          }}
        >
          {group.node_count}
        </span>
        {group.alert_count > 0 && (
          <span
            className="shrink-0 rounded-full px-1.5 py-0.5 text-[9px] font-bold"
            style={{ background: `${accent}25`, color: accent }}
          >
            {group.alert_count}⚑
          </span>
        )}
      </div>
    </div>
  );
}

export default memo(TopologyClusterHaloNode);
