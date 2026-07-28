import { memo } from "react";
import type { NodeProps } from "@xyflow/react";
import { Handle, Position } from "@xyflow/react";

import type { ClusterHaloNodeData } from "../../lib/graph/graphTransform";
import { REGION_HEADER } from "../../lib/layout/layoutContainment";
import { groupTypeMeta } from "../../lib/presentation/groups";
import { severityColor } from "../../lib/presentation/visuals";

const CENTER_HANDLE = {
  opacity: 0,
  left: "50%",
  top: "50%",
  transform: "translate(-50%, -50%)",
  pointerEvents: "none",
} as const;

function TopologyClusterHaloNode({ data: rawData }: NodeProps) {
  const data = rawData as unknown as ClusterHaloNodeData;
  const { group, width, height, isCentral, isSelected, isDimmed, drawnCount } = data;
  const shown = Number(drawnCount ?? 0);
  const total = group.node_count;
  const countLabel = shown > 0 && shown < total ? `${shown}/${total}` : String(total);
  const meta = groupTypeMeta(group.group_type, group.group_key);
  const risky = group.alert_count > 0 || group.risk_score >= 70;
  const accent = risky ? severityColor(group.highest_severity) : isCentral ? "#22D3EE" : meta.color;

  const borderColor = isSelected
    ? `${accent}cc`
    : risky
      ? `${accent}55`
      : isCentral
        ? "rgba(34,211,238,0.34)"
        : "rgba(148,163,184,0.16)";

  return (
    <div
      className="pointer-events-none relative"
      style={{ width, height, opacity: isDimmed ? 0.3 : 1, transition: "opacity 200ms ease" }}
    >
      <Handle type="target" position={Position.Left} style={CENTER_HANDLE} />
      <Handle type="source" position={Position.Right} style={CENTER_HANDLE} />
      <div
        className="absolute inset-0 rounded-xl"
        style={{
          border: `${isSelected ? 1.5 : 1}px solid ${borderColor}`,
          background: risky
            ? `linear-gradient(180deg, ${accent}10 0%, rgba(7,17,31,0) 40%)`
            : isCentral
              ? "linear-gradient(180deg, rgba(34,211,238,0.07) 0%, rgba(7,17,31,0) 38%)"
              : "rgba(148,163,184,0.028)",
          boxShadow: isSelected ? `0 0 0 1px ${accent}55, 0 0 26px ${accent}1f` : "none",
        }}
      />
      <div
        className="absolute inset-x-0 top-0 flex items-center gap-2 px-3"
        style={{ height: REGION_HEADER, pointerEvents: "auto", cursor: "pointer" }}
      >
        <span
          className="shrink-0 rounded-[3px] px-1.5 py-[2px] text-[8.5px] font-bold uppercase tracking-[0.09em]"
          style={{ color: accent, background: `${accent}1c` }}
        >
          {meta.label}
        </span>
        <span
          className="min-w-0 flex-1 truncate text-[12px] font-semibold"
          style={{ color: isSelected || risky ? accent : "rgba(226,232,240,0.94)" }}
          title={group.label}
        >
          {group.label}
        </span>
        {isCentral && (
          <span
            className="shrink-0 rounded-[3px] px-1.5 py-[2px] text-[8px] font-bold uppercase tracking-[0.1em]"
            style={{ color: "#0B1220", background: "#22D3EE" }}
            title="The host running this Seagull sensor"
          >
            This host
          </span>
        )}
        <span
          className="shrink-0 rounded-full px-2 py-[2px] text-[9px] font-semibold tabular-nums"
          style={{ color: "rgba(203,213,225,0.85)", background: "rgba(148,163,184,0.14)" }}
          title={
            shown > 0 && shown < total
              ? `${shown} of ${total} nodes drawn — the rest are collapsed or have no observed link`
              : `${total} nodes in this group`
          }
        >
          {countLabel}
        </span>
        {group.alert_count > 0 && (
          <span
            className="shrink-0 rounded-full px-2 py-[2px] text-[9px] font-bold tabular-nums"
            style={{ color: accent, background: `${accent}22` }}
            title={`${group.alert_count} alerts`}
          >
            {group.alert_count > 99 ? "99+" : group.alert_count} ⚑
          </span>
        )}
      </div>
    </div>
  );
}

export default memo(TopologyClusterHaloNode);
