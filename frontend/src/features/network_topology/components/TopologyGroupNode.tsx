import { memo } from "react";
import type { NodeProps } from "@xyflow/react";
import { Handle, Position } from "@xyflow/react";

import type { GroupNodeData } from "../lib/graphTransform";
import { nodeVisualByType, severityColor } from "../lib/visuals";

function groupSymbol(groupType: string): string {
  if (groupType === "agent") return "◎";
  if (groupType === "subnet") return "⌁";
  if (groupType === "scope" || groupType === "ip_scope") return "◌";
  return "◦";
}

function groupTypeLabel(groupType: string): string {
  if (groupType === "agent") return "Agent";
  if (groupType === "subnet") return "Subnet";
  if (groupType === "scope" || groupType === "ip_scope") return "Scope";
  return "Group";
}

function riskTone(score: number): string {
  if (score >= 80) return severityColor("critical");
  if (score >= 60) return severityColor("high");
  if (score >= 40) return severityColor("medium");
  if (score >= 20) return severityColor("low");
  return severityColor("informational");
}

function TopologyGroupNode({ data: rawData }: NodeProps) {
  const data = rawData as unknown as GroupNodeData;
  const { group, isSelected, isHighlighted, isDimmed } = data;
  const visual = nodeVisualByType(
    group.group_type === "agent" ? "agent" :
    group.group_type === "subnet" ? "subnet" : "unknown",
  );
  const risky = group.alert_count > 0 || group.risk_score >= 70;
  const accent = risky ? severityColor(group.highest_severity) : visual.stroke;
  const opacity = isDimmed ? 0.15 : group.is_stale ? 0.45 : 1;
  const bottomBorderColor =
    group.alert_count > 0 ? severityColor(group.highest_severity) : "rgba(96,165,250,0.18)";
  const riskScore = Math.max(0, Math.min(100, Math.round(group.risk_score || 0)));
  const showRiskBar = riskScore > 0;

  return (
    <div className="relative h-full w-full select-none transition-opacity" style={{ opacity }}>
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

      <div
        className="relative flex h-full w-full items-center gap-2 overflow-hidden rounded-xl border px-2 py-1"
        style={{
          background: risky ? `${accent}0d` : "rgba(10,18,32,0.94)",
          borderColor: isSelected ? accent : risky ? `${accent}50` : `${visual.stroke}28`,
          borderBottomWidth: 3,
          borderBottomColor: bottomBorderColor,
          boxShadow: isSelected
            ? `0 0 22px ${accent}32, inset 0 0 0 0.5px ${accent}28, 0 0 0 1px ${accent}`
            : risky || isHighlighted
              ? `0 0 14px ${accent}1e`
              : "none",
        }}
      >
        <div
          className="relative flex h-7 w-7 shrink-0 items-center justify-center rounded-full border"
          style={{
            color: accent,
            borderColor: risky ? `${accent}70` : `${visual.stroke}48`,
            background: risky ? `${accent}1c` : visual.fill,
          }}
        >
          <span className="text-[13px] leading-none">{groupSymbol(group.group_type)}</span>
          {risky && (
            <span
              className="absolute -right-[1px] -top-[1px] h-[7px] w-[7px] rounded-full border-[1.5px] border-[#07111f]"
              style={{ background: accent }}
            />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div
            className="truncate text-[11px] font-semibold leading-tight"
            style={{ color: isSelected ? accent : "rgba(226,232,240,0.92)" }}
            title={group.label}
          >
            {group.label}
          </div>
          {showRiskBar && (
            <div className="mt-[3px] flex items-center gap-1.5">
              <div
                className="relative h-[3px] flex-1 overflow-hidden rounded-full"
                style={{ background: "rgba(148,163,184,0.15)" }}
              >
                <div
                  className="absolute inset-y-0 left-0 rounded-full"
                  style={{ width: `${riskScore}%`, background: riskTone(riskScore) }}
                />
              </div>
              <span className="shrink-0 text-[8.5px] tabular-nums" style={{ color: "rgba(148,163,184,0.65)" }}>
                {riskScore}
              </span>
            </div>
          )}
          <div
            className="mt-[3px] truncate text-[9px]"
            style={{ color: "rgba(148,163,184,0.55)" }}
          >
            {groupTypeLabel(group.group_type)} · {group.node_count} {group.node_count === 1 ? "node" : "nodes"}
            {group.alert_count > 0 && (
              <>
                {" · "}
                <span style={{ color: accent, fontWeight: 600 }}>
                  {group.alert_count} {group.alert_count === 1 ? "alert" : "alerts"}
                </span>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default memo(TopologyGroupNode);
