import { memo } from "react";
import type { NodeProps } from "@xyflow/react";
import { Handle, Position } from "@xyflow/react";

import { cx } from "@/shared/lib/cx";

import type { GroupNodeData } from "../lib/graphTransform";
import { nodeVisualByType, severityColor } from "../lib/visuals";

function groupSymbol(groupType: string): string {
  if (groupType === "agent") return "◎";
  if (groupType === "subnet") return "⌁";
  if (groupType === "scope" || groupType === "ip_scope") return "◌";
  return "•";
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
  const opacity = isDimmed ? 0.18 : group.is_stale ? 0.48 : 1;
  const label = group.label.length > 24 ? `${group.label.slice(0, 22)}…` : group.label;

  return (
    <div
      className="relative flex h-[52px] w-[148px] select-none items-center gap-2 transition-opacity"
      style={{ opacity, background: "transparent", border: "none", boxShadow: "none" }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

      <div
        className={cx(
          "relative flex h-9 w-9 shrink-0 items-center justify-center rounded-full border transition-all",
          isSelected && "ring-2 ring-offset-2 ring-offset-[#07111f]",
        )}
        style={{
          color: accent,
          borderColor: isSelected ? accent : risky ? `${accent}b8` : `${visual.stroke}8a`,
          background: risky ? `${accent}16` : visual.fill,
          boxShadow: isSelected
            ? `0 0 22px ${accent}3d`
            : risky || isHighlighted
              ? `0 0 18px ${accent}25`
              : "none",
        }}
      >
        <span className="text-[17px] leading-none">{groupSymbol(group.group_type)}</span>
        {risky && (
          <span
            className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full border border-[#07111f]"
            style={{ background: accent }}
          />
        )}
      </div>

      <div className="min-w-0">
        <div className="truncate text-[11px] font-medium text-foreground/92" title={group.label}>
          {label}
        </div>
        <div className="mt-0.5 flex items-center gap-1.5 text-[10px] text-muted-foreground/62">
          <span>{group.node_count} node{group.node_count === 1 ? "" : "s"}</span>
          {group.alert_count > 0 && (
            <>
              <span className="text-muted-foreground/30">·</span>
              <span style={{ color: accent }}>{group.alert_count} alert{group.alert_count === 1 ? "" : "s"}</span>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default memo(TopologyGroupNode);
