import { memo } from "react";
import type { NodeProps } from "@xyflow/react";
import { Handle, Position } from "@xyflow/react";

import type { GroupNodeData } from "../../lib/graph/graphTransform";
import { groupTypeMeta } from "../../lib/presentation/groups";
import { severityColor } from "../../lib/presentation/visuals";

const CENTER_HANDLE = {
  opacity: 0,
  left: "50%",
  top: "50%",
  transform: "translate(-50%, -50%)",
  pointerEvents: "none",
} as const;

function riskTone(score: number): string {
  if (score >= 80) return severityColor("critical");
  if (score >= 60) return severityColor("high");
  if (score >= 40) return severityColor("medium");
  return severityColor("low");
}

function Metric({ value, label, tone }: { value: number | string; label: string; tone?: string }) {
  return (
    <div className="flex min-w-0 flex-col leading-none">
      <span
        className="text-[13px] font-semibold tabular-nums"
        style={{ color: tone ?? "rgba(226,232,240,0.92)" }}
      >
        {value}
      </span>
      <span
        className="mt-[3px] truncate text-[8.5px] uppercase tracking-[0.09em]"
        style={{ color: "rgba(148,163,184,0.6)" }}
      >
        {label}
      </span>
    </div>
  );
}

function TopologyGroupNode({ data: rawData }: NodeProps) {
  const data = rawData as unknown as GroupNodeData;
  const { group, isSelected, isHighlighted, isDimmed, isCentral } = data;
  const meta = groupTypeMeta(group.group_type, group.group_key);
  const risky = group.alert_count > 0 || group.risk_score >= 70;
  const accent = risky ? severityColor(group.highest_severity) : isCentral ? "#22D3EE" : meta.color;
  const opacity = isDimmed ? 0.26 : group.is_stale ? 0.55 : 1;
  const riskScore = Math.max(0, Math.min(100, Math.round(group.risk_score || 0)));
  const externalCount = Number(data.externalCount ?? 0);
  const serviceCount = Number(data.serviceCount ?? 0);
  const linkCount = Number(data.linkCount ?? 0);

  return (
    <div className="relative h-full w-full select-none transition-opacity" style={{ opacity }}>
      <Handle type="target" position={Position.Left} style={CENTER_HANDLE} />
      <Handle type="source" position={Position.Right} style={CENTER_HANDLE} />

      <div
        className="relative flex h-full w-full flex-col overflow-hidden rounded-xl border"
        style={{
          background: risky
            ? `linear-gradient(180deg, ${accent}12 0%, rgba(10,18,32,0.96) 55%)`
            : isCentral
              ? "linear-gradient(180deg, rgba(34,211,238,0.10) 0%, rgba(10,18,32,0.96) 55%)"
              : "rgba(10,18,32,0.94)",
          borderColor: isSelected
            ? accent
            : risky
              ? `${accent}55`
              : isCentral
                ? "rgba(34,211,238,0.42)"
                : "rgba(148,163,184,0.18)",
          boxShadow: isSelected
            ? `0 0 0 1px ${accent}, 0 0 24px ${accent}33`
            : isHighlighted || risky || isCentral
              ? `0 0 16px ${accent}1e`
              : "none",
        }}
      >
        <div
          className="flex items-center gap-1.5 border-b px-2.5 pb-1.5 pt-2"
          style={{ borderColor: "rgba(148,163,184,0.12)" }}
        >
          <span
            className="shrink-0 rounded-[3px] px-1.5 py-[2px] text-[8px] font-bold uppercase tracking-[0.09em]"
            style={{ color: accent, background: `${accent}1c` }}
          >
            {meta.label}
          </span>
          <span
            className="min-w-0 flex-1 truncate text-[12px] font-semibold"
            style={{ color: isSelected ? accent : "rgba(226,232,240,0.94)" }}
            title={`${group.label} — ${meta.description}`}
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
          {group.is_stale && (
            <span
              className="shrink-0 rounded-[3px] px-1.5 py-[2px] text-[8px] font-bold uppercase tracking-[0.1em]"
              style={{ color: "#F97316", background: "rgba(249,115,22,0.14)" }}
            >
              Stale
            </span>
          )}
        </div>

        <div className="flex flex-1 items-center gap-3 px-2.5 py-1.5">
          <Metric value={group.node_count} label="nodes" />
          {serviceCount > 0 && <Metric value={serviceCount} label="services" />}
          {externalCount > 0 && <Metric value={externalCount} label="external" />}
          <Metric value={linkCount} label="links" />
          <Metric
            value={group.alert_count}
            label="alerts"
            tone={group.alert_count > 0 ? severityColor(group.highest_severity) : undefined}
          />
        </div>

        <div className="flex items-center gap-2 px-2.5 pb-2">
          <div
            className="relative h-[3px] flex-1 overflow-hidden rounded-full"
            style={{ background: "rgba(148,163,184,0.16)" }}
          >
            <div
              className="absolute inset-y-0 left-0 rounded-full"
              style={{ width: `${Math.max(riskScore, 2)}%`, background: riskTone(riskScore) }}
            />
          </div>
          <span
            className="shrink-0 text-[8.5px] uppercase tracking-[0.08em] tabular-nums"
            style={{ color: "rgba(148,163,184,0.62)" }}
            title="Highest risk score among the nodes in this group"
          >
            risk {riskScore}
          </span>
        </div>
      </div>
    </div>
  );
}

export default memo(TopologyGroupNode);
