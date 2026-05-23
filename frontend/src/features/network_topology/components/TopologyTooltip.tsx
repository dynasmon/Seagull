import { memo } from "react";

import { formatTopologyTimestamp, toTitleLabel } from "../lib/labels";
import { severityColor } from "../lib/visuals";
import type { TopologyEdge, TopologyGroup, TopologyNode } from "../types";

export type TooltipInfo =
  | { kind: "node"; node: TopologyNode; x: number; y: number }
  | { kind: "group"; group: TopologyGroup; x: number; y: number }
  | {
      kind: "edge";
      edge: TopologyEdge;
      sourceLabel: string;
      targetLabel: string;
      isBidirectional?: boolean;
      x: number;
      y: number;
    }
  | null;

const TOOLTIP_W = 260;
const OX = 14;
const OY = 8;

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <span className="shrink-0 text-[10px] text-muted-foreground/55">{label}</span>
      <span className="truncate text-right text-[10px] text-foreground/80">{value}</span>
    </div>
  );
}

function RiskBar({ score }: { score: number }) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const sev = clamped >= 80 ? "critical" : clamped >= 60 ? "high" : clamped >= 40 ? "medium" : clamped >= 20 ? "low" : "informational";
  const color = severityColor(sev);
  return (
    <div className="flex items-center gap-2">
      <div
        className="relative h-[4px] w-[80px] overflow-hidden rounded-full"
        style={{ background: "rgba(148,163,184,0.18)" }}
      >
        <div
          className="absolute inset-y-0 left-0 rounded-full"
          style={{ width: `${clamped}%`, background: color }}
        />
      </div>
      <span className="text-[10px] tabular-nums text-foreground/75">{clamped}</span>
    </div>
  );
}

function NodeContent({ node }: { node: TopologyNode }) {
  const sev = node.severity ?? "unknown";
  return (
    <>
      <div className="mb-1.5 truncate text-[11px] font-semibold text-foreground">
        {node.label || node.node_key}
      </div>
      <div className="space-y-0.5">
        <Row label="Type" value={toTitleLabel(node.node_type)} />
        {(node.ip || node.cidr) && <Row label="Address" value={node.ip ?? node.cidr} />}
        {node.port != null && node.protocol && (
          <Row label="Port" value={`${node.port}/${node.protocol.toUpperCase()}`} />
        )}
        {node.agent_id && <Row label="Agent" value={node.agent_id} />}
        <Row label="Severity" value={<span style={{ color: severityColor(sev) }}>{sev}</span>} />
        {node.risk_score > 0 && <Row label="Risk" value={<RiskBar score={node.risk_score} />} />}
        {node.alert_count > 0 && <Row label="Alerts" value={node.alert_count} />}
        {node.event_count > 0 && <Row label="Events" value={node.event_count} />}
        {node.observation_count > 0 && <Row label="Observations" value={node.observation_count} />}
        <Row label="Confidence" value={`${node.confidence}%`} />
        <Row label="First seen" value={formatTopologyTimestamp(node.first_seen_at)} />
        <Row label="Last seen" value={formatTopologyTimestamp(node.last_seen_at)} />
        {node.is_stale && (
          <Row label="Status" value={<span style={{ color: "#F97316" }}>stale</span>} />
        )}
      </div>
    </>
  );
}

function GroupContent({ group }: { group: TopologyGroup }) {
  const sev = group.highest_severity ?? "unknown";
  const firstSeen = (group as TopologyGroup & { first_seen?: string | null }).first_seen ?? null;
  return (
    <>
      <div className="mb-1.5 truncate text-[11px] font-semibold text-foreground">
        {group.label}
      </div>
      <div className="space-y-0.5">
        <Row label="Type" value={toTitleLabel(group.group_type)} />
        <Row label="Nodes" value={group.node_count} />
        {group.alert_count > 0 && <Row label="Alerts" value={group.alert_count} />}
        <Row label="Severity" value={<span style={{ color: severityColor(sev) }}>{sev}</span>} />
        {group.risk_score > 0 && <Row label="Risk score" value={<RiskBar score={group.risk_score} />} />}
        {group.cidr && <Row label="CIDR" value={group.cidr} />}
        {group.group_type === "subnet" && group.gateway_candidate_count != null && (
          <Row label="Gateways" value={group.gateway_candidate_count} />
        )}
        {firstSeen && <Row label="First seen" value={formatTopologyTimestamp(firstSeen)} />}
      </div>
      <div className="mt-1.5 text-[9px] italic text-muted-foreground/45">
        Double-click to explore
      </div>
    </>
  );
}

function EdgeContent({
  edge,
  sourceLabel,
  targetLabel,
  isBidirectional,
}: {
  edge: TopologyEdge;
  sourceLabel: string;
  targetLabel: string;
  isBidirectional?: boolean;
}) {
  const arrow = isBidirectional ? "↔" : "→";
  return (
    <>
      <div className="mb-1 text-[10px]">
        <span className="font-medium text-foreground/80">{sourceLabel}</span>
        <span className="mx-1 text-muted-foreground/40">{arrow}</span>
        <span className="font-medium text-foreground/80">{targetLabel}</span>
      </div>
      <div className="space-y-0.5">
        <Row label="Type" value={toTitleLabel(edge.edge_type)} />
        <Row label="Direction" value={<span className="text-foreground/85">{arrow}</span>} />
        {(edge.port || edge.protocol) && (
          <Row
            label="Protocol"
            value={[edge.protocol?.toUpperCase(), edge.port != null ? String(edge.port) : null]
              .filter(Boolean)
              .join("/")}
          />
        )}
        <Row label="Confidence" value={`${edge.confidence}%`} />
        {edge.event_count > 0 && <Row label="Events" value={edge.event_count} />}
        {edge.alert_count > 0 && <Row label="Alerts" value={edge.alert_count} />}
        <Row label="Last seen" value={formatTopologyTimestamp(edge.last_seen_at)} />
      </div>
    </>
  );
}

function TopologyTooltip({ info }: { info: TooltipInfo }) {
  if (!info) return null;

  const rawLeft = info.x + OX;
  const rawTop = info.y + OY;

  const left =
    typeof window !== "undefined" && rawLeft + TOOLTIP_W > window.innerWidth
      ? info.x - TOOLTIP_W - OX
      : rawLeft;
  const top = Math.max(8, rawTop);

  return (
    <div
      className="pointer-events-none fixed z-[9999] rounded-lg border border-border/50 px-3 py-2.5"
      style={{
        left,
        top,
        width: TOOLTIP_W,
        background: "rgba(10,15,26,0.97)",
        boxShadow: "0 4px 28px rgba(0,0,0,0.55)",
      }}
    >
      {info.kind === "node" && <NodeContent node={info.node} />}
      {info.kind === "group" && <GroupContent group={info.group} />}
      {info.kind === "edge" && (
        <EdgeContent
          edge={info.edge}
          sourceLabel={info.sourceLabel}
          targetLabel={info.targetLabel}
          isBidirectional={info.isBidirectional}
        />
      )}
    </div>
  );
}

export default memo(TopologyTooltip);
