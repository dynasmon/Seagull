import { memo } from "react";

import { formatTopologyTimestamp, toTitleLabel } from "../../lib/presentation/labels";
import { groupTypeMeta } from "../../lib/presentation/groups";
import {
  EDGE_TYPE_LABELS,
  NODE_TYPE_LABELS,
  isAgentAssetNode,
  isExternalNode,
  severityColor,
} from "../../lib/presentation/visuals";
import type { TopologyBundle } from "../../lib/graph/graphTransform";
import type { TopologyEdge, TopologyGroup, TopologyGroupEdge, TopologyNode } from "../../types";

export type TooltipInfo =
  | { kind: "node"; node: TopologyNode; isAgentAsset?: boolean; x: number; y: number }
  | { kind: "group"; group: TopologyGroup; x: number; y: number }
  | {
      kind: "bundle";
      bundle: TopologyBundle;
      isExpanded: boolean;
      x: number;
      y: number;
    }
  | {
      kind: "groupEdge";
      groupEdge: TopologyGroupEdge;
      sourceLabel: string;
      targetLabel: string;
      x: number;
      y: number;
    }
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

const TOOLTIP_W = 272;
const OX = 14;
const OY = 8;

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <span className="shrink-0 text-[10px] text-muted-foreground/55">{label}</span>
      <span className="truncate text-right text-[10px] text-foreground/85">{value}</span>
    </div>
  );
}

function Chip({ text, color }: { text: string; color: string }) {
  return (
    <span
      className="rounded-[3px] px-1.5 py-[1px] text-[8.5px] font-bold uppercase tracking-[0.08em]"
      style={{ color, background: `${color}20` }}
    >
      {text}
    </span>
  );
}

function RiskBar({ score }: { score: number }) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const severity =
    clamped >= 80 ? "critical" : clamped >= 60 ? "high" : clamped >= 40 ? "medium" : "low";
  return (
    <span className="inline-flex items-center gap-2">
      <span
        className="relative inline-block h-[4px] w-[72px] overflow-hidden rounded-full align-middle"
        style={{ background: "rgba(148,163,184,0.18)" }}
      >
        <span
          className="absolute inset-y-0 left-0 rounded-full"
          style={{ width: `${clamped}%`, background: severityColor(severity) }}
        />
      </span>
      <span className="tabular-nums">{clamped}</span>
    </span>
  );
}

function NodeContent({ node, isAgentAsset }: { node: TopologyNode; isAgentAsset?: boolean }) {
  const severity = node.severity ?? "unknown";
  const external = isExternalNode(node);
  const selfAsset = isAgentAsset ?? isAgentAssetNode(node);
  const peerDeviation = node.metadata?.peer_group_deviation as Record<string, unknown> | undefined;

  return (
    <>
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        {selfAsset && <Chip text="This host" color="#22D3EE" />}
        {external && <Chip text="Internet" color="#94A3B8" />}
        {node.is_stale && <Chip text="Stale" color="#F97316" />}
      </div>
      <div className="mb-1.5 truncate text-[11px] font-semibold text-foreground" title={node.label}>
        {node.label || node.node_key}
      </div>
      <div className="space-y-0.5">
        <Row label="Type" value={NODE_TYPE_LABELS[node.node_type] ?? toTitleLabel(node.node_type)} />
        {(node.ip || node.cidr) && <Row label="Address" value={node.ip ?? node.cidr} />}
        {node.port != null && <Row label="Port" value={`${node.port}/${String(node.protocol ?? "tcp").toUpperCase()}`} />}
        {node.agent_id && <Row label="Reported by" value={node.agent_id} />}
        {!node.agent_id && typeof node.metadata?.observed_by_agent_id === "string" && (
          <Row label="Observed by" value={String(node.metadata.observed_by_agent_id)} />
        )}
        <Row
          label="Severity"
          value={<span style={{ color: severityColor(severity) }}>{severity}</span>}
        />
        {node.risk_score > 0 && <Row label="Risk" value={<RiskBar score={node.risk_score} />} />}
        {peerDeviation && (
          <Row
            label="Peer deviation"
            value={
              <span style={{ color: severityColor(String(peerDeviation.severity ?? severity)) }}>
                {String(peerDeviation.risk_score ?? node.risk_score)}
              </span>
            }
          />
        )}
        {node.alert_count > 0 && <Row label="Alerts" value={node.alert_count} />}
        {node.event_count > 0 && <Row label="Events" value={node.event_count} />}
        <Row label="Confidence" value={`${node.confidence}%`} />
        <Row label="Last seen" value={formatTopologyTimestamp(node.last_seen_at)} />
      </div>
      <div className="mt-1.5 text-[9px] italic text-muted-foreground/45">
        Click for evidence · right-click for actions
      </div>
    </>
  );
}

function GroupContent({ group }: { group: TopologyGroup }) {
  const severity = group.highest_severity ?? "unknown";
  const meta = groupTypeMeta(group.group_type, group.group_key);
  const firstSeen = (group as TopologyGroup & { first_seen?: string | null }).first_seen ?? null;
  return (
    <>
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <Chip text={meta.label} color={meta.color} />
      </div>
      <div className="mb-1 truncate text-[11px] font-semibold text-foreground" title={group.label}>
        {group.label}
      </div>
      <div className="mb-1.5 text-[9.5px] leading-snug text-muted-foreground/70">{meta.description}</div>
      <div className="space-y-0.5">
        <Row label="Nodes" value={group.node_count} />
        {group.alert_count > 0 && <Row label="Alerts" value={group.alert_count} />}
        <Row
          label="Highest severity"
          value={<span style={{ color: severityColor(severity) }}>{severity}</span>}
        />
        {group.risk_score > 0 && <Row label="Risk" value={<RiskBar score={group.risk_score} />} />}
        {group.cidr && <Row label="CIDR" value={group.cidr} />}
        {group.group_type === "subnet" && group.gateway_candidate_count != null && (
          <Row label="Gateways" value={group.gateway_candidate_count} />
        )}
        {firstSeen && <Row label="First seen" value={formatTopologyTimestamp(firstSeen)} />}
      </div>
      <div className="mt-1.5 text-[9px] italic text-muted-foreground/45">
        Click for detail · double-click to open in Connection
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
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <Chip
          text={EDGE_TYPE_LABELS[edge.edge_type] ?? toTitleLabel(edge.edge_type)}
          color={severityColor(edge.alert_count > 0 ? edge.severity : "unknown")}
        />
      </div>
      <div className="mb-1.5 text-[10px]">
        <span className="font-medium text-foreground/85">{sourceLabel}</span>
        <span className="mx-1 text-muted-foreground/45">{arrow}</span>
        <span className="font-medium text-foreground/85">{targetLabel}</span>
      </div>
      <div className="space-y-0.5">
        <Row label="Direction" value={isBidirectional ? "Both ways" : "One way"} />
        {(edge.port || edge.protocol) && (
          <Row
            label="Protocol"
            value={[edge.protocol?.toUpperCase(), edge.port != null ? String(edge.port) : null]
              .filter(Boolean)
              .join("/")}
          />
        )}
        {edge.event_count > 0 && <Row label="Events" value={edge.event_count} />}
        {edge.alert_count > 0 && <Row label="Alerts" value={edge.alert_count} />}
        <Row label="Confidence" value={`${edge.confidence}%`} />
        <Row label="Last seen" value={formatTopologyTimestamp(edge.last_seen_at)} />
      </div>
    </>
  );
}

function GroupEdgeContent({
  groupEdge,
  sourceLabel,
  targetLabel,
}: {
  groupEdge: TopologyGroupEdge;
  sourceLabel: string;
  targetLabel: string;
}) {
  const counts = groupEdge.edge_type_counts ?? {};
  const breakdown = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const total = breakdown.reduce((sum, [, count]) => sum + count, 0);
  return (
    <>
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <Chip
          text="Group link"
          color={severityColor(groupEdge.alert_count > 0 ? groupEdge.severity : "unknown")}
        />
      </div>
      <div className="mb-1.5 text-[10px]">
        <span className="font-medium text-foreground/85">{sourceLabel}</span>
        <span className="mx-1 text-muted-foreground/45">↔</span>
        <span className="font-medium text-foreground/85">{targetLabel}</span>
      </div>
      <div className="space-y-0.5">
        <Row label="Relationships" value={total || groupEdge.event_count} />
        {breakdown.map(([type, count]) => (
          <Row key={type} label={EDGE_TYPE_LABELS[type] ?? toTitleLabel(type)} value={count} />
        ))}
        {groupEdge.alert_count > 0 && <Row label="Alerts" value={groupEdge.alert_count} />}
      </div>
    </>
  );
}

function BundleContent({ bundle, isExpanded }: { bundle: TopologyBundle; isExpanded: boolean }) {
  const breakdown = Object.entries(bundle.typeCounts).sort((a, b) => b[1] - a[1]);
  return (
    <>
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <Chip
          text="Bundled links"
          color={severityColor(bundle.alertCount > 0 ? bundle.severity : "unknown")}
        />
      </div>
      <div className="mb-1.5 text-[10px]">
        <span className="font-medium text-foreground/85">{bundle.sourceLabel}</span>
        <span className="mx-1 text-muted-foreground/45">↔</span>
        <span className="font-medium text-foreground/85">{bundle.targetLabel}</span>
      </div>
      <div className="space-y-0.5">
        <Row label="Relationships" value={bundle.linkCount} />
        {breakdown.map(([type, count]) => (
          <Row key={type} label={EDGE_TYPE_LABELS[type] ?? toTitleLabel(type)} value={count} />
        ))}
        {bundle.eventCount > 0 && <Row label="Events" value={bundle.eventCount} />}
        {bundle.alertCount > 0 && <Row label="Alerts" value={bundle.alertCount} />}
      </div>
      <div className="mt-1.5 text-[9px] italic text-muted-foreground/45">
        {isExpanded ? "Click to bundle these links again" : "Click to draw each link separately"}
      </div>
    </>
  );
}

function TopologyTooltip({ info }: { info: TooltipInfo }) {
  if (!info) return null;

  const rawLeft = info.x + OX;
  const left =
    typeof window !== "undefined" && rawLeft + TOOLTIP_W > window.innerWidth
      ? info.x - TOOLTIP_W - OX
      : rawLeft;
  const top = Math.max(8, info.y + OY);

  return (
    <div
      className="pointer-events-none fixed z-[9999] rounded-lg border border-border/50 px-3 py-2.5"
      style={{
        left,
        top,
        width: TOOLTIP_W,
        background: "rgba(10,15,26,0.98)",
        boxShadow: "0 4px 28px rgba(0,0,0,0.55)",
      }}
    >
      {info.kind === "node" && <NodeContent node={info.node} isAgentAsset={info.isAgentAsset} />}
      {info.kind === "group" && <GroupContent group={info.group} />}
      {info.kind === "bundle" && <BundleContent bundle={info.bundle} isExpanded={info.isExpanded} />}
      {info.kind === "groupEdge" && (
        <GroupEdgeContent
          groupEdge={info.groupEdge}
          sourceLabel={info.sourceLabel}
          targetLabel={info.targetLabel}
        />
      )}
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
