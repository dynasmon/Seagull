import { useMemo, useState, type ReactNode } from "react";

import Drawer from "@/shared/components/Drawer";
import { Badge } from "@/shared/components/Badge";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { JsonBlock } from "@/shared/components/JsonBlock";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationFactCard,
  InvestigationListItem,
  InvestigationMetaStrip,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
} from "@/shared/components/investigation";
import PinToWorkspaceDrawer from "@/features/investigations/PinToWorkspaceDrawer";
import { pinAttackChainCaseToWorkspace, pinEventToWorkspace } from "@/features/investigations/api";

import { TopologyIpScopeBadge } from "./TopologyIpScopeBadge";
import { formatTopologyTimestamp, toTitleLabel, topologySeverityVariant } from "../lib/labels";
import { severityColor } from "../lib/visuals";
import {
  alertPivotUrl,
  attackChainCasePivotUrl,
  buildExposureAssetPivotUrl,
  buildInventoryPivotUrl,
  edgeAlertsPivot,
  edgeEventsPivot,
  exposureFindingPivotUrl,
  flowPivotUrl,
  nodeAlertsPivot,
  nodeAssetKey,
  nodeEventsPivot,
  nodePrimaryIp,
  observationPivotUrl,
} from "../lib/pivots";
import type {
  TopologyEdge,
  TopologyEdgeDetail,
  TopologyGroup,
  TopologyGroupDetail,
  TopologyNode,
  TopologyNodeDetail,
  TopologyObservation,
  TopologyRelatedAlert,
  TopologyRelatedAttackChainCase,
  TopologyRelatedExposureFinding,
  TopologyRelatedFlow,
  TopologySubnetDetail,
} from "../types";

export type NetworkTopologyDetailSelection =
  | { kind: "node"; key: string; detail: TopologyNodeDetail | null; loading: boolean; error: string | null }
  | { kind: "edge"; key: string; detail: TopologyEdgeDetail | null; loading: boolean; error: string | null }
  | {
      kind: "group";
      key: string;
      group: TopologyGroup;
      memberNodes: TopologyNode[];
      backendDetail: TopologyGroupDetail | null;
      backendDetailLoading: boolean;
      backendDetailError: string | null;
      subnetCidr: string | null;
      subnetDetail: TopologySubnetDetail | null;
      subnetDetailLoading: boolean;
      subnetDetailError: string | null;
      onExploreInConnection: () => void;
    }
  | null;

type PinTarget =
  | { kind: "event"; id: number; title: string; agentId?: string | null }
  | { kind: "attack_chain_case"; id: number; title: string; agentId?: string | null }
  | null;

function text(value: unknown): string {
  return String(value ?? "").trim();
}

function formatCount(value: number | null | undefined): string {
  const n = Number(value ?? 0);
  if (!Number.isFinite(n)) return "0";
  return new Intl.NumberFormat().format(n);
}

function formatBytes(value: number | null | undefined): string {
  const n = Number(value ?? 0);
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let current = n;
  let unit = 0;
  while (current >= 1024 && unit < units.length - 1) {
    current /= 1024;
    unit += 1;
  }
  return `${current >= 10 || unit === 0 ? current.toFixed(0) : current.toFixed(1)} ${units[unit]}`;
}

function portLabel(port?: number | null, protocol?: string | null): string {
  if (typeof port !== "number") return protocol ? String(protocol).toUpperCase() : "-";
  return `${port}${protocol ? `/${String(protocol).toUpperCase()}` : ""}`;
}

function endpointLabel(ip?: string | null, port?: number | null): string {
  const value = text(ip);
  if (!value) return "-";
  return typeof port === "number" ? `${value}:${port}` : value;
}

function confidenceReasonForNode(node: TopologyNode): string {
  const type = text(node.node_type).toLowerCase();
  const source = text(node.metadata?.match_source || node.metadata?.source);
  if (source) return `Evidence source: ${toTitleLabel(source)}.`;
  if (type === "agent") return "High confidence because this node comes from a registered Seagull agent.";
  if (type === "interface" || type === "host") return "Confidence is based on inventory and traffic observations tied to this asset.";
  if (type === "service") return "Confidence is based on repeated traffic to this IP and port.";
  if (type === "subnet") return "Subnet membership is inferred from observed interface addresses and CIDRs.";
  if (type === "external_ip") return "This public endpoint was observed in traffic or alert evidence.";
  return "Confidence reflects how directly this node was observed in available telemetry.";
}

function scopeExplanation(scope: unknown, nodeType?: string): string {
  const raw = text(scope).toLowerCase();
  if (text(nodeType).toLowerCase() === "docker_network") {
    return "Docker network: an address in a container bridge range; it may not be a physical host.";
  }
  if (raw === "internal_network" || raw === "private_address" || raw === "unique_local") {
    return "Internal: traffic is inside configured or private network space.";
  }
  if (raw === "public_internet") {
    return "Public: the endpoint is routable on the internet and should be treated as external.";
  }
  if (raw === "loopback") return "Loopback: traffic stays on the local host.";
  if (raw === "link_local") return "Link-local: local segment addressing, usually not routed.";
  return "Scope is based on IP classification and configured internal CIDRs when present.";
}

function relationshipKind(edge: TopologyEdge, source?: TopologyNode | null, target?: TopologyNode | null): "Observed" | "Inferred" | "Configured" | "Stale" {
  if (source?.is_stale || target?.is_stale) return "Stale";
  const type = text(edge.edge_type).toLowerCase();
  if (type === "observed_flow" || type === "listens_on" || type === "alert_related" || type === "exposure_related") return "Observed";
  if (type === "owns_interface" || type === "same_agent") return "Configured";
  return "Inferred";
}

function relationshipExplanation(kind: ReturnType<typeof relationshipKind>, edgeType?: string): string {
  if (kind === "Observed") return "Observed: Seagull saw telemetry or security evidence that directly connects these endpoints.";
  if (kind === "Configured") return "Configured: the relationship comes from agent or inventory records.";
  if (kind === "Stale") return "Stale: one or both endpoints have not been seen recently, so verify before acting.";
  if (text(edgeType).toLowerCase() === "member_of_subnet") {
    return "Inferred: subnet membership was derived from interface IP/CIDR data.";
  }
  return "Inferred: Seagull derived this link from related evidence, not from a confirmed physical path.";
}

function physicalTopologyNote(): string {
  return "Physical topology not confirmed: this is a logical map from telemetry, inventory, alerts, and exposure data.";
}

function sensitiveKey(key: string): boolean {
  return /(password|passwd|secret|token|api[-_]?key|authorization|cookie|credential|private[-_]?key|session)/i.test(key);
}

function sanitizeMetadata(value: unknown, depth = 0): unknown {
  if (depth >= 5) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitizeMetadata(item, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (sensitiveKey(key)) continue;
      out[key] = sanitizeMetadata(item, depth + 1);
    }
    return out;
  }
  if (typeof value === "string" && value.length > 2000) return `${value.slice(0, 2000)}...[truncated]`;
  return value;
}

function PivotLink({ href, children, title }: { href?: string | null; children: ReactNode; title?: string }) {
  if (!href) return null;
  return (
    <a
      href={href}
      title={title}
      className="inline-flex items-center rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground hover:bg-muted/15 hover:text-foreground"
    >
      {children}
    </a>
  );
}

function EmptyLine({ children = "No related records returned." }: { children?: ReactNode }) {
  return <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2 text-sm text-muted-foreground">{children}</div>;
}

function FlowPath({ flow }: { flow: TopologyRelatedFlow }) {
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-1.5">
      <span>{endpointLabel(flow.src_ip, flow.src_port)}</span>
      <span className="text-muted-foreground">to</span>
      <span>{endpointLabel(flow.dst_ip, flow.dst_port)}</span>
    </span>
  );
}

function RelatedFlows({ flows }: { flows: TopologyRelatedFlow[] }) {
  if (flows.length === 0) return <EmptyLine>No related flows found for this selection.</EmptyLine>;
  return (
    <div className="space-y-2">
      {flows.slice(0, 8).map((flow) => {
        const badges: Array<{ label: ReactNode; variant?: "info" | "neutral" }> = [
          { label: flow.protocol ? flow.protocol.toUpperCase() : "network", variant: "neutral" },
        ];
        if (flow.app_proto) badges.push({ label: toTitleLabel(flow.app_proto), variant: "info" });
        return (
          <InvestigationListItem
            key={flow.id}
            title={<FlowPath flow={flow} />}
            description={`${flow.event_type} · ${formatTopologyTimestamp(flow.timestamp)}`}
            badges={badges}
            meta={[
              { label: "bytes", value: flow.bytes == null ? "-" : formatBytes(flow.bytes) },
              { label: "agent", value: flow.agent_id || "-" },
            ]}
            actions={<PivotLink href={flowPivotUrl(flow)}>Events</PivotLink>}
          />
        );
      })}
    </div>
  );
}

function RelatedAlerts({ alerts }: { alerts: TopologyRelatedAlert[] }) {
  if (alerts.length === 0) return <EmptyLine>No related alerts found for this selection.</EmptyLine>;
  return (
    <div className="space-y-2">
      {alerts.slice(0, 8).map((alert) => (
        <InvestigationListItem
          key={alert.id}
          title={`Alert #${alert.id} · ${alert.rule_id}`}
          description={alert.description || "No description."}
          badges={[
            { label: alert.severity, variant: topologySeverityVariant(alert.severity) },
            { label: alert.status, variant: "neutral" },
          ]}
          meta={[
            { label: "created", value: formatTopologyTimestamp(alert.created_at) },
            { label: "confidence", value: `${alert.confidence}%` },
            { label: "network", value: `${endpointLabel(alert.src_ip)} to ${endpointLabel(alert.dst_ip, alert.dst_port)}` },
          ]}
          actions={<PivotLink href={alertPivotUrl(alert)}>Alerts</PivotLink>}
        />
      ))}
    </div>
  );
}

function RelatedFindings({ findings }: { findings: TopologyRelatedExposureFinding[] }) {
  if (findings.length === 0) return <EmptyLine>No related exposure findings found.</EmptyLine>;
  return (
    <div className="space-y-2">
      {findings.slice(0, 8).map((finding) => (
        <InvestigationListItem
          key={finding.finding_key}
          title={finding.title || finding.finding_key}
          description={finding.summary || finding.asset_key}
          badges={[
            { label: finding.severity, variant: topologySeverityVariant(finding.severity) },
            { label: finding.status, variant: "neutral" },
            { label: finding.finding_type, variant: "neutral" },
          ]}
          meta={[
            { label: "asset", value: finding.asset_key },
            { label: "confidence", value: `${finding.confidence}%` },
            { label: "last seen", value: formatTopologyTimestamp(finding.last_seen_at) },
          ]}
          actions={<PivotLink href={exposureFindingPivotUrl(finding)}>Exposure</PivotLink>}
        />
      ))}
    </div>
  );
}

function RelatedAttackChains({ cases }: { cases: TopologyRelatedAttackChainCase[] }) {
  if (cases.length === 0) return <EmptyLine>No linked attack-chain cases found.</EmptyLine>;
  return (
    <div className="space-y-2">
      {cases.slice(0, 8).map((item) => (
        <InvestigationListItem
          key={item.id}
          title={`Case #${item.id} · ${toTitleLabel(item.max_stage)}`}
          description={item.suspect_ip ? `Suspect IP ${item.suspect_ip}` : `Agent ${item.agent_id}`}
          badges={[
            { label: item.status, variant: "neutral" },
            { label: `score ${item.score}`, variant: topologySeverityVariant(item.score >= 70 ? "high" : item.score >= 40 ? "medium" : "low") },
          ]}
          meta={[
            { label: "steps", value: item.step_count },
            { label: "last seen", value: formatTopologyTimestamp(item.last_seen_at) },
          ]}
          actions={<PivotLink href={attackChainCasePivotUrl(item)}>Attack Chain</PivotLink>}
        />
      ))}
    </div>
  );
}

function Observations({ observations, meta }: { observations: TopologyObservation[]; meta?: { omitted?: number } }) {
  if (observations.length === 0) return <EmptyLine>No topology observations returned.</EmptyLine>;
  return (
    <div className="space-y-2">
      {observations.map((obs) => {
        const pivot = observationPivotUrl(obs);
        return (
          <div key={obs.id} className="rounded-xl border border-border/60 bg-background/35 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge>{toTitleLabel(obs.source_type)}</Badge>
                  {obs.source_id ? <span className="break-all font-mono text-[11px] text-muted-foreground">{obs.source_id}</span> : null}
                </div>
                <div className="mt-2 text-sm">{obs.summary}</div>
              </div>
              <div className="shrink-0 text-right text-[11px] text-muted-foreground">
                <div>{formatTopologyTimestamp(obs.observed_at)}</div>
                <div className="mt-1 font-mono">{obs.confidence}% confidence</div>
              </div>
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              {obs.agent_id ? <Badge variant="neutral">{obs.agent_id}</Badge> : null}
              {pivot ? <PivotLink href={pivot}>Open Source</PivotLink> : null}
            </div>
          </div>
        );
      })}
      {meta?.omitted ? <div className="text-[11px] text-muted-foreground">{meta.omitted} older observation(s) omitted from this detail payload.</div> : null}
    </div>
  );
}

function EvidenceSources({ sources }: { sources: TopologyNodeDetail["evidence_sources"] | TopologyEdgeDetail["evidence_sources"] }) {
  if (sources.length === 0) return <EmptyLine>No source summary available.</EmptyLine>;
  return (
    <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
      {sources.map((source) => (
        <InvestigationFactCard
          key={source.source_type}
          label={toTitleLabel(source.source_type)}
          value={formatCount(source.count)}
          hint={source.latest_observed_at ? `Latest ${formatTopologyTimestamp(source.latest_observed_at)}` : undefined}
          mono
        />
      ))}
    </div>
  );
}

function ConnectedNodes({ nodes }: { nodes: TopologyNode[] }) {
  if (nodes.length === 0) return <EmptyLine>No connected nodes returned.</EmptyLine>;
  return (
    <div className="space-y-2">
      {nodes.slice(0, 10).map((node) => (
        <InvestigationListItem
          key={node.node_key}
          title={node.label || node.node_key}
          description={`${toTitleLabel(node.node_type)}${node.ip ? ` · ${node.ip}` : node.cidr ? ` · ${node.cidr}` : ""}`}
          badges={[
            { label: node.severity, variant: topologySeverityVariant(node.severity) },
            { label: node.is_stale ? "stale" : "active", variant: node.is_stale ? "medium" : "low" },
          ]}
          meta={[
            { label: "confidence", value: `${node.confidence}%` },
            { label: "last seen", value: formatTopologyTimestamp(node.last_seen_at) },
          ]}
        />
      ))}
    </div>
  );
}

function firstPinTargetFromNode(detail: TopologyNodeDetail): PinTarget {
  const caseItem = detail.related_attack_chain_cases.find((item) => item.id > 0);
  if (caseItem) {
    return {
      kind: "attack_chain_case",
      id: caseItem.id,
      title: `Attack-chain case #${caseItem.id}`,
      agentId: caseItem.agent_id,
    };
  }
  const flow = detail.related_flows.find((item) => item.id > 0);
  if (flow) return { kind: "event", id: flow.id, title: `Network event #${flow.id}`, agentId: flow.agent_id };
  return null;
}

function firstPinTargetFromEdge(detail: TopologyEdgeDetail): PinTarget {
  const caseItem = detail.related_attack_chain_cases.find((item) => item.id > 0);
  if (caseItem) return { kind: "attack_chain_case", id: caseItem.id, title: `Attack-chain case #${caseItem.id}`, agentId: caseItem.agent_id };
  const flow = detail.related_flows.find((item) => item.id > 0);
  if (flow) return { kind: "event", id: flow.id, title: `Network event #${flow.id}`, agentId: flow.agent_id };
  return null;
}

export function NetworkTopologyNodeDetailContent({
  detail,
  onPin,
}: {
  detail: TopologyNodeDetail;
  onPin?: (target: PinTarget) => void;
}) {
  const node = detail.node;
  const ipScope = text(node.metadata?.ip_scope);
  const assetKey = nodeAssetKey(node);
  const exposureHref = buildExposureAssetPivotUrl({ assetKey, agentId: node.agent_id, q: assetKey || node.label });
  const inventoryHref = buildInventoryPivotUrl({ agentId: node.agent_id, openDrawer: true });
  const pinTarget = firstPinTargetFromNode(detail);
  const safeMetadata = useMemo(() => sanitizeMetadata(node.metadata), [node.metadata]);

  return (
    <InvestigationShell>
      <InvestigationMetaStrip
        items={[
          { label: "Type", value: toTitleLabel(node.node_type), variant: "info" },
          { label: "Status", value: node.is_stale ? "stale" : "active", variant: node.is_stale ? "medium" : "low" },
          { label: "Severity", value: node.severity, variant: topologySeverityVariant(node.severity) },
          { label: "Confidence", value: `${node.confidence}%` },
        ]}
      />

      <InvestigationActionBar>
        <PivotLink href={nodeEventsPivot(node)} title="Open Events with this node scope">Events</PivotLink>
        <PivotLink href={nodeAlertsPivot(node)} title="Open Alerts with this node scope">Alerts</PivotLink>
        <PivotLink href={inventoryHref} title="Open Inventory for this agent">Inventory</PivotLink>
        <PivotLink href={exposureHref} title="Open Exposure for this asset">Exposure</PivotLink>
        {pinTarget ? (
          <InvestigationActionButton onClick={() => onPin?.(pinTarget)} tone="primary" title="Pin supported evidence to a workspace">
            Pin Evidence
          </InvestigationActionButton>
        ) : null}
      </InvestigationActionBar>

      <InvestigationSection title="What this means" subtitle={physicalTopologyNote()}>
        <div className="space-y-3 text-sm leading-relaxed text-muted-foreground">
          <p>
            <span className="font-semibold text-foreground">{node.label}</span> is a {toTitleLabel(node.node_type).toLowerCase()} in the logical network map.
            {nodePrimaryIp(node) ? ` Seagull associates it with ${nodePrimaryIp(node)}.` : ""}
          </p>
          <p>{scopeExplanation(ipScope, node.node_type)}</p>
          <p>{node.is_stale ? "Stale: this node has not been refreshed by recent topology projection." : "Active: this node was present in the latest topology projection."}</p>
        </div>
      </InvestigationSection>

      <InvestigationSection title="Identity and context" subtitle={confidenceReasonForNode(node)}>
        <InvestigationSummaryGrid>
          <InvestigationFactCard label="Name" value={node.label || node.node_key} mono copyValue={node.node_key} />
          <InvestigationFactCard label="Node key" value={node.node_key} mono copyValue={node.node_key} />
          <InvestigationFactCard label="IP / CIDR" value={node.ip ? <IpAddressPill ip={node.ip} ipContext={{ scope: ipScope || null }} compact /> : node.cidr || "-"} />
          <InvestigationFactCard label="Agent" value={node.agent_id || "-"} mono copyValue={node.agent_id || undefined} />
          <InvestigationFactCard label="Interface" value={text(node.metadata?.interface_name) || "-"} mono />
          <InvestigationFactCard label="Service" value={portLabel(node.port, node.protocol)} mono />
          <InvestigationFactCard label="Scope" value={<TopologyIpScopeBadge scope={ipScope} compact />} hint={scopeExplanation(ipScope, node.node_type)} />
          <InvestigationFactCard label="First seen" value={formatTopologyTimestamp(node.first_seen_at)} mono />
          <InvestigationFactCard label="Last seen" value={formatTopologyTimestamp(node.last_seen_at)} mono />
          <InvestigationFactCard label="Related alerts" value={formatCount(detail.related_alerts.length || node.alert_count)} />
          <InvestigationFactCard label="Related flows" value={formatCount(detail.related_flows.length || node.event_count)} />
          <InvestigationFactCard label="Evidence records" value={formatCount(detail.evidence_meta.total || node.observation_count)} />
        </InvestigationSummaryGrid>
      </InvestigationSection>

      <InvestigationSection title="Related flows" subtitle="Recent events that involve this IP, agent, or service port.">
        <RelatedFlows flows={detail.related_flows} />
      </InvestigationSection>

      <InvestigationSection title="Related security context" subtitle="Alerts, exposure findings, and attack-chain cases tied to this node.">
        <div className="space-y-4">
          <RelatedAlerts alerts={detail.related_alerts} />
          <RelatedFindings findings={detail.related_exposure_findings} />
          <RelatedAttackChains cases={detail.related_attack_chain_cases} />
        </div>
      </InvestigationSection>

      <InvestigationSection title="Related services and neighbors" subtitle="Logical neighbors from the topology graph.">
        <div className="space-y-4">
          {detail.related_services.length ? (
            <ConnectedNodes nodes={detail.related_services} />
          ) : (
            <EmptyLine>No related service nodes found.</EmptyLine>
          )}
          <ConnectedNodes nodes={detail.connected_nodes} />
        </div>
      </InvestigationSection>

      <InvestigationSection title="Evidence sources" subtitle="Source systems that contributed observations for this node.">
        <EvidenceSources sources={detail.evidence_sources} />
      </InvestigationSection>

      <InvestigationSection title="Topology observations" subtitle="Capped evidence list returned by the detail endpoint.">
        <Observations observations={detail.observations} meta={detail.evidence_meta} />
      </InvestigationSection>

      <InvestigationSection title="Sanitized metadata" subtitle="Raw technical metadata is secondary and sensitive keys are hidden.">
        <JsonBlock value={safeMetadata} maxHeight="220px" showControls={false} />
      </InvestigationSection>
    </InvestigationShell>
  );
}

export function NetworkTopologyEdgeDetailContent({
  detail,
  onPin,
}: {
  detail: TopologyEdgeDetail;
  onPin?: (target: PinTarget) => void;
}) {
  const edge = detail.edge;
  const kind = relationshipKind(edge, detail.source_node, detail.target_node);
  const sourceLabel = detail.source_node?.label || edge.source_node_key;
  const targetLabel = detail.target_node?.label || edge.target_node_key;
  const sourceIp = detail.source_node?.ip || null;
  const targetIp = detail.target_node?.ip || null;
  const pinTarget = firstPinTargetFromEdge(detail);
  const safeMetadata = useMemo(() => sanitizeMetadata(edge.metadata), [edge.metadata]);

  return (
    <InvestigationShell>
      <InvestigationMetaStrip
        items={[
          { label: "Relationship", value: kind, variant: kind === "Stale" ? "medium" : kind === "Observed" ? "info" : "neutral" },
          { label: "Type", value: toTitleLabel(edge.edge_type) },
          { label: "Severity", value: edge.severity, variant: topologySeverityVariant(edge.severity) },
          { label: "Confidence", value: `${edge.confidence}%` },
        ]}
      />

      <InvestigationActionBar>
        <PivotLink href={edgeEventsPivot(edge, sourceIp, targetIp)} title="Open Events with this edge scope">Events</PivotLink>
        <PivotLink href={edgeAlertsPivot(edge, sourceIp, targetIp)} title="Open Alerts with this edge scope">Alerts</PivotLink>
        {pinTarget ? (
          <InvestigationActionButton onClick={() => onPin?.(pinTarget)} tone="primary" title="Pin supported evidence to a workspace">
            Pin Evidence
          </InvestigationActionButton>
        ) : null}
      </InvestigationActionBar>

      <InvestigationSection title="What this means" subtitle={physicalTopologyNote()}>
        <div className="space-y-3 text-sm leading-relaxed text-muted-foreground">
          <p>
            <span className="font-semibold text-foreground">{sourceLabel}</span> connects to{" "}
            <span className="font-semibold text-foreground">{targetLabel}</span> as {toTitleLabel(edge.edge_type).toLowerCase()}.
          </p>
          <p>{relationshipExplanation(kind, edge.edge_type)}</p>
        </div>
      </InvestigationSection>

      <InvestigationSection title="Relationship facts">
        <InvestigationSummaryGrid>
          <InvestigationFactCard label="Source node" value={sourceLabel} mono copyValue={edge.source_node_key} />
          <InvestigationFactCard label="Target node" value={targetLabel} mono copyValue={edge.target_node_key} />
          <InvestigationFactCard label="Protocol / port" value={portLabel(edge.port, edge.protocol)} mono />
          <InvestigationFactCard label="Event count" value={formatCount(edge.event_count || detail.related_flows.length)} mono />
          <InvestigationFactCard label="Bytes" value={formatBytes(detail.total_bytes)} mono />
          <InvestigationFactCard
            label="Application protocols"
            value={
              detail.application_protocols.length ? (
                <span className="flex flex-wrap gap-1.5">
                  {detail.application_protocols.map((proto) => <Badge key={proto} variant="info">{toTitleLabel(proto)}</Badge>)}
                </span>
              ) : (
                "-"
              )
            }
          />
          <InvestigationFactCard label="Related alerts" value={formatCount(detail.related_alerts.length || edge.alert_count)} />
          <InvestigationFactCard label="First seen" value={formatTopologyTimestamp(edge.first_seen_at)} mono />
          <InvestigationFactCard label="Last seen" value={formatTopologyTimestamp(edge.last_seen_at)} mono />
        </InvestigationSummaryGrid>
      </InvestigationSection>

      <InvestigationSection title="Endpoints">
        <InvestigationSummaryGrid>
          <InvestigationFactCard
            label="Source"
            value={sourceIp ? <IpAddressPill ip={sourceIp} ipContext={{ scope: text(detail.source_node?.metadata?.ip_scope) || null }} compact /> : sourceLabel}
          />
          <InvestigationFactCard
            label="Target"
            value={targetIp ? <IpAddressPill ip={targetIp} ipContext={{ scope: text(detail.target_node?.metadata?.ip_scope) || null }} compact /> : targetLabel}
          />
          <InvestigationFactCard label="Agent" value={edge.agent_id || "-"} mono />
          <InvestigationFactCard label="Evidence records" value={formatCount(detail.evidence_meta.total)} mono />
        </InvestigationSummaryGrid>
      </InvestigationSection>

      <InvestigationSection title="Related flows" subtitle="Recent events that support or contextualize this relationship.">
        <RelatedFlows flows={detail.related_flows} />
      </InvestigationSection>

      <InvestigationSection title="Related security context" subtitle="Alerts, exposure findings, and attack-chain cases tied to this relationship.">
        <div className="space-y-4">
          <RelatedAlerts alerts={detail.related_alerts} />
          <RelatedFindings findings={detail.related_exposure_findings} />
          <RelatedAttackChains cases={detail.related_attack_chain_cases} />
        </div>
      </InvestigationSection>

      <InvestigationSection title="Evidence sources" subtitle="Source systems that contributed observations for this relationship.">
        <EvidenceSources sources={detail.evidence_sources} />
      </InvestigationSection>

      <InvestigationSection title="Evidence references" subtitle="Capped observation list returned by the detail endpoint.">
        <Observations observations={detail.observations} meta={detail.evidence_meta} />
      </InvestigationSection>

      <InvestigationSection title="Sanitized metadata" subtitle="Raw technical metadata is secondary and sensitive keys are hidden.">
        <JsonBlock value={safeMetadata} maxHeight="220px" showControls={false} />
      </InvestigationSection>
    </InvestigationShell>
  );
}

function GroupTypeLabel({ groupType }: { groupType: string }) {
  if (groupType === "agent") return <>Agent</>;
  if (groupType === "subnet") return <>Subnet</>;
  if (groupType === "ip_scope" || groupType === "scope") return <>IP Scope</>;
  return <>Ungrouped</>;
}

function TruncationNotice({ omitted, label }: { omitted?: number; label: string }) {
  if (!omitted) return null;
  return <div className="text-[11px] text-muted-foreground">{omitted} additional {label} omitted from this detail payload.</div>;
}

export function NetworkTopologySubnetDetailContent({
  detail,
}: {
  detail: TopologySubnetDetail;
}) {
  return (
    <div className="space-y-4">
      <InvestigationMetaStrip
        items={[
          { label: "CIDR", value: detail.cidr, variant: "info" },
          { label: "Scope", value: <TopologyIpScopeBadge scope={detail.ip_scope} compact /> },
          { label: "Freshness", value: detail.last_seen ? formatTopologyTimestamp(detail.last_seen) : "-" },
        ]}
      />

      <InvestigationSummaryGrid>
        <InvestigationFactCard label="Node count" value={formatCount(detail.node_count)} />
        <InvestigationFactCard label="Active nodes" value={formatCount(detail.active_node_count)} />
        <InvestigationFactCard label="Stale nodes" value={formatCount(detail.stale_node_count)} />
        <InvestigationFactCard label="Alert count" value={formatCount(detail.alert_count)} />
        <InvestigationFactCard
          label="Highest severity"
          value={<span style={{ color: severityColor(detail.highest_severity), textTransform: "capitalize" }}>{detail.highest_severity}</span>}
        />
        {detail.risk_score != null ? <InvestigationFactCard label="Risk score" value={formatCount(detail.risk_score)} /> : null}
        {detail.confidence != null ? <InvestigationFactCard label="Confidence" value={`${detail.confidence}%`} /> : null}
        {detail.first_seen ? <InvestigationFactCard label="First seen" value={formatTopologyTimestamp(detail.first_seen)} mono /> : null}
        {detail.last_seen ? <InvestigationFactCard label="Last seen" value={formatTopologyTimestamp(detail.last_seen)} mono /> : null}
      </InvestigationSummaryGrid>

      <InvestigationSection title="Gateway candidates" subtitle="Only nodes supported by existing topology evidence are shown.">
        {detail.gateway_candidates.length ? (
          <div className="space-y-2">
            {detail.gateway_candidates.map((node) => (
              <InvestigationListItem
                key={node.node_key}
                title={node.label || node.node_key}
                meta={[{ value: [node.ip ?? node.cidr, toTitleLabel(node.node_type)].filter(Boolean).join(" · ") }]}
              />
            ))}
            <TruncationNotice omitted={detail.truncation.gateway_candidates.omitted} label="gateway candidate(s)" />
          </div>
        ) : (
          <EmptyLine>No gateway candidates identified from current evidence.</EmptyLine>
        )}
      </InvestigationSection>

      <InvestigationSection
        title="Top member nodes"
        subtitle={`Showing ${detail.member_nodes.length} of ${detail.node_count}`}
      >
        {detail.member_nodes.length ? (
          <div className="space-y-2">
            {detail.member_nodes.map((node) => (
              <InvestigationListItem
                key={node.node_key}
                title={node.label || node.node_key}
                badges={[
                  { label: node.severity, variant: topologySeverityVariant(node.severity) },
                  { label: node.is_stale ? "stale" : "active", variant: node.is_stale ? "neutral" : "info" },
                ]}
                meta={[
                  { label: "address", value: node.ip ?? node.cidr ?? "-" },
                  { label: "alerts", value: node.alert_count },
                  { label: "last seen", value: formatTopologyTimestamp(node.last_seen_at) },
                ]}
              />
            ))}
            <TruncationNotice omitted={detail.truncation.member_nodes.omitted} label="member node(s)" />
          </div>
        ) : (
          <EmptyLine>No subnet member nodes returned.</EmptyLine>
        )}
      </InvestigationSection>

      <InvestigationSection title="Listening services" subtitle="Services tied to subnet members through existing topology edges.">
        {detail.listening_services.length ? (
          <div className="space-y-2">
            {detail.listening_services.map((node) => (
              <InvestigationListItem
                key={node.node_key}
                title={node.label || node.node_key}
                meta={[
                  { label: "address", value: node.ip ?? "-" },
                  { label: "service", value: portLabel(node.port, node.protocol) },
                ]}
              />
            ))}
            <TruncationNotice omitted={detail.truncation.listening_services.omitted} label="service(s)" />
          </div>
        ) : (
          <EmptyLine>No listening services returned for this subnet.</EmptyLine>
        )}
      </InvestigationSection>

      <InvestigationSection title="External destinations" subtitle="Public nodes connected through real observed topology edges.">
        {detail.external_destinations.length ? (
          <div className="space-y-2">
            {detail.external_destinations.map((node) => (
              <InvestigationListItem
                key={node.node_key}
                title={node.label || node.node_key}
                meta={[
                  { label: "address", value: node.ip ?? "-" },
                  { label: "last seen", value: formatTopologyTimestamp(node.last_seen_at) },
                ]}
              />
            ))}
            <TruncationNotice omitted={detail.truncation.external_destinations.omitted} label="external destination(s)" />
          </div>
        ) : (
          <EmptyLine>No external destinations returned for this subnet.</EmptyLine>
        )}
      </InvestigationSection>

      <InvestigationSection title="Related edges" subtitle="Bounded topology relationships touching subnet members.">
        {detail.related_edges.length ? (
          <div className="space-y-2">
            {detail.related_edges.map((edge) => (
              <InvestigationListItem
                key={edge.edge_key}
                title={`${edge.source_node_key.split(":").pop() ?? edge.source_node_key} → ${edge.target_node_key.split(":").pop() ?? edge.target_node_key}`}
                meta={[
                  { label: "type", value: toTitleLabel(edge.edge_type) },
                  { label: "alerts", value: edge.alert_count },
                ]}
              />
            ))}
            <TruncationNotice omitted={detail.truncation.related_edges.omitted} label="related edge(s)" />
          </div>
        ) : (
          <EmptyLine>No related edges returned for this subnet.</EmptyLine>
        )}
      </InvestigationSection>

      <InvestigationSection title="Recent observations" subtitle="Most recent topology observations for the subnet and its members.">
        <Observations observations={detail.recent_observations} meta={detail.truncation.recent_observations} />
      </InvestigationSection>
    </div>
  );
}

export function NetworkTopologyGroupDetailContent({
  group,
  memberNodes,
  backendDetail,
  backendDetailLoading,
  backendDetailError,
  subnetCidr,
  subnetDetail,
  subnetDetailLoading,
  subnetDetailError,
  onExploreInConnection,
}: {
  group: TopologyGroup;
  memberNodes: TopologyNode[];
  backendDetail: TopologyGroupDetail | null;
  backendDetailLoading: boolean;
  backendDetailError: string | null;
  subnetCidr: string | null;
  subnetDetail: TopologySubnetDetail | null;
  subnetDetailLoading: boolean;
  subnetDetailError: string | null;
  onExploreInConnection: () => void;
}) {
  const sev = backendDetail?.highest_severity ?? group.highest_severity ?? null;
  const nodeCount = backendDetail?.node_count ?? group.node_count;
  const alertCount = backendDetail?.alert_count ?? group.alert_count;
  const riskScore = backendDetail?.risk_score ?? group.risk_score;
  const displayNodes: TopologyNode[] = backendDetail?.top_member_nodes ?? memberNodes;
  const displayEdges = backendDetail?.related_edges ?? [];

  return (
    <InvestigationShell>
      {backendDetailLoading && (
        <div className="rounded-md border border-border/70 bg-background/35 px-3 py-2 text-sm text-muted-foreground">
          Loading group detail...
        </div>
      )}
      {backendDetailError && !backendDetail && (
        <div className="rounded-md border border-border/40 bg-background/30 px-3 py-2 text-xs text-muted-foreground">
          Backend detail unavailable — showing client summary.
        </div>
      )}

      <InvestigationSummaryGrid>
        <InvestigationFactCard label="Group type" value={<GroupTypeLabel groupType={group.group_type} />} />
        <InvestigationFactCard label="Nodes" value={String(nodeCount)} />
        <InvestigationFactCard label="Alert count" value={String(alertCount)} />
        {sev && <InvestigationFactCard label="Highest severity" value={<span style={{ color: severityColor(sev), textTransform: "capitalize" }}>{sev}</span>} />}
        {riskScore != null && <InvestigationFactCard label="Risk score" value={String(riskScore)} />}
        {group.cidr && <InvestigationFactCard label="CIDR" value={group.cidr} />}
        {backendDetail?.first_seen && <InvestigationFactCard label="First seen" value={formatTopologyTimestamp(backendDetail.first_seen)} mono />}
        {backendDetail?.last_seen && <InvestigationFactCard label="Last seen" value={formatTopologyTimestamp(backendDetail.last_seen)} mono />}
      </InvestigationSummaryGrid>

      <InvestigationActionBar>
        <InvestigationActionButton onClick={onExploreInConnection}>
          {group.group_type === "subnet" && (subnetCidr || group.group_key.startsWith("subnet:"))
            ? "Explore subnet"
            : "Explore in Connection view"}
        </InvestigationActionButton>
      </InvestigationActionBar>

      {group.group_type === "subnet" && (
        <InvestigationSection title="Subnet exploration" subtitle="Network-level context derived from existing topology evidence.">
          {subnetDetailLoading && !subnetDetail ? (
            <div className="rounded-md border border-border/70 bg-background/35 px-3 py-2 text-sm text-muted-foreground">
              Loading subnet detail...
            </div>
          ) : null}
          {subnetDetailError && !subnetDetail ? (
            <div className="rounded-md border border-border/40 bg-background/30 px-3 py-2 text-xs text-muted-foreground">
              Subnet detail unavailable — keeping the group summary visible.
            </div>
          ) : null}
          {subnetDetail ? <NetworkTopologySubnetDetailContent detail={subnetDetail} /> : null}
        </InvestigationSection>
      )}

      {displayNodes.length > 0 && (
        <InvestigationSection
          title="Member nodes"
          subtitle={`Showing ${displayNodes.length} of ${nodeCount}${backendDetail?.child_node_keys_truncated ? " (list capped)" : ""}`}
        >
          {displayNodes.map((node) => (
            <InvestigationListItem
              key={node.node_key}
              title={node.label || node.node_key}
              meta={[{ value: [node.ip ?? node.cidr, node.node_type].filter(Boolean).join(" · ") }]}
            />
          ))}
        </InvestigationSection>
      )}

      {displayEdges.length > 0 && (
        <InvestigationSection title="Related connections" subtitle="Edges among group members and first-hop neighbors.">
          {displayEdges.slice(0, 10).map((edge) => (
            <InvestigationListItem
              key={edge.edge_key}
              title={`${edge.source_node_key.split(":").pop() ?? edge.source_node_key} → ${edge.target_node_key.split(":").pop() ?? edge.target_node_key}`}
              meta={[{ value: toTitleLabel(edge.edge_type) }]}
            />
          ))}
        </InvestigationSection>
      )}
    </InvestigationShell>
  );
}

export function NetworkTopologyDetailDrawer({
  selection,
  onClose,
}: {
  selection: NetworkTopologyDetailSelection;
  onClose: () => void;
}) {
  const [pinTarget, setPinTarget] = useState<PinTarget>(null);
  const open = selection !== null;
  const title =
    selection?.kind === "node"
      ? selection.detail?.node.label ?? selection.key
      : selection?.kind === "edge"
        ? toTitleLabel(selection.detail?.edge.edge_type ?? selection.key)
        : selection?.kind === "group"
          ? selection.group.label || selection.key
          : "Topology Detail";

  const description =
    selection?.kind === "group"
      ? "Group summary, member nodes, and connection view drill-down."
      : selection?.kind === "node"
        ? "Node evidence, relationships, and investigation pivots."
        : "Relationship evidence, endpoints, and investigation pivots.";

  return (
    <Drawer
      open={open}
      title={title}
      description={description}
      onClose={() => {
        setPinTarget(null);
        onClose();
      }}
      headerLabel="Network Topology"
      widthClassName="w-[980px]"
    >
      {!selection ? null : selection.kind === "group" ? (
        <NetworkTopologyGroupDetailContent
          group={selection.group}
          memberNodes={selection.memberNodes}
          backendDetail={selection.backendDetail}
          backendDetailLoading={selection.backendDetailLoading}
          backendDetailError={selection.backendDetailError}
          subnetCidr={selection.subnetCidr}
          subnetDetail={selection.subnetDetail}
          subnetDetailLoading={selection.subnetDetailLoading}
          subnetDetailError={selection.subnetDetailError}
          onExploreInConnection={selection.onExploreInConnection}
        />
      ) : selection.loading ? (
        <div className="rounded-md border border-border/70 bg-background/35 p-4 text-sm text-muted-foreground">Loading detail...</div>
      ) : selection.error ? (
        <div className="rounded-md border border-danger/45 bg-danger/10 p-4 text-sm text-danger">{selection.error}</div>
      ) : selection.kind === "node" && selection.detail ? (
        <NetworkTopologyNodeDetailContent detail={selection.detail} onPin={setPinTarget} />
      ) : selection.kind === "edge" && selection.detail ? (
        <NetworkTopologyEdgeDetailContent detail={selection.detail} onPin={setPinTarget} />
      ) : null}

      {pinTarget ? (
        <PinToWorkspaceDrawer
          open={Boolean(pinTarget)}
          onClose={() => setPinTarget(null)}
          title={pinTarget.title}
          defaultWorkspaceTitle={`Investigation · ${pinTarget.title}`}
          workspaceDefaults={{
            primary_agent_id: pinTarget.agentId || undefined,
            linked_attack_chain_case_id: pinTarget.kind === "attack_chain_case" ? pinTarget.id : undefined,
          }}
          onPin={(workspaceId, options) =>
            pinTarget.kind === "event"
              ? pinEventToWorkspace(workspaceId, pinTarget.id, { ...options, source_module: "network_topology" })
              : pinAttackChainCaseToWorkspace(workspaceId, pinTarget.id, { ...options, source_module: "network_topology" })
          }
        />
      ) : null}
    </Drawer>
  );
}
