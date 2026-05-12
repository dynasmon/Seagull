import type { ReactNode } from "react";

import Drawer from "@/shared/components/Drawer";
import { Badge } from "@/shared/components/Badge";
import { JsonBlock } from "@/shared/components/JsonBlock";
import { SeverityPill } from "@/shared/components/SeverityPill";

import { TopologyIpScopeBadge } from "./TopologyIpScopeBadge";
import { formatTopologyTimestamp, toTitleLabel, topologySeverityVariant } from "../lib/labels";
import type { TopologyEdgeDetail, TopologyNodeDetail } from "../types";

export type NetworkTopologyDetailSelection =
  | { kind: "node"; key: string; detail: TopologyNodeDetail | null; loading: boolean; error: string | null }
  | { kind: "edge"; key: string; detail: TopologyEdgeDetail | null; loading: boolean; error: string | null }
  | null;

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="rounded-md border border-border/70 bg-background/35 px-3 py-2">
      <div className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{label}</div>
      <div className="mt-1 min-w-0 break-words text-[12px] font-semibold text-foreground">{value}</div>
    </div>
  );
}

export function NetworkTopologyDetailDrawer({
  selection,
  onClose,
}: {
  selection: NetworkTopologyDetailSelection;
  onClose: () => void;
}) {
  const open = selection !== null;
  const title =
    selection?.kind === "node"
      ? selection.detail?.node.label ?? selection.key
      : selection?.kind === "edge"
        ? toTitleLabel(selection.detail?.edge.edge_type ?? selection.key)
        : "Topology Detail";

  return (
    <Drawer
      open={open}
      title={title}
      description={selection?.kind === "node" ? "Node evidence, relationships, and observed context." : "Edge evidence, endpoints, and observed context."}
      onClose={onClose}
      headerLabel="Network Topology"
      widthClassName="w-[760px]"
      bodyClassName="space-y-4"
    >
      {!selection ? null : selection.loading ? (
        <div className="rounded-md border border-border/70 bg-background/35 p-4 text-sm text-muted-foreground">Loading detail...</div>
      ) : selection.error ? (
        <div className="rounded-md border border-danger/45 bg-danger/10 p-4 text-sm text-danger">{selection.error}</div>
      ) : selection.kind === "node" && selection.detail ? (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <Fact label="Type" value={toTitleLabel(selection.detail.node.node_type)} />
            <Fact
              label="Severity"
              value={
                <SeverityPill variant={topologySeverityVariant(selection.detail.node.severity)}>
                  {selection.detail.node.severity}
                </SeverityPill>
              }
            />
            <Fact label="Risk Score" value={selection.detail.node.risk_score} />
            <Fact label="Confidence" value={`${selection.detail.node.confidence}%`} />
            <Fact label="Agent" value={selection.detail.node.agent_id || "-"} />
            <Fact label="Last Seen" value={formatTopologyTimestamp(selection.detail.node.last_seen_at)} />
            <Fact label="IP" value={selection.detail.node.ip || selection.detail.node.cidr || "-"} />
            <Fact label="IP Scope" value={<TopologyIpScopeBadge scope={String(selection.detail.node.metadata?.ip_scope || "")} compact />} />
          </div>

          <section className="space-y-2">
            <div className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
              Connected Nodes
            </div>
            <div className="grid gap-2">
              {selection.detail.connected_nodes.length === 0 ? (
                <div className="text-sm text-muted-foreground">No connected nodes returned.</div>
              ) : (
                selection.detail.connected_nodes.slice(0, 8).map((node) => (
                  <div key={node.node_key} className="flex min-w-0 items-center justify-between gap-3 rounded-md border border-border/70 bg-background/35 px-3 py-2">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold">{node.label}</div>
                      <div className="truncate text-[11px] text-muted-foreground">{toTitleLabel(node.node_type)}</div>
                    </div>
                    <Badge variant={topologySeverityVariant(node.severity)}>{node.severity}</Badge>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="space-y-2">
            <div className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
              Recent Observations
            </div>
            <div className="space-y-2">
              {selection.detail.observations.length === 0 ? (
                <div className="text-sm text-muted-foreground">No observations returned.</div>
              ) : (
                selection.detail.observations.map((obs) => (
                  <div key={obs.id} className="rounded-md border border-border/70 bg-background/35 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Badge>{obs.source_type}</Badge>
                      <span className="text-[11px] text-muted-foreground">{formatTopologyTimestamp(obs.observed_at)}</span>
                    </div>
                    <div className="mt-2 text-sm">{obs.summary}</div>
                  </div>
                ))
              )}
            </div>
          </section>

          <JsonBlock value={selection.detail.node.metadata} maxHeight="220px" />
        </>
      ) : selection.kind === "edge" && selection.detail ? (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <Fact label="Type" value={toTitleLabel(selection.detail.edge.edge_type)} />
            <Fact
              label="Severity"
              value={
                <SeverityPill variant={topologySeverityVariant(selection.detail.edge.severity)}>
                  {selection.detail.edge.severity}
                </SeverityPill>
              }
            />
            <Fact label="Confidence" value={`${selection.detail.edge.confidence}%`} />
            <Fact label="Weight" value={selection.detail.edge.weight.toFixed(2)} />
            <Fact label="Protocol" value={selection.detail.edge.protocol?.toUpperCase() || "-"} />
            <Fact label="Port" value={selection.detail.edge.port ?? "-"} />
            <Fact label="Source" value={selection.detail.source_node?.label || selection.detail.edge.source_node_key} />
            <Fact label="Target" value={selection.detail.target_node?.label || selection.detail.edge.target_node_key} />
          </div>

          <section className="space-y-2">
            <div className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
              Recent Observations
            </div>
            <div className="space-y-2">
              {selection.detail.observations.length === 0 ? (
                <div className="text-sm text-muted-foreground">No observations returned.</div>
              ) : (
                selection.detail.observations.map((obs) => (
                  <div key={obs.id} className="rounded-md border border-border/70 bg-background/35 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Badge>{obs.source_type}</Badge>
                      <span className="text-[11px] text-muted-foreground">{formatTopologyTimestamp(obs.observed_at)}</span>
                    </div>
                    <div className="mt-2 text-sm">{obs.summary}</div>
                  </div>
                ))
              )}
            </div>
          </section>

          <JsonBlock value={selection.detail.edge.metadata} maxHeight="260px" />
        </>
      ) : null}
    </Drawer>
  );
}
