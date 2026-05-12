import { Badge } from "@/shared/components/Badge";
import { Panel } from "@/shared/components/Panel";
import { SeverityPill } from "@/shared/components/SeverityPill";

import { TopologyIpScopeBadge } from "./TopologyIpScopeBadge";
import { formatTopologyTimestamp, topologySeverityVariant } from "../lib/labels";
import type { TopologyObservation, TopologySubnet } from "../types";

export function NetworkTopologyEvidencePanel({
  observations,
  subnets,
  loading,
}: {
  observations: TopologyObservation[];
  subnets: TopologySubnet[];
  loading?: boolean;
}) {
  return (
    <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(320px,0.7fr)]">
      <Panel
        title="Evidence"
        subtitle="Recent topology observations matching the applied time window."
        scrollY
        className="min-h-[300px] max-h-[460px]"
      >
        {loading && observations.length === 0 ? (
          <div className="text-sm text-muted-foreground">Loading observations...</div>
        ) : observations.length === 0 ? (
          <div className="text-sm text-muted-foreground">No observations matched the current filters.</div>
        ) : (
          <div className="space-y-2">
            {observations.map((obs) => (
              <div key={obs.id} className="rounded-md border border-border/70 bg-background/35 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <Badge>{obs.source_type}</Badge>
                    {obs.agent_id ? <span className="font-mono text-[11px] text-muted-foreground">{obs.agent_id}</span> : null}
                  </div>
                  <span className="text-[11px] text-muted-foreground">{formatTopologyTimestamp(obs.observed_at)}</span>
                </div>
                <div className="mt-2 text-sm text-foreground">{obs.summary}</div>
                <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{obs.node_key}</div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel
        title="Subnets"
        subtitle="Inferred network segments and local interface coverage."
        scrollY
        className="min-h-[300px] max-h-[460px]"
      >
        {loading && subnets.length === 0 ? (
          <div className="text-sm text-muted-foreground">Loading subnets...</div>
        ) : subnets.length === 0 ? (
          <div className="text-sm text-muted-foreground">No subnets matched the current filters.</div>
        ) : (
          <div className="space-y-2">
            {subnets.map((subnet) => (
              <div key={subnet.node_key} className="rounded-md border border-border/70 bg-background/35 p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="break-all font-mono text-sm font-semibold">{subnet.cidr}</div>
                    <div className="mt-1 text-[11px] text-muted-foreground">
                      {subnet.agent_id || "shared"} · last seen {formatTopologyTimestamp(subnet.last_seen_at)}
                    </div>
                  </div>
                  <SeverityPill variant={topologySeverityVariant(subnet.severity)}>{subnet.severity}</SeverityPill>
                </div>
                <div className="mt-2 flex flex-wrap gap-2">
                  <TopologyIpScopeBadge scope={String(subnet.metadata?.ip_scope || "")} compact />
                  <Badge>{subnet.confidence}% confidence</Badge>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
