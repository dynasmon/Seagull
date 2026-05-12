import { MetricCard } from "@/shared/components/MetricCard";

import { compactNumber, formatFreshness } from "../lib/labels";
import type { TopologySummary } from "../types";

export function NetworkTopologySummaryCards({
  summary,
  loading,
}: {
  summary: TopologySummary | null;
  loading?: boolean;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
      <MetricCard title="Nodes" value={compactNumber(summary?.total_nodes)} loading={loading} tone="info" />
      <MetricCard title="Edges" value={compactNumber(summary?.total_edges)} loading={loading} />
      <MetricCard title="Agents" value={compactNumber(summary?.agent_count)} loading={loading} />
      <MetricCard title="Subnets" value={compactNumber(summary?.subnet_count)} loading={loading} />
      <MetricCard title="External IPs" value={compactNumber(summary?.external_ip_count)} loading={loading} tone="warning" />
      <MetricCard
        title="Freshness"
        value={formatFreshness(summary?.freshness_seconds)}
        helper={summary?.stale ? "Projection is stale" : "Projection current"}
        loading={loading}
        tone={summary?.stale ? "warning" : "success"}
      />
    </div>
  );
}
