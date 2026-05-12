import { Button } from "@/shared/components/Button";
import { DataQueryStateBanner } from "@/shared/components/DataView";

import { compactNumber, formatFreshness, formatTopologyTimestamp } from "../lib/labels";
import type { TopologyGraph, TopologySummary } from "../types";

function warningCount(summary: TopologySummary | null): number {
  const projection = summary?.source_coverage?.projection;
  if (!projection || typeof projection !== "object") return 0;
  const warnings = (projection as { warnings?: unknown }).warnings;
  return Array.isArray(warnings) ? warnings.length : 0;
}

export function NetworkTopologyVisibilityBanner({
  summary,
  graph,
  error,
  onRefresh,
  refreshing,
}: {
  summary: TopologySummary | null;
  graph: TopologyGraph | null;
  error?: string | null;
  onRefresh: () => void;
  refreshing?: boolean;
}) {
  if (error) {
    return (
      <DataQueryStateBanner
        tone="danger"
        message={error}
        right={
          <Button variant="danger" size="sm" onClick={onRefresh} disabled={refreshing}>
            Retry
          </Button>
        }
      />
    );
  }

  const health = graph?.graph_health;
  const truncated = Boolean(health?.nodes_truncated || health?.edges_truncated);
  const stale = Boolean(summary?.stale || graph?.stale);
  const warnings = warningCount(summary);
  const tone = stale || truncated || warnings > 0 ? "warning" : "success";
  const projectedAt = summary?.projected_at ?? summary?.last_projected_at ?? null;

  return (
    <DataQueryStateBanner
      tone={tone}
      message={
        <>
          Coverage: {compactNumber(summary?.agent_count)} agents, {compactNumber(summary?.subnet_count)} subnets,
          {" "}{compactNumber(summary?.external_ip_count)} external IPs. Projection {formatFreshness(summary?.freshness_seconds)}
          {projectedAt ? ` (${formatTopologyTimestamp(projectedAt)})` : ""}.
        </>
      }
      right={
        <span>
          {truncated ? "Graph truncated by current limits" : warnings > 0 ? `${warnings} projection warnings` : "Visible data reflects applied filters"}
        </span>
      }
    />
  );
}
