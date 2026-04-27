import { MetricCard } from "@/shared/components/MetricCard";

import { ExposureSummary } from "../types";
import {
  formatExposureCount,
  formatExposureScore,
  formatExposureTimestamp,
  toTitleCase,
  truncateText,
} from "../utils";

type Props = {
  summary: ExposureSummary | null;
  loading?: boolean;
};

function SummaryListCard({
  title,
  items,
  loading,
  emptyLabel,
}: {
  title: string;
  items: Array<{ key: string; count: number }>;
  loading?: boolean;
  emptyLabel: string;
}) {
  return (
    <div className="ui-card-shell px-3 py-3">
      <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">{title}</div>
      {loading ? (
        <div className="mt-3 space-y-2">
          <div className="h-3 w-24 animate-pulse rounded bg-muted/60" />
          <div className="h-3 w-32 animate-pulse rounded bg-muted/50" />
          <div className="h-3 w-20 animate-pulse rounded bg-muted/45" />
        </div>
      ) : items.length > 0 ? (
        <div className="mt-2 space-y-2">
          {items.slice(0, 3).map((item) => (
            <div key={item.key} className="flex items-center justify-between gap-2 text-[11px]">
              <span className="min-w-0 truncate text-muted-foreground" title={item.key}>
                {truncateText(toTitleCase(item.key), 28)}
              </span>
              <span className="shrink-0 font-mono text-foreground">{formatExposureCount(item.count)}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="mt-2 text-[11px] text-muted-foreground">{emptyLabel}</div>
      )}
    </div>
  );
}

function SummaryTimestampCard({
  updatedAt,
  loading,
}: {
  updatedAt: string | null | undefined;
  loading?: boolean;
}) {
  return (
    <div className="ui-card-shell px-3 py-3">
      <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">Updated</div>
      <div className="mt-1 text-sm font-semibold leading-tight text-foreground">
        {loading ? (
          <span className="inline-block h-5 w-32 animate-pulse rounded bg-muted/60" aria-label="Loading" />
        ) : (
          formatExposureTimestamp(updatedAt)
        )}
      </div>
      <div className="mt-1 text-[10px] text-muted-foreground">
        {updatedAt ? "Backend exposure snapshot" : "Waiting for the first posture refresh"}
      </div>
    </div>
  );
}

export function ExposureSummaryCards({ summary, loading }: Props) {
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
      <MetricCard
        title="Total Assets"
        value={formatExposureCount(summary?.total_assets)}
        loading={loading}
      />
      <MetricCard
        title="Critical / High"
        value={
          summary
            ? `${formatExposureCount(summary.critical_assets)} / ${formatExposureCount(summary.high_assets)}`
            : "-"
        }
        helper="Critical first, then high"
        loading={loading}
        tone="danger"
      />
      <MetricCard
        title="Max Risk"
        value={formatExposureScore(summary?.max_risk_score)}
        helper="Highest observed asset score"
        loading={loading}
        tone={(summary?.max_risk_score ?? 0) >= 80 ? "danger" : (summary?.max_risk_score ?? 0) >= 60 ? "warning" : "default"}
      />
      <MetricCard
        title="Average Risk"
        value={formatExposureScore(summary?.avg_risk_score)}
        helper="Fleet-wide mean score"
        loading={loading}
      />
      <MetricCard
        title="Active Findings"
        value={formatExposureCount(summary?.active_findings)}
        loading={loading}
        tone="warning"
      />
      <MetricCard
        title="Attack Paths"
        value={formatExposureCount(summary?.active_attack_paths)}
        loading={loading}
        tone={(summary?.active_attack_paths ?? 0) > 0 ? "danger" : "default"}
      />
      <MetricCard
        title="Stale Agents"
        value={formatExposureCount(summary?.stale_agents)}
        helper="Assets missing fresh telemetry"
        loading={loading}
        tone={(summary?.stale_agents ?? 0) > 0 ? "warning" : "default"}
      />
      <MetricCard
        title="Stale Inventory"
        value={formatExposureCount(summary?.stale_inventory_assets)}
        helper="Assets with aged inventory state"
        loading={loading}
        tone={(summary?.stale_inventory_assets ?? 0) > 0 ? "warning" : "default"}
      />
      <SummaryListCard
        title="Top Reason Codes"
        items={summary?.top_reason_codes ?? []}
        loading={loading}
        emptyLabel="No dominant reason codes."
      />
      <SummaryTimestampCard updatedAt={summary?.updated_at} loading={loading} />
    </div>
  );
}
