import { MetricCard } from "@/shared/components/MetricCard";
import { ExposureSummary } from "../types";

type Props = {
  summary: ExposureSummary | null;
  loading?: boolean;
};

export function ExposureSummaryCards({ summary, loading }: Props) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      <MetricCard
        title="Critical Assets"
        value={summary?.critical_assets ?? 0}
        loading={loading}
        tone="danger"
      />
      <MetricCard
        title="High Assets"
        value={summary?.high_assets ?? 0}
        loading={loading}
        tone="warning"
      />
      <MetricCard
        title="Active Findings"
        value={summary?.active_findings ?? 0}
        loading={loading}
        tone="warning"
      />
      <MetricCard
        title="Attack Paths"
        value={summary?.active_attack_paths ?? 0}
        loading={loading}
        tone={summary?.active_attack_paths ? "danger" : "default"}
      />
      <MetricCard
        title="Avg Risk Score"
        value={summary ? Math.round(summary.avg_risk_score) : 0}
        loading={loading}
        tone="default"
      />
      <MetricCard
        title="Total Assets"
        value={summary?.total_assets ?? 0}
        loading={loading}
        tone="default"
      />
    </div>
  );
}
