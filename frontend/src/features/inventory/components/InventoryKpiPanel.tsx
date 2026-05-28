import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { MetricCard } from "@/shared/components/MetricCard";

import type { InventoryOverviewSnapshot } from "../types";
import { fmtMinutes } from "../lib/inventoryFormatters";

interface InventoryKpiPanelProps {
  snapshot: InventoryOverviewSnapshot | null;
  busy: boolean;
}

export function InventoryKpiPanel({ snapshot, busy }: InventoryKpiPanelProps) {
  return (
    <Panel title="KPIs" className="lg:col-span-2">
      {!snapshot && busy ? (
        <Loading label="Loading inventory overview..." />
      ) : snapshot ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard size="sm" title="Agents" value={snapshot.kpis.agents_total} helper="Registered endpoints" />
          <MetricCard
            size="sm"
            title="Online (5m)"
            value={snapshot.kpis.agents_online_5m}
            helper="Last seen ≤ 5 minutes"
            tone={snapshot.kpis.agents_online_5m > 0 ? "success" : "warning"}
          />
          <MetricCard
            size="sm"
            title="With inventory (6h)"
            value={snapshot.kpis.agents_with_inventory_6h}
            helper="Any snapshot in the last 6 hours"
          />
          <MetricCard
            size="sm"
            title="Oldest inventory"
            value={fmtMinutes(snapshot.kpis.oldest_inventory_age_minutes)}
            helper="Max age across latest snapshots"
            tone={snapshot.kpis.oldest_inventory_age_minutes > 360 ? "warning" : "default"}
          />
        </div>
      ) : (
        <EmptyState title="No data" hint="No inventory telemetry yet." />
      )}
    </Panel>
  );
}
