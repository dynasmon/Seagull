import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";

import { SimpleTimeSeries } from "@/features/overview/components/Charts";

import type { InventoryOverviewSnapshot } from "../types";
import { InventorySection } from "./primitives/InventorySection";

interface InventorySnapshotsPanelProps {
  snapshot: InventoryOverviewSnapshot | null;
  busy: boolean;
  windowMinutes: number;
}

export function InventorySnapshotsPanel({ snapshot, busy, windowMinutes }: InventorySnapshotsPanelProps) {
  return (
    <InventorySection id="timeseries" title="Activity" defaultOpen>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Panel
          title="Inventory snapshots / minute"
          actions={<span className="text-[10px] font-mono text-muted-foreground">{windowMinutes}m window</span>}
          className="min-h-[420px]"
        >
          {snapshot ? (
            <SimpleTimeSeries
              data={snapshot.snapshots_per_minute.data}
              seriesKeys={snapshot.snapshots_per_minute.series}
              height={320}
              minWidth={720}
            />
          ) : busy ? (
            <Loading />
          ) : (
            <EmptyState title="No data" />
          )}
        </Panel>

        <Panel
          title="Inventory changes / 10m"
          actions={<span className="text-[10px] font-mono text-muted-foreground">packages_hash delta</span>}
          className="min-h-[420px]"
        >
          {snapshot ? (
            <SimpleTimeSeries
              data={snapshot.changes_per_10m.data}
              seriesKeys={snapshot.changes_per_10m.series}
              height={320}
              minWidth={720}
            />
          ) : busy ? (
            <Loading />
          ) : (
            <EmptyState title="No data" />
          )}
        </Panel>
      </div>
    </InventorySection>
  );
}
