import { Button } from "@/shared/components/Button";
import { StatusPill } from "@/shared/components/StatusPill";
import { InvestigationSection } from "@/shared/components/investigation";
import { cx } from "@/shared/lib/cx";

import type { InventorySnapshotOut } from "../../types";
import { fmtDateTime } from "../../lib/inventoryFormatters";

interface InventoryDrawerHistoryTabProps {
  drawerHistory: InventorySnapshotOut[];
  focusedSnapshotId: number | null;
  setFocusedSnapshotId: (id: number) => void;
  setPinSnapshotId: (id: number) => void;
  compact: boolean;
}

export function InventoryDrawerHistoryTab({
  drawerHistory,
  focusedSnapshotId,
  setFocusedSnapshotId,
  setPinSnapshotId,
  compact,
}: InventoryDrawerHistoryTabProps) {
  return (
    <InvestigationSection
      title="Recent snapshots"
      subtitle="Track package hash drift and pin relevant baseline states."
      bodyClassName="p-0"
    >
      <div className="overflow-hidden">
        <table className={cx("w-full", compact ? "text-xs" : "text-sm")}>
          <thead className="bg-surface-2/80">
            <tr className="text-left text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
              <th className="px-3 py-2">Collected</th>
              <th className="px-3 py-2 text-right">Packages</th>
              <th className="px-3 py-2 text-right">Changed</th>
              <th className="px-3 py-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {drawerHistory.slice(0, 20).map((s, idx) => {
              const next = drawerHistory[idx + 1];
              const changed = next ? s.packages_hash !== next.packages_hash : false;
              const focused = focusedSnapshotId === s.id;
              return (
                <tr
                  key={s.id}
                  className={cx(
                    "border-t border-border/55 font-mono text-[11.5px] ui-row",
                    focused && "ui-row-selected",
                  )}
                >
                  <td className="px-3 py-2 text-muted-foreground">{fmtDateTime(s.collected_at)}</td>
                  <td className="px-3 py-2 text-right text-muted-foreground">{s.packages_count}</td>
                  <td className="px-3 py-2 text-right">
                    <StatusPill variant={changed ? "warning" : "neutral"}>
                      {changed ? "changed" : "stable"}
                    </StatusPill>
                  </td>
                  <td className="px-3 py-2 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <Button variant="subtle" size="sm" onClick={() => setFocusedSnapshotId(s.id)}>
                        Focus
                      </Button>
                      <Button
                        variant={focused ? "primary" : "subtle"}
                        size="sm"
                        onClick={() => setPinSnapshotId(s.id)}
                      >
                        Pin
                      </Button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {drawerHistory.length === 0 ? (
              <tr>
                <td className="px-3 py-3 text-[11px] text-muted-foreground" colSpan={4}>
                  No history.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </InvestigationSection>
  );
}
