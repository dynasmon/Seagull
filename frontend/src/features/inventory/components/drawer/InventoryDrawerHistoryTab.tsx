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
    <InvestigationSection title="Recent snapshots" subtitle="Track package hash drift and pin relevant baseline states.">
      <div className="overflow-hidden rounded-lg border border-border/60">
        <table className={cx("w-full", compact ? "text-xs" : "text-sm")}>
          <thead className="bg-muted/10">
            <tr className="text-[10px] uppercase tracking-widest font-mono text-muted-foreground">
              <th className="text-left px-3 py-2">Collected</th>
              <th className="text-right px-3 py-2">Packages</th>
              <th className="text-right px-3 py-2">Changed</th>
              <th className="text-right px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60">
            {drawerHistory.slice(0, 20).map((s, idx) => {
              const next = drawerHistory[idx + 1];
              const changed = next ? s.packages_hash !== next.packages_hash : false;
              return (
                <tr key={s.id} className={cx("text-[11px] font-mono", focusedSnapshotId === s.id && "bg-primary/10")}>
                  <td className="px-3 py-2 text-muted-foreground">{fmtDateTime(s.collected_at)}</td>
                  <td className="px-3 py-2 text-right text-muted-foreground">{s.packages_count}</td>
                  <td className="px-3 py-2 text-right">
                    <span
                      className={cx(
                        "inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] uppercase",
                        changed
                          ? "border-warning/40 text-warning bg-warning/10"
                          : "border-border/60 text-muted-foreground bg-muted/10"
                      )}
                    >
                      {changed ? "yes" : "no"}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => setFocusedSnapshotId(s.id)}
                        className={cx(
                          "rounded-md border border-border/60 bg-background/40 px-2 py-1",
                          "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                          "hover:bg-muted/15 hover:text-foreground"
                        )}
                      >
                        Focus
                      </button>
                      <button
                        type="button"
                        onClick={() => setPinSnapshotId(s.id)}
                        className={cx(
                          "rounded-md border border-border/60 bg-background/40 px-2 py-1",
                          "text-[10px] font-mono uppercase tracking-widest text-muted-foreground",
                          "hover:bg-muted/15 hover:text-foreground",
                          focusedSnapshotId === s.id && "border-primary/40 text-foreground"
                        )}
                      >
                        Pin
                      </button>
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
