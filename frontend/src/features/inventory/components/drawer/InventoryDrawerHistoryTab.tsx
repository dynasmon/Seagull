import { useMemo } from "react";

import { Button } from "@/shared/components/Button";
import { StatusPill } from "@/shared/components/StatusPill";
import { Table, type Column } from "@/shared/components/Table";
import { InvestigationSection } from "@/shared/components/investigation";

import type { InventorySnapshotOut } from "../../types";
import { fmtDateTime } from "../../lib/inventoryFormatters";

interface InventoryDrawerHistoryTabProps {
  drawerHistory: InventorySnapshotOut[];
  focusedSnapshotId: number | null;
  setFocusedSnapshotId: (id: number) => void;
  setPinSnapshotId: (id: number) => void;
  compact: boolean;
}

type HistoryRow = InventorySnapshotOut & { _changed: boolean };

export function InventoryDrawerHistoryTab({
  drawerHistory,
  focusedSnapshotId,
  setFocusedSnapshotId,
  setPinSnapshotId,
  compact,
}: InventoryDrawerHistoryTabProps) {
  const rows = useMemo<HistoryRow[]>(
    () =>
      drawerHistory.slice(0, 20).map((s, idx) => {
        const next = drawerHistory[idx + 1];
        return { ...s, _changed: next ? s.packages_hash !== next.packages_hash : false };
      }),
    [drawerHistory],
  );

  const columns = useMemo<Array<Column<HistoryRow>>>(
    () => [
      {
        key: "collected",
        title: "Collected",
        className: "font-mono text-muted-foreground",
        render: (s) => fmtDateTime(s.collected_at),
      },
      {
        key: "packages",
        title: "Packages",
        align: "right",
        className: "font-mono text-muted-foreground",
        render: (s) => s.packages_count,
      },
      {
        key: "changed",
        title: "Changed",
        align: "right",
        render: (s) => (
          <StatusPill variant={s._changed ? "warning" : "neutral"}>{s._changed ? "changed" : "stable"}</StatusPill>
        ),
      },
      {
        key: "actions",
        title: "Actions",
        align: "right",
        render: (s) => (
          <div className="flex items-center justify-end gap-1.5">
            <Button variant="subtle" size="sm" onClick={() => setFocusedSnapshotId(s.id)}>
              Focus
            </Button>
            <Button
              variant={focusedSnapshotId === s.id ? "primary" : "subtle"}
              size="sm"
              onClick={() => setPinSnapshotId(s.id)}
            >
              Pin
            </Button>
          </div>
        ),
      },
    ],
    [focusedSnapshotId, setFocusedSnapshotId, setPinSnapshotId],
  );

  return (
    <InvestigationSection
      title="Recent snapshots"
      subtitle="Track package hash drift and pin relevant baseline states."
      bodyClassName="p-0"
    >
      {rows.length === 0 ? (
        <div className="p-3 text-[11px] text-muted-foreground">No history.</div>
      ) : (
        <Table
          className="!shadow-none !border-0 !bg-transparent !rounded-none"
          compact={compact}
          columns={columns}
          rows={rows}
          rowKey={(s) => String(s.id)}
          selectedRowKey={focusedSnapshotId != null ? String(focusedSnapshotId) : null}
        />
      )}
    </InvestigationSection>
  );
}
