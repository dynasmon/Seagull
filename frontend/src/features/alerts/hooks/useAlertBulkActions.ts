import { useEffect, useState } from "react";

import type { Alert } from "../types";

export function useAlertBulkActions(filtered: Alert[]) {
  const [selectedRowIds, setSelectedRowIds] = useState<Set<number>>(() => new Set());

  useEffect(() => {
    const visible = new Set(filtered.map((row) => row.id));
    setSelectedRowIds((prev) => {
      if (prev.size === 0) return prev;
      const next = new Set<number>();
      prev.forEach((id) => {
        if (visible.has(id)) next.add(id);
      });
      return next;
    });
  }, [filtered]);

  const selectedRows = filtered.filter((row) => selectedRowIds.has(row.id));

  function toggleRowSelection(alertId: number, nextChecked: boolean) {
    setSelectedRowIds((prev) => {
      const next = new Set(prev);
      if (nextChecked) next.add(alertId);
      else next.delete(alertId);
      return next;
    });
  }

  function toggleAllVisibleRows(nextChecked: boolean) {
    setSelectedRowIds((prev) => {
      if (!nextChecked) {
        const next = new Set(prev);
        filtered.forEach((row) => next.delete(row.id));
        return next;
      }
      const next = new Set(prev);
      filtered.forEach((row) => next.add(row.id));
      return next;
    });
  }

  function clearSelectedRows() {
    setSelectedRowIds(new Set());
  }

  return {
    selectedRowIds,
    selectedRows,
    toggleRowSelection,
    toggleAllVisibleRows,
    clearSelectedRows,
  };
}

export type AlertBulkActions = ReturnType<typeof useAlertBulkActions>;
