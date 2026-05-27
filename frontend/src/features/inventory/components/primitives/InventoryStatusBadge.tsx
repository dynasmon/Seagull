import { cx } from "@/shared/lib/cx";
import type { FleetHealthRow } from "../../types";

interface InventoryStatusBadgeProps {
  status: FleetHealthRow["inventory_status"];
}

export function InventoryStatusBadge({ status }: InventoryStatusBadgeProps) {
  const klass =
    status === "fresh"
      ? "border-success/40 text-success bg-success/10"
      : status === "stale"
        ? "border-warning/40 text-warning bg-warning/10"
        : "border-danger/40 text-danger bg-danger/10";
  const label = status === "fresh" ? "fresh" : status === "stale" ? "stale" : "no inventory";
  return (
    <span className={cx("inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-mono uppercase", klass)}>
      {label}
    </span>
  );
}
