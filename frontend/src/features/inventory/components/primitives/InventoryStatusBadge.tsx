import { StatusPill } from "@/shared/components/StatusPill";
import type { StatusVariant } from "@/shared/components/StatusPill";

import type { FleetHealthRow } from "../../types";

interface InventoryStatusBadgeProps {
  status: FleetHealthRow["inventory_status"];
}

export function InventoryStatusBadge({ status }: InventoryStatusBadgeProps) {
  const variant: StatusVariant = status === "fresh" ? "active" : status === "stale" ? "warning" : "danger";
  const label = status === "fresh" ? "fresh" : status === "stale" ? "stale" : "no inventory";
  return (
    <StatusPill variant={variant} withDot>
      {label}
    </StatusPill>
  );
}
