import PageHeader from "@/shared/components/PageHeader";
import { Button } from "@/shared/components/Button";

import { fmtDateTime } from "../lib/inventoryFormatters";

interface InventoryHeaderProps {
  compact: boolean;
  onToggleCompact: () => void;
  lastUpdatedAt: Date | null;
  busy: boolean;
  onRefresh: () => void;
}

export function InventoryHeader({ compact, onToggleCompact, lastUpdatedAt, busy, onRefresh }: InventoryHeaderProps) {
  const toolbarRight = (
    <div className="flex items-center gap-3">
      <Button variant="subtle" size="lg" onClick={onToggleCompact}>
        {compact ? "Compact rows" : "Comfortable rows"}
      </Button>
      <div className="hidden md:block text-[11px] font-mono text-muted-foreground">
        {lastUpdatedAt ? `Updated ${fmtDateTime(lastUpdatedAt.toISOString())}` : ""}
      </div>
      <Button variant="subtle" size="lg" onClick={onRefresh} disabled={busy}>
        Refresh
      </Button>
    </div>
  );

  return (
    <PageHeader
      title="Inventory"
      breadcrumb={["Assets"]}
      description={
        <span>
          IT hygiene workspace across assets, software, runtime, and service posture. Click any agent row to open the inspector drawer.
        </span>
      }
      toolbarRight={toolbarRight}
    />
  );
}
