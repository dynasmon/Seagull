import {
  InvestigationFactCard,
  InvestigationKeyValueGrid,
  InvestigationSection,
  InvestigationSummaryGrid,
} from "@/shared/components/investigation";

import type { AgentDetail } from "@/features/agents/types";
import type { InventorySnapshotOut } from "../../types";
import { fmtDateTime } from "../../lib/inventoryFormatters";
import { parseWarnings } from "../../lib/inventoryParsers";
import { extractExtraDomainMetrics } from "../../lib/inventoryPresenters";

interface InventoryDrawerOverviewTabProps {
  drawerAgent: AgentDetail;
  drawerLatest: InventorySnapshotOut | null;
}

export function InventoryDrawerOverviewTab({ drawerAgent, drawerLatest }: InventoryDrawerOverviewTabProps) {
  return (
    <InvestigationSection title="Inventory overview" subtitle="Quick health and baseline context for this endpoint.">
      <InvestigationSummaryGrid>
        <InvestigationFactCard label="Display name" value={drawerAgent.display_name || "-"} mono />
        <InvestigationFactCard label="Description" value={drawerAgent.description || "-"} />
        <InvestigationFactCard label="Tags" value={drawerAgent.tags.length ? drawerAgent.tags.join(", ") : "-"} mono />
        <InvestigationFactCard label="Last seen" value={fmtDateTime(drawerAgent.last_seen_at)} mono />
        <InvestigationFactCard label="Snapshot manager" value={drawerLatest?.manager || "-"} mono />
        <InvestigationFactCard
          label="Package count"
          value={drawerLatest ? String(drawerLatest.packages_count) : "-"}
          mono
        />
      </InvestigationSummaryGrid>

      <div className="mt-4">
        <InvestigationKeyValueGrid
          entries={[
            ...extractExtraDomainMetrics(drawerLatest?.extra || {}).map((m) => ({ key: m.key, value: m.value })),
            ...parseWarnings(drawerLatest?.extra || {})
              .slice(0, 8)
              .map((w, idx) => ({ key: `warning_${idx + 1}`, value: w })),
          ]}
        />
      </div>
    </InvestigationSection>
  );
}
