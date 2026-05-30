import EmptyState from "@/shared/components/EmptyState";
import { JsonBlock } from "@/shared/components/JsonBlock";
import {
  InvestigationFactCard,
  InvestigationRawJsonPanel,
  InvestigationSection,
  InvestigationSummaryGrid,
} from "@/shared/components/investigation";

import type { InventorySnapshotOut } from "../../types";
import { fmtDateTime } from "../../lib/inventoryFormatters";

interface InventoryDrawerSnapshotTabProps {
  drawerLatest: InventorySnapshotOut | null;
}

export function InventoryDrawerSnapshotTab({ drawerLatest }: InventoryDrawerSnapshotTabProps) {
  if (!drawerLatest) {
    return <EmptyState title="No snapshot" hint="No inventory snapshot for this agent." />;
  }

  const extra = drawerLatest.extra || {};
  const domainEntries = [
    { key: "processes", value: extra.processes ?? extra.runtime_processes ?? extra.process_list },
    { key: "network", value: extra.network_connections ?? extra.connections ?? extra.network_interfaces ?? extra.interfaces },
    { key: "services", value: extra.services ?? extra.systemd_services ?? extra.listening_services },
    { key: "identity", value: extra.users ?? extra.identities ?? extra.accounts ?? extra.groups },
  ].filter((x) => x.value !== undefined);

  return (
    <div className="space-y-4">
      <InvestigationSection title="Latest snapshot details">
        <InvestigationSummaryGrid>
          <InvestigationFactCard label="Collected" value={fmtDateTime(drawerLatest.collected_at)} mono />
          <InvestigationFactCard label="Manager" value={drawerLatest.manager || "-"} mono />
          <InvestigationFactCard label="Schema" value={String(drawerLatest.schema_version)} mono />
          <InvestigationFactCard label="Packages hash" value={drawerLatest.packages_hash || "-"} mono />
          <InvestigationFactCard label="Packages count" value={String(drawerLatest.packages_count)} mono />
          <InvestigationFactCard
            label="OS"
            value={drawerLatest.os?.pretty_name || drawerLatest.os?.name || drawerLatest.os?.id || "unknown"}
            mono
          />
        </InvestigationSummaryGrid>
      </InvestigationSection>

      <InvestigationSection title="Domain evidence">
        {domainEntries.length === 0 ? (
          <EmptyState title="No domain evidence" hint="This snapshot did not include process/network/service/identity extras." />
        ) : (
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            {domainEntries.map((entry) => (
              <div key={entry.key} className="rounded-md border border-border/60 bg-background/30 p-3">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{entry.key}</div>
                <JsonBlock value={entry.value} showControls={false} maxHeight="220px" className="mt-2" />
              </div>
            ))}
          </div>
        )}
      </InvestigationSection>

      <InvestigationRawJsonPanel value={drawerLatest} title="Raw snapshot JSON" />
    </div>
  );
}
