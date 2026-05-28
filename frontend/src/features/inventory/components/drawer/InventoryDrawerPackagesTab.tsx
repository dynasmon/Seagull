import EmptyState from "@/shared/components/EmptyState";
import { Table } from "@/shared/components/Table";
import { TextInput } from "@/shared/components/TextInput";
import { InvestigationSection } from "@/shared/components/investigation";

import type { InventorySnapshotOut, PackageEntry } from "../../types";
import { filterPackages } from "../../lib/inventoryPackageFilters";

interface InventoryDrawerPackagesTabProps {
  drawerLatest: InventorySnapshotOut | null;
  pkgQuery: string;
  setPkgQuery: (q: string) => void;
  compact: boolean;
}

export function InventoryDrawerPackagesTab({
  drawerLatest,
  pkgQuery,
  setPkgQuery,
  compact,
}: InventoryDrawerPackagesTabProps) {
  if (!drawerLatest) {
    return <EmptyState title="No snapshot" hint="No package list available." />;
  }

  const allPackages = drawerLatest.packages || [];
  const filtered = filterPackages(allPackages, pkgQuery);
  const visible = filtered.slice(0, 200);

  return (
    <InvestigationSection title="Package evidence" subtitle="Search the latest package list without leaving the drawer.">
      <div className="space-y-3">
        <div className="flex items-end justify-between gap-3">
          <div className="text-[11px] text-muted-foreground">Showing up to 200 entries from latest snapshot.</div>
          <TextInput
            type="search"
            value={pkgQuery}
            onChange={(e) => setPkgQuery(e.target.value)}
            placeholder="Search packages..."
            className="w-[260px] max-w-full font-mono"
          />
        </div>

        {allPackages.length === 0 ? (
          <EmptyState title="No packages" hint="No package entries in the latest snapshot." />
        ) : visible.length === 0 ? (
          <EmptyState title="No matches" hint="Your filter did not match any package." />
        ) : (
          <Table
            compact={compact}
            scrollX={false}
            className="text-xs"
            columns={[
              { key: "name", title: "Name", className: "font-mono text-foreground" },
              { key: "version", title: "Version", className: "font-mono text-muted-foreground w-44" },
              {
                key: "arch",
                title: "Arch",
                className: "text-right font-mono text-muted-foreground w-20",
                render: (p: PackageEntry) => p.arch || "",
              },
            ]}
            rows={visible}
            rowKey={(p: PackageEntry, i) => `${p.name}-${p.version}-${p.arch || ""}-${i}`}
          />
        )}
      </div>
    </InvestigationSection>
  );
}
