import EmptyState from "@/shared/components/EmptyState";
import { Table } from "@/shared/components/Table";
import { InvestigationSection } from "@/shared/components/investigation";
import { cx } from "@/shared/lib/cx";

import type { InventorySnapshotOut, PackageEntry } from "../../types";
import { filterPackages } from "../../lib/inventoryPackageFilters";

interface InventoryDrawerPackagesTabProps {
  drawerLatest: InventorySnapshotOut | null;
  pkgQuery: string;
  setPkgQuery: (q: string) => void;
  compact: boolean;
}

export function InventoryDrawerPackagesTab({ drawerLatest, pkgQuery, setPkgQuery, compact }: InventoryDrawerPackagesTabProps) {
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
          <input
            value={pkgQuery}
            onChange={(e) => setPkgQuery(e.target.value)}
            placeholder="Search packages..."
            className={cx(
              "w-[260px] max-w-full border border-border/60 bg-background/40 px-3 py-2",
              "text-[11px] text-foreground outline-none font-mono",
              "placeholder:text-muted-foreground/60 focus:ring-2 focus:ring-primary/30"
            )}
          />
        </div>

        {allPackages.length === 0 ? (
          <EmptyState title="NO PACKAGES" hint="No package entries in the latest snapshot." />
        ) : visible.length === 0 ? (
          <EmptyState title="NO MATCHES" hint="Your filter did not match any package." />
        ) : (
          <Table
            compact={compact}
            scrollX={false}
            className="text-xs"
            columns={[
              { key: "name", title: "NAME", className: "font-mono text-foreground" },
              { key: "version", title: "VERSION", className: "font-mono text-muted-foreground w-44" },
              {
                key: "arch",
                title: "ARCH",
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
