import { useMemo, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";

import AuditEventDrawer from "../components/AuditEventDrawer";
import AuditEventsTable from "../components/AuditEventsTable";
import AuditFiltersBar from "../components/AuditFiltersBar";
import { isChangeEvent } from "../lib";
import { useAuditQuery } from "../useAuditQuery";
import type { AuditEvent } from "../types";

const CHANGE_RESOURCES = [
  { key: "", label: "All governance objects" },
  { key: "alert_rule", label: "Rules" },
  { key: "attack_chain_allowlist", label: "Allowlists" },
  { key: "user", label: "Users" },
  { key: "platform_setting", label: "Settings" },
];

export default function AuditChangesView() {
  const q = useAuditQuery({ fixedEventType: "admin_action", defaultLimit: 120 });
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const changeRows = useMemo(() => {
    return q.visibleRows.filter((r) => {
      if (!isChangeEvent(r)) return false;
      const a = String(r.action || "").toLowerCase();
      return a.includes("create") || a.includes("update") || a.includes("patch") || a.includes("delete");
    });
  }, [q.visibleRows]);

  return (
    <div className="space-y-4">
      <AuditFiltersBar
        filters={q.filters}
        setFilter={q.setFilter}
        onApply={q.reload}
        onClear={q.resetFilters}
        loading={q.loading}
        hideEventType
      />

      <Card title="Governance Scope">
        <div className="flex flex-wrap gap-2">
          {CHANGE_RESOURCES.map((r) => {
            const active = q.filters.resourceType === r.key;
            return (
              <button
                key={r.label}
                type="button"
                onClick={() => q.setFilter("resourceType", r.key)}
                className={`h-8 rounded-md border px-3 text-xs font-mono ${active ? "border-primary bg-primary/10" : "border-border/60 bg-background/40"}`}
              >
                {r.label}
              </button>
            );
          })}
        </div>
        <div className="mt-3 text-xs text-muted-foreground">
          Values marked as <span className="font-mono">&lt;redacted&gt;</span> are masked by backend policy and are shown as-is.
        </div>
        <div className="mt-2 flex flex-wrap gap-2">
          <Badge variant="neutral">before/after available when safe</Badge>
          <Badge variant="neutral">changed fields tracked</Badge>
          <Badge variant="neutral">correlation via operation_id/request_id/trace_id</Badge>
        </div>
      </Card>

      <AuditEventsTable
        rows={changeRows}
        loading={q.loading}
        error={q.error}
        emptyTitle="No governance changes found for current filters."
        onOpen={setSelected}
        page={q.page}
        hasPrev={q.hasPrev}
        hasMore={q.hasMore}
        onPrev={q.prevPage}
        onNext={q.nextPage}
      />

      <AuditEventDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
