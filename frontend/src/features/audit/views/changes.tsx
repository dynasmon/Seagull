import { useMemo } from "react";

import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";

import AuditEventDrawer from "../components/AuditEventDrawer";
import AuditEventsTable from "../components/AuditEventsTable";
import AuditFiltersBar from "../components/AuditFiltersBar";
import { isChangeEvent } from "../lib";
import { useAuditQuery } from "../useAuditQuery";
import { useAuditEventSelection } from "../useAuditEventSelection";

const CHANGE_RESOURCES = [
  { key: "", label: "All governance objects" },
  { key: "alert_rule", label: "Rules" },
  { key: "attack_chain_allowlist", label: "Allowlists" },
  { key: "user", label: "Users" },
  { key: "platform_setting", label: "Settings" },
];

export default function AuditChangesView() {
  const q = useAuditQuery({ fixedEventType: "admin_action", defaultLimit: 120 });

  const changeRows = useMemo(() => {
    return q.visibleRows.filter((r) => {
      if (!isChangeEvent(r)) return false;
      const a = String(r.action || "").toLowerCase();
      return a.includes("create") || a.includes("update") || a.includes("patch") || a.includes("delete");
    });
  }, [q.visibleRows]);
  const selection = useAuditEventSelection(changeRows);

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
                className={active ? "ui-btn h-8 border-primary/60 bg-primary/10 px-3 text-xs font-mono" : "ui-btn-secondary h-8 px-3 text-xs font-mono"}
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
        onOpen={selection.openEvent}
        page={q.page}
        hasPrev={q.hasPrev}
        hasMore={q.hasMore}
        onPrev={q.prevPage}
        onNext={q.nextPage}
        compact={q.compact}
        setCompact={q.setCompact}
        sort={{ key: "created_at", direction: q.filters.sort }}
        onSortChange={(next) => q.setFilter("sort", next.direction)}
      />

      <AuditEventDrawer event={selection.selectedEvent} onClose={selection.closeEvent} />
    </div>
  );
}
