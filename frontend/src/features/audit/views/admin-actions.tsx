import AuditEventDrawer from "../components/AuditEventDrawer";
import AuditEventsTable from "../components/AuditEventsTable";
import AuditFiltersBar from "../components/AuditFiltersBar";
import { useAuditQuery } from "../useAuditQuery";
import { useAuditEventSelection } from "../useAuditEventSelection";

export default function AuditAdminActionsView() {
  const q = useAuditQuery({ fixedEventType: "admin_action", defaultLimit: 100 });
  const selection = useAuditEventSelection(q.visibleRows);

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

      <AuditEventsTable
        rows={q.visibleRows}
        loading={q.loading}
        error={q.error}
        emptyTitle="No administrative actions found for current filters."
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
