import { useState } from "react";

import AuditEventDrawer from "../components/AuditEventDrawer";
import AuditEventsTable from "../components/AuditEventsTable";
import AuditFiltersBar from "../components/AuditFiltersBar";
import { useAuditQuery } from "../useAuditQuery";
import type { AuditEvent } from "../types";

export default function AuditAdminActionsView() {
  const q = useAuditQuery({ fixedEventType: "admin_action", defaultLimit: 100 });
  const [selected, setSelected] = useState<AuditEvent | null>(null);

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
