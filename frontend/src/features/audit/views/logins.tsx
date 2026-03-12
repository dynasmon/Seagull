import { useEffect, useMemo, useState } from "react";

import { getAdminLoginEvidence } from "../api";
import AuditEventDrawer from "../components/AuditEventDrawer";
import AuditEventsTable from "../components/AuditEventsTable";
import AuditFiltersBar from "../components/AuditFiltersBar";
import { fmtDateTime } from "../lib";
import { useAuditQuery } from "../useAuditQuery";
import type { AuditEvent, LoginEvidenceEvent } from "../types";
import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";
import { Table } from "@/shared/components/Table";

export default function AuditLoginsView() {
  const q = useAuditQuery({ fixedEventType: "auth", defaultLimit: 100 });
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const [evidence, setEvidence] = useState<LoginEvidenceEvent[]>([]);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);

  async function loadEvidence() {
    setEvidenceLoading(true);
    setEvidenceError(null);
    try {
      const rows = await getAdminLoginEvidence(100, true);
      setEvidence(rows || []);
    } catch (e: any) {
      setEvidenceError(e?.message || "Failed to load login evidence");
      setEvidence([]);
    } finally {
      setEvidenceLoading(false);
    }
  }

  useEffect(() => {
    loadEvidence();
  }, []);

  const filteredEvidence = useMemo(() => {
    const actor = (q.filters.actor || "").trim().toLowerCase();
    const outcome = (q.filters.outcome || "").trim().toLowerCase();
    const origin = (q.filters.origin || "").trim().toLowerCase();
    const fromMs = q.filters.from ? new Date(q.filters.from).getTime() : Number.NEGATIVE_INFINITY;
    const toMs = q.filters.to ? new Date(q.filters.to).getTime() : Number.POSITIVE_INFINITY;

    return evidence.filter((r) => {
      const ts = new Date(r.created_at).getTime();
      if (Number.isFinite(fromMs) && ts < fromMs) return false;
      if (Number.isFinite(toMs) && ts > toMs) return false;
      if (actor && !String(r.username || "").toLowerCase().includes(actor)) return false;

      if (origin) {
        const ip = String(r.ip || "").toLowerCase();
        const ua = String(r.user_agent || "").toLowerCase();
        if (!ip.includes(origin) && !ua.includes(origin)) return false;
      }

      if (outcome) {
        const out = r.succeeded ? "success" : "failure";
        if (!out.includes(outcome)) return false;
      }

      return true;
    });
  }, [evidence, q.filters.actor, q.filters.from, q.filters.origin, q.filters.outcome, q.filters.to]);

  return (
    <div className="space-y-4">
      <AuditFiltersBar
        filters={q.filters}
        setFilter={q.setFilter}
        onApply={q.reload}
        onClear={q.resetFilters}
        loading={q.loading}
        hideEventType
        hideResourceType
      />

      <AuditEventsTable
        rows={q.visibleRows}
        loading={q.loading}
        error={q.error}
        emptyTitle="No authentication events found for current filters."
        onOpen={setSelected}
        page={q.page}
        hasPrev={q.hasPrev}
        hasMore={q.hasMore}
        onPrev={q.prevPage}
        onNext={q.nextPage}
      />

      <Card title="Login Evidence Feed" right="/api/admin/login-history">
        {evidenceError ? <div className="text-sm text-red-400">{evidenceError}</div> : null}
        {evidenceLoading ? (
          <div className="py-6 text-sm text-muted-foreground">Loading login evidence...</div>
        ) : filteredEvidence.length === 0 ? (
          <div className="py-6 text-sm text-muted-foreground">No login evidence in current window.</div>
        ) : (
          <Table
            rows={filteredEvidence}
            rowKey={(r, i) => `${r.created_at}-${r.username}-${i}`}
            columns={[
              { key: "created_at", title: "When", className: "text-xs whitespace-nowrap", render: (r) => fmtDateTime(r.created_at) },
              { key: "username", title: "Username", className: "text-xs font-mono" },
              { key: "method", title: "Method", className: "text-xs font-mono" },
              { key: "ip", title: "Origin", className: "text-xs font-mono", render: (r) => r.ip || "-" },
              {
                key: "succeeded",
                title: "Result",
                className: "text-xs",
                render: (r) => (
                  <Badge variant={r.succeeded ? "low" : "critical"}>{r.succeeded ? "success" : "failed"}</Badge>
                ),
              },
            ]}
          />
        )}
      </Card>

      <AuditEventDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
