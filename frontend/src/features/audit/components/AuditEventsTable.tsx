import { Badge } from "@/shared/components/Badge";
import { Table } from "@/shared/components/Table";

import { eventSeverity, fmtDateTime, summarizeEvent } from "../lib";
import type { AuditEvent } from "../types";

export default function AuditEventsTable({
  rows,
  loading,
  error,
  emptyTitle,
  onOpen,
  page,
  hasPrev,
  hasMore,
  onPrev,
  onNext,
}: {
  rows: AuditEvent[];
  loading: boolean;
  error: string | null;
  emptyTitle: string;
  onOpen: (row: AuditEvent) => void;
  page: number;
  hasPrev: boolean;
  hasMore: boolean;
  onPrev: () => void;
  onNext: () => void;
}) {
  return (
    <div className="rounded-xl border border-border/60 bg-background/60 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-muted-foreground">Page {page} · {rows.length} rows loaded</div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onPrev}
            disabled={!hasPrev || loading}
            className="h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs disabled:opacity-50"
          >
            Previous
          </button>
          <button
            type="button"
            onClick={onNext}
            disabled={!hasMore || loading}
            className="h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>

      {error ? <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</div> : null}

      {loading ? (
        <div className="py-8 text-sm text-muted-foreground">Loading audit events...</div>
      ) : rows.length === 0 ? (
        <div className="py-8 text-sm text-muted-foreground">{emptyTitle}</div>
      ) : (
        <Table
          rows={rows}
          rowKey={(r) => r.id}
          columns={[
            {
              key: "created_at",
              title: "When",
              className: "whitespace-nowrap text-xs",
              render: (r) => fmtDateTime(r.created_at),
            },
            {
              key: "event",
              title: "Event",
              className: "font-mono text-xs",
              render: (r) => (
                <div className="space-y-1 min-w-[240px]">
                  <div>{r.event_type}</div>
                  <div className="text-[11px] text-muted-foreground">{r.action}</div>
                </div>
              ),
            },
            {
              key: "resource",
              title: "Resource",
              className: "font-mono text-xs",
              render: (r) => (
                <div className="space-y-1 min-w-[180px]">
                  <div>{r.resource_type}</div>
                  <div className="text-[11px] text-muted-foreground truncate max-w-[220px]">{r.resource_id || "-"}</div>
                </div>
              ),
            },
            {
              key: "actor",
              title: "Actor",
              className: "text-xs",
              render: (r) => r.actor_username || "-",
            },
            {
              key: "summary",
              title: "Summary",
              className: "text-xs",
              render: (r) => <div className="max-w-[320px] truncate">{summarizeEvent(r)}</div>,
            },
            {
              key: "badges",
              title: "Outcome",
              className: "text-xs",
              render: (r) => (
                <div className="flex gap-1">
                  <Badge variant={r.outcome === "success" ? "low" : "critical"}>{r.outcome || "unknown"}</Badge>
                  <Badge variant={eventSeverity(r)}>sev:{eventSeverity(r)}</Badge>
                </div>
              ),
            },
            {
              key: "details",
              title: "Details",
              className: "text-right",
              render: (r) => (
                <button
                  type="button"
                  onClick={() => onOpen(r)}
                  className="rounded-md border border-border/60 bg-background/40 px-2 py-1 text-xs hover:bg-muted/30"
                >
                  Open
                </button>
              ),
            },
          ]}
        />
      )}
    </div>
  );
}
