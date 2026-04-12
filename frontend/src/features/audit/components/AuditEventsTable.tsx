import { Badge } from "@/shared/components/Badge";
import { Table, type TableSortState } from "@/shared/components/Table";

import { eventSeverity, fmtDateTime, summarizeEvent } from "../lib";
import type { AuditEvent } from "../types";

function auditRowKey(row: AuditEvent, index: number): string {
  return `${row.id || "na"}-${row.created_at || "na"}-${row.operation_id || "na"}-${index}`;
}

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
  compact = false,
  setCompact,
  sort = null,
  onSortChange,
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
  compact?: boolean;
  setCompact?: (next: boolean) => void;
  sort?: TableSortState | null;
  onSortChange?: (next: TableSortState) => void;
}) {
  return (
    <div className="ui-card-shell space-y-3 p-4">
      <div className="flex items-center justify-between">
        <div className="text-xs text-muted-foreground font-mono">Page {page} · {rows.length} rows loaded</div>
        <div className="flex items-center gap-2">
          {setCompact ? (
            <div className="hidden items-center gap-1 sm:flex">
              <button
                type="button"
                onClick={() => setCompact(false)}
                className={compact ? "ui-btn-secondary h-8 px-2 text-xs" : "ui-btn h-8 px-2 text-xs"}
              >
                Comfortable
              </button>
              <button
                type="button"
                onClick={() => setCompact(true)}
                className={compact ? "ui-btn h-8 px-2 text-xs" : "ui-btn-secondary h-8 px-2 text-xs"}
              >
                Compact
              </button>
            </div>
          ) : null}

          <button
            type="button"
            onClick={onPrev}
            disabled={!hasPrev || loading}
            className="ui-btn-secondary h-8 px-3 text-xs disabled:opacity-50"
          >
            Previous
          </button>
          <button
            type="button"
            onClick={onNext}
            disabled={!hasMore || loading}
            className="ui-btn-secondary h-8 px-3 text-xs disabled:opacity-50"
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
          rowKey={auditRowKey}
          compact={compact}
          sort={sort}
          onSortChange={onSortChange}
          onRowClick={(row) => onOpen(row)}
          columns={[
            {
              key: "created_at",
              title: "When",
              className: "whitespace-nowrap text-xs font-mono",
              sortable: true,
              sortKey: "created_at",
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
              render: (r) => (
                <div className="font-mono text-[12px]">{r.actor_username || "-"}</div>
              ),
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
                  onClick={(event) => {
                    event.stopPropagation();
                    onOpen(r);
                  }}
                  className="ui-btn-secondary h-7 px-2 text-xs"
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
