import { Badge } from "@/shared/components/Badge";
import AsyncState from "@/shared/components/AsyncState";
import { Button } from "@/shared/components/Button";
import { Table, type TableSortState } from "@/shared/components/Table";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";

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
            <div className="hidden items-center sm:flex">
              <ToggleSwitch label="Compact" checked={compact} onChange={(e) => setCompact(e.target.checked)} />
            </div>
          ) : null}

          <Button variant="secondary" size="sm" onClick={onPrev} disabled={!hasPrev || loading}>
            Previous
          </Button>
          <Button variant="secondary" size="sm" onClick={onNext} disabled={!hasMore || loading}>
            Next
          </Button>
        </div>
      </div>

      <AsyncState
        loading={loading}
        error={error}
        empty={rows.length === 0}
        loadingLabel="Loading audit events..."
        emptyTitle={emptyTitle}
        className="px-0 py-8"
      />

      {!loading && !error && rows.length > 0 ? (
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
              className: "text-xs font-mono",
              sortable: true,
              sortKey: "created_at",
              render: (r) => fmtDateTime(r.created_at),
            },
            {
              key: "event",
              title: "Event",
              className: "font-mono text-xs",
              render: (r) => (
                <div className="space-y-1">
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
                <div className="space-y-1">
                  <div>{r.resource_type}</div>
                  <div className="text-[11px] text-muted-foreground break-all">{r.resource_id || "-"}</div>
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
              render: (r) => <div className="line-clamp-2">{summarizeEvent(r)}</div>,
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
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={(event) => {
                    event.stopPropagation();
                    onOpen(r);
                  }}
                >
                  Open
                </Button>
              ),
            },
          ]}
        />
      ) : null}
    </div>
  );
}
