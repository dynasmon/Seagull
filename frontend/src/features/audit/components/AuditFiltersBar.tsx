import { cx } from "@/shared/lib/cx";

import type { AuditFilters } from "../types";

type Props = {
  filters: AuditFilters;
  setFilter: (name: keyof AuditFilters, value: string | number) => void;
  onApply: () => void;
  onClear: () => void;
  loading?: boolean;
  hideEventType?: boolean;
  hideResourceType?: boolean;
};

export default function AuditFiltersBar({
  filters,
  setFilter,
  onApply,
  onClear,
  loading = false,
  hideEventType = false,
  hideResourceType = false,
}: Props) {
  return (
    <div className="rounded-xl border border-border/60 bg-background/60 p-4 space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
        <label className="space-y-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Text query</div>
          <input
            value={filters.query}
            onChange={(e) => setFilter("query", e.target.value)}
            placeholder="id, action, resource, trace id..."
            className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none focus:ring-1 focus:ring-primary/40"
          />
        </label>

        <label className="space-y-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Actor</div>
          <input
            value={filters.actor}
            onChange={(e) => setFilter("actor", e.target.value)}
            placeholder="admin"
            className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none focus:ring-1 focus:ring-primary/40"
          />
        </label>

        <label className="space-y-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Action</div>
          <input
            value={filters.action}
            onChange={(e) => setFilter("action", e.target.value)}
            placeholder="create, update, delete"
            className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none focus:ring-1 focus:ring-primary/40"
          />
        </label>

        <label className="space-y-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Outcome</div>
          <input
            value={filters.outcome}
            onChange={(e) => setFilter("outcome", e.target.value)}
            placeholder="success, failure, denied"
            className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none focus:ring-1 focus:ring-primary/40"
          />
        </label>

        {!hideEventType && (
          <label className="space-y-1">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Category</div>
            <input
              value={filters.eventType}
              onChange={(e) => setFilter("eventType", e.target.value)}
              placeholder="admin_action, auth"
              className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none focus:ring-1 focus:ring-primary/40"
            />
          </label>
        )}

        {!hideResourceType && (
          <label className="space-y-1">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Resource</div>
            <input
              value={filters.resourceType}
              onChange={(e) => setFilter("resourceType", e.target.value)}
              placeholder="user, alert_rule..."
              className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none focus:ring-1 focus:ring-primary/40"
            />
          </label>
        )}

        <label className="space-y-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Origin (IP/UA)</div>
          <input
            value={filters.origin}
            onChange={(e) => setFilter("origin", e.target.value)}
            placeholder="10.0.0.1"
            className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none focus:ring-1 focus:ring-primary/40"
          />
        </label>

        <label className="space-y-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">From</div>
          <input
            type="datetime-local"
            value={filters.from}
            onChange={(e) => setFilter("from", e.target.value)}
            className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none focus:ring-1 focus:ring-primary/40"
          />
        </label>

        <label className="space-y-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">To</div>
          <input
            type="datetime-local"
            value={filters.to}
            onChange={(e) => setFilter("to", e.target.value)}
            className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none focus:ring-1 focus:ring-primary/40"
          />
        </label>

        <label className="space-y-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Limit</div>
          <input
            value={String(filters.limit)}
            onChange={(e) => setFilter("limit", e.target.value)}
            className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none focus:ring-1 focus:ring-primary/40"
          />
        </label>

        <label className="space-y-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Order</div>
          <select
            value={filters.sort}
            onChange={(e) => setFilter("sort", e.target.value as "asc" | "desc")}
            className="h-9 w-full rounded-md border border-border/60 bg-background/40 px-3 text-sm font-mono outline-none focus:ring-1 focus:ring-primary/40"
          >
            <option value="desc">Newest first</option>
            <option value="asc">Oldest first</option>
          </select>
        </label>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onApply}
          disabled={loading}
          className={cx(
            "h-9 rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground",
            "hover:opacity-95 disabled:opacity-60"
          )}
        >
          {loading ? "Applying..." : "Apply filters"}
        </button>

        <button
          type="button"
          onClick={onClear}
          className="h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm hover:bg-muted/30"
        >
          Clear
        </button>

        <div className="text-xs text-muted-foreground">
          Text/origin filters are applied to loaded page; other filters are server-side.
        </div>
      </div>
    </div>
  );
}
