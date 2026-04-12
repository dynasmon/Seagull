import { cx } from "@/shared/lib/cx";
import { DataFilterGroup, DataViewFilterBar } from "@/shared/components/DataView";

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
  const pageSizeOptions = [25, 50, 100, 200, 500];
  const hasCustomLimit = !pageSizeOptions.includes(filters.limit);

  return (
    <form
      className="ui-card-shell space-y-4 p-4"
      onSubmit={(e) => {
        e.preventDefault();
        onApply();
      }}
    >
      <DataViewFilterBar className="md:grid-cols-2 xl:grid-cols-4">
        <DataFilterGroup label="Text query">
          <input
            value={filters.query}
            onChange={(e) => setFilter("query", e.target.value)}
            placeholder="id, action, resource, trace id..."
            className="ui-input"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Actor">
          <input
            value={filters.actor}
            onChange={(e) => setFilter("actor", e.target.value)}
            placeholder="admin"
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Action">
          <input
            value={filters.action}
            onChange={(e) => setFilter("action", e.target.value)}
            placeholder="create, update, delete"
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Outcome">
          <input
            value={filters.outcome}
            onChange={(e) => setFilter("outcome", e.target.value)}
            placeholder="success, failure, denied"
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        {!hideEventType ? (
          <DataFilterGroup label="Category">
            <input
              value={filters.eventType}
              onChange={(e) => setFilter("eventType", e.target.value)}
              placeholder="admin_action, auth"
              className="ui-input font-mono"
            />
          </DataFilterGroup>
        ) : null}

        {!hideResourceType ? (
          <DataFilterGroup label="Resource">
            <input
              value={filters.resourceType}
              onChange={(e) => setFilter("resourceType", e.target.value)}
              placeholder="user, alert_rule..."
              className="ui-input font-mono"
            />
          </DataFilterGroup>
        ) : null}

        <DataFilterGroup label="Origin (IP/UA)">
          <input
            value={filters.origin}
            onChange={(e) => setFilter("origin", e.target.value)}
            placeholder="10.0.0.1"
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="From">
          <input
            type="datetime-local"
            value={filters.from}
            onChange={(e) => setFilter("from", e.target.value)}
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="To">
          <input
            type="datetime-local"
            value={filters.to}
            onChange={(e) => setFilter("to", e.target.value)}
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Rows per page">
          <select
            value={String(filters.limit)}
            onChange={(e) => setFilter("limit", Number(e.target.value))}
            className="ui-select font-mono"
          >
            {hasCustomLimit ? (
              <option value={String(filters.limit)}>
                {filters.limit}
              </option>
            ) : null}
            {pageSizeOptions.map((opt) => (
              <option key={opt} value={String(opt)}>
                {opt}
              </option>
            ))}
          </select>
        </DataFilterGroup>

        <DataFilterGroup label="Order">
          <select
            value={filters.sort}
            onChange={(e) => setFilter("sort", e.target.value as "asc" | "desc")}
            className="ui-select font-mono"
          >
            <option value="desc">Newest first</option>
            <option value="asc">Oldest first</option>
          </select>
        </DataFilterGroup>
      </DataViewFilterBar>

      <div className="flex flex-wrap items-center gap-2 pt-1">
        <button
          type="submit"
          disabled={loading}
          className={cx(
            "ui-btn h-9 border-primary/60 bg-primary/95 px-3 text-primary-foreground",
            "hover:bg-primary disabled:opacity-60"
          )}
        >
          {loading ? "Applying..." : "Apply filters"}
        </button>

        <button
          type="button"
          onClick={onClear}
          className="ui-btn-secondary h-9 px-3"
        >
          Clear
        </button>

        <div className="text-xs text-muted-foreground font-mono">
          Text/origin filters are applied to loaded page; other filters are server-side.
        </div>
      </div>
    </form>
  );
}
