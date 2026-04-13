import { useEffect, useState } from "react";

import { cx } from "@/shared/lib/cx";
import { DataFilterGroup, DataViewFilterBar } from "@/shared/components/DataView";

import type { AuditFilters } from "../types";

type Props = {
  filters: AuditFilters;
  onApplyFilters: (next: AuditFilters) => void;
  onClear: () => void;
  loading?: boolean;
  hideEventType?: boolean;
  hideResourceType?: boolean;
};

export default function AuditFiltersBar({
  filters,
  onApplyFilters,
  onClear,
  loading = false,
  hideEventType = false,
  hideResourceType = false,
}: Props) {
  const pageSizeOptions = [25, 50, 100, 200, 500];
  const [draft, setDraft] = useState(filters);
  const hasCustomLimit = !pageSizeOptions.includes(draft.limit);

  useEffect(() => {
    setDraft(filters);
  }, [filters]);

  function patch<K extends keyof AuditFilters>(key: K, value: AuditFilters[K]) {
    setDraft((prev) => ({ ...prev, [key]: value }));
  }

  return (
    <form
      className="ui-card-shell space-y-4 p-4"
      onSubmit={(e) => {
        e.preventDefault();
        onApplyFilters(draft);
      }}
    >
      <DataViewFilterBar className="md:grid-cols-2 xl:grid-cols-4">
        <DataFilterGroup label="Text query">
          <input
            value={draft.query}
            onChange={(e) => patch("query", e.target.value)}
            placeholder="id, action, resource, trace id..."
            className="ui-input"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Actor">
          <input
            value={draft.actor}
            onChange={(e) => patch("actor", e.target.value)}
            placeholder="admin"
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Action">
          <input
            value={draft.action}
            onChange={(e) => patch("action", e.target.value)}
            placeholder="create, update, delete"
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Outcome">
          <input
            value={draft.outcome}
            onChange={(e) => patch("outcome", e.target.value)}
            placeholder="success, failure, denied"
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        {!hideEventType ? (
          <DataFilterGroup label="Category">
            <input
              value={draft.eventType}
              onChange={(e) => patch("eventType", e.target.value)}
              placeholder="admin_action, auth"
              className="ui-input font-mono"
            />
          </DataFilterGroup>
        ) : null}

        {!hideResourceType ? (
          <DataFilterGroup label="Resource">
            <input
              value={draft.resourceType}
              onChange={(e) => patch("resourceType", e.target.value)}
              placeholder="user, alert_rule..."
              className="ui-input font-mono"
            />
          </DataFilterGroup>
        ) : null}

        <DataFilterGroup label="Origin (IP/UA)">
          <input
            value={draft.origin}
            onChange={(e) => patch("origin", e.target.value)}
            placeholder="10.0.0.1"
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="From">
          <input
            type="datetime-local"
            value={draft.from}
            onChange={(e) => patch("from", e.target.value)}
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="To">
          <input
            type="datetime-local"
            value={draft.to}
            onChange={(e) => patch("to", e.target.value)}
            className="ui-input font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Rows per page">
          <select
            value={String(draft.limit)}
            onChange={(e) => patch("limit", Number(e.target.value))}
            className="ui-select font-mono"
          >
            {hasCustomLimit ? (
              <option value={String(draft.limit)}>
                {draft.limit}
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
            value={draft.sort}
            onChange={(e) => patch("sort", e.target.value as AuditFilters["sort"])}
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
          onClick={() => {
            setDraft(filters);
            onClear();
          }}
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
