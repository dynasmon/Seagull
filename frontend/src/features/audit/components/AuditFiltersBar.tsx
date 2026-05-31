import { useEffect, useState } from "react";

import { Button } from "@/shared/components/Button";
import { DataFilterGroup, DataViewFilterBar } from "@/shared/components/DataView";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextInput } from "@/shared/components/TextInput";

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
          <TextInput
            value={draft.query}
            onChange={(e) => patch("query", e.target.value)}
            placeholder="id, action, resource, trace id..."
          />
        </DataFilterGroup>

        <DataFilterGroup label="Actor">
          <TextInput
            value={draft.actor}
            onChange={(e) => patch("actor", e.target.value)}
            placeholder="admin"
            className="font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Action">
          <TextInput
            value={draft.action}
            onChange={(e) => patch("action", e.target.value)}
            placeholder="create, update, delete"
            className="font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Outcome">
          <TextInput
            value={draft.outcome}
            onChange={(e) => patch("outcome", e.target.value)}
            placeholder="success, failure, denied"
            className="font-mono"
          />
        </DataFilterGroup>

        {!hideEventType ? (
          <DataFilterGroup label="Category">
            <TextInput
              value={draft.eventType}
              onChange={(e) => patch("eventType", e.target.value)}
              placeholder="admin_action, auth"
              className="font-mono"
            />
          </DataFilterGroup>
        ) : null}

        {!hideResourceType ? (
          <DataFilterGroup label="Resource">
            <TextInput
              value={draft.resourceType}
              onChange={(e) => patch("resourceType", e.target.value)}
              placeholder="user, alert_rule..."
              className="font-mono"
            />
          </DataFilterGroup>
        ) : null}

        <DataFilterGroup label="Origin (IP/UA)">
          <TextInput
            value={draft.origin}
            onChange={(e) => patch("origin", e.target.value)}
            placeholder="10.0.0.1"
            className="font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="From">
          <TextInput
            type="datetime-local"
            value={draft.from}
            onChange={(e) => patch("from", e.target.value)}
            className="font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="To">
          <TextInput
            type="datetime-local"
            value={draft.to}
            onChange={(e) => patch("to", e.target.value)}
            className="font-mono"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Rows per page">
          <SelectInput
            value={String(draft.limit)}
            onChange={(e) => patch("limit", Number(e.target.value))}
            className="font-mono"
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
          </SelectInput>
        </DataFilterGroup>

        <DataFilterGroup label="Order">
          <SelectInput
            value={draft.sort}
            onChange={(e) => patch("sort", e.target.value as AuditFilters["sort"])}
            className="font-mono"
          >
            <option value="desc">Newest first</option>
            <option value="asc">Oldest first</option>
          </SelectInput>
        </DataFilterGroup>
      </DataViewFilterBar>

      <div className="flex flex-wrap items-center gap-2 pt-1">
        <Button type="submit" variant="primary" size="md" disabled={loading}>
          {loading ? "Applying..." : "Apply filters"}
        </Button>

        <Button
          type="button"
          variant="secondary"
          size="md"
          onClick={() => {
            setDraft(filters);
            onClear();
          }}
        >
          Clear
        </Button>

        <div className="text-xs text-muted-foreground font-mono">
          Text/origin filters are applied to loaded page; other filters are server-side.
        </div>
      </div>
    </form>
  );
}
