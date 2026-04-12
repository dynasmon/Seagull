import { clampInt } from "@/shared/lib/filters";

export type DataTableSortPreference = {
  key: string;
  direction: "asc" | "desc";
};

export type PersistedDataTableState = {
  page_size: number;
  compact: boolean;
  sort: DataTableSortPreference | null;
};

export function sanitizeDataTableSort(raw: unknown): DataTableSortPreference | null {
  if (!raw || typeof raw !== "object") return null;
  const maybe = raw as { key?: unknown; direction?: unknown };
  const key = String(maybe.key || "").trim();
  if (!key) return null;
  const direction = maybe.direction === "asc" ? "asc" : maybe.direction === "desc" ? "desc" : null;
  if (!direction) return null;
  return { key, direction };
}

export function sanitizeDataTableState(
  raw: unknown,
  opts: {
    minPageSize: number;
    maxPageSize: number;
    fallbackPageSize: number;
    fallbackCompact: boolean;
    fallbackSort: DataTableSortPreference | null;
  }
): PersistedDataTableState {
  const candidate = (raw || {}) as Partial<PersistedDataTableState>;
  const page_size = clampInt(candidate.page_size, opts.minPageSize, opts.maxPageSize, opts.fallbackPageSize);
  const compact = typeof candidate.compact === "boolean" ? candidate.compact : opts.fallbackCompact;
  const sort = sanitizeDataTableSort(candidate.sort) ?? opts.fallbackSort;
  return { page_size, compact, sort };
}
