import { useCallback, useMemo } from "react";

import { usePersistentState } from "@/shared/hooks/usePersistentState";
import { clampInt } from "@/shared/lib/filters";

export type DataTableSortPreference = {
  key: string;
  direction: "asc" | "desc";
};

type PersistedState = {
  page_size: number;
  compact: boolean;
  sort: DataTableSortPreference | null;
};

type Options = {
  storageKey: string;
  defaultPageSize?: number;
  minPageSize?: number;
  maxPageSize?: number;
  defaultCompact?: boolean;
  defaultSort?: DataTableSortPreference | null;
};

function sanitizeSort(raw: unknown): DataTableSortPreference | null {
  if (!raw || typeof raw !== "object") return null;
  const maybe = raw as { key?: unknown; direction?: unknown };
  const key = String(maybe.key || "").trim();
  if (!key) return null;
  const direction = maybe.direction === "asc" ? "asc" : maybe.direction === "desc" ? "desc" : null;
  if (!direction) return null;
  return { key, direction };
}

export function useDataTablePreferences(opts: Options) {
  const minPageSize = Math.max(1, opts.minPageSize ?? 10);
  const maxPageSize = Math.max(minPageSize, opts.maxPageSize ?? 500);
  const fallbackPageSize = clampInt(opts.defaultPageSize, minPageSize, maxPageSize, 50);
  const fallbackCompact = Boolean(opts.defaultCompact);
  const fallbackSort = opts.defaultSort ?? null;

  const sanitize = useCallback(
    (raw: unknown): PersistedState => {
      const candidate = (raw || {}) as Partial<PersistedState>;
      const page_size = clampInt(candidate.page_size, minPageSize, maxPageSize, fallbackPageSize);
      const compact = typeof candidate.compact === "boolean" ? candidate.compact : fallbackCompact;
      const sort = sanitizeSort(candidate.sort) ?? fallbackSort;
      return { page_size, compact, sort };
    },
    [fallbackCompact, fallbackPageSize, fallbackSort, maxPageSize, minPageSize]
  );

  const [state, setState] = usePersistentState<PersistedState>(opts.storageKey, sanitize({}), sanitize);

  const setPageSize = useCallback(
    (value: number) => {
      setState((prev) => ({
        ...prev,
        page_size: clampInt(value, minPageSize, maxPageSize, prev.page_size)
      }));
    },
    [maxPageSize, minPageSize, setState]
  );

  const setCompact = useCallback(
    (value: boolean) => {
      setState((prev) => ({ ...prev, compact: Boolean(value) }));
    },
    [setState]
  );

  const setSort = useCallback(
    (next: DataTableSortPreference | null) => {
      setState((prev) => ({ ...prev, sort: sanitizeSort(next) }));
    },
    [setState]
  );

  return useMemo(
    () => ({
      pageSize: state.page_size,
      compact: state.compact,
      sort: state.sort,
      setPageSize,
      setCompact,
      setSort,
    }),
    [setCompact, setPageSize, setSort, state.compact, state.page_size, state.sort]
  );
}

export default useDataTablePreferences;
