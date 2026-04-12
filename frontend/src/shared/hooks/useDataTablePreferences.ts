import { useCallback, useMemo } from "react";

import { usePersistentState } from "@/shared/hooks/usePersistentState";
import { clampInt } from "@/shared/lib/filters";
import {
  sanitizeDataTableSort,
  sanitizeDataTableState,
  type DataTableSortPreference,
  type PersistedDataTableState,
} from "@/shared/lib/dataTablePreferences";

export type { DataTableSortPreference };

type Options = {
  storageKey: string;
  defaultPageSize?: number;
  minPageSize?: number;
  maxPageSize?: number;
  defaultCompact?: boolean;
  defaultSort?: DataTableSortPreference | null;
};

export function useDataTablePreferences(opts: Options) {
  const minPageSize = Math.max(1, opts.minPageSize ?? 10);
  const maxPageSize = Math.max(minPageSize, opts.maxPageSize ?? 500);
  const fallbackPageSize = clampInt(opts.defaultPageSize, minPageSize, maxPageSize, 50);
  const fallbackCompact = Boolean(opts.defaultCompact);
  const fallbackSort = opts.defaultSort ?? null;

  const sanitize = useCallback(
    (raw: unknown): PersistedDataTableState =>
      sanitizeDataTableState(raw, {
        minPageSize,
        maxPageSize,
        fallbackPageSize,
        fallbackCompact,
        fallbackSort,
      }),
    [fallbackCompact, fallbackPageSize, fallbackSort, maxPageSize, minPageSize]
  );

  const [state, setState] = usePersistentState<PersistedDataTableState>(opts.storageKey, sanitize({}), sanitize);

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
      setState((prev) => ({ ...prev, sort: sanitizeDataTableSort(next) }));
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
