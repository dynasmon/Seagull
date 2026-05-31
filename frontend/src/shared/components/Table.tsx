import { useMemo, type ReactNode } from "react";
import { EuiBasicTable, EuiCheckbox } from "@elastic/eui";
import type { Criteria, EuiBasicTableColumn, EuiTableSortingType } from "@elastic/eui";

import { cx } from "@/shared/lib/cx";

export type TableSortState = {
  key: string;
  direction: "asc" | "desc";
};

export type Column<T> = {
  key: string;
  title: string;
  render?: (row: T) => ReactNode;
  className?: string;
  width?: number;
  sortable?: boolean;
  sortKey?: string;
  align?: "left" | "center" | "right";
};

function toSelectedSet(input?: string[] | Set<string>): Set<string> {
  if (!input) return new Set();
  if (input instanceof Set) return input;
  return new Set(input);
}

export function Table<T extends object>({
  columns,
  rows,
  rowKey,
  className,
  scrollX = false,
  stickyHeader = true,
  compact = true,
  selectedRowKey,
  selectedRowKeys,
  selectableRows = false,
  onToggleRow,
  onToggleAllRows,
  onRowClick,
  sort,
  onSortChange,
  rowClassName,
  footer,
}: {
  columns: Array<Column<T>>;
  rows: T[];
  rowKey: (row: T, idx: number) => string;
  className?: string;
  scrollX?: boolean;
  stickyHeader?: boolean;
  compact?: boolean;
  selectedRowKey?: string | null;
  selectedRowKeys?: string[] | Set<string>;
  selectableRows?: boolean;
  onToggleRow?: (row: T, checked: boolean) => void;
  onToggleAllRows?: (checked: boolean) => void;
  onRowClick?: (row: T, idx: number) => void;
  sort?: TableSortState | null;
  onSortChange?: (next: TableSortState) => void;
  rowClassName?: (row: T, idx: number) => string | undefined;
  footer?: ReactNode;
}) {
  const selectedSet = toSelectedSet(selectedRowKeys);

  const indexByRow = useMemo(() => {
    const map = new Map<T, number>();
    rows.forEach((row, idx) => map.set(row, idx));
    return map;
  }, [rows]);

  const idxOf = (row: T) => indexByRow.get(row) ?? rows.indexOf(row);
  const keyForRow = (row: T) => String(rowKey(row, idxOf(row)));

  const dataColumns: Array<EuiBasicTableColumn<T>> = columns.map((c) => ({
    field: (c.sortKey || c.key) as keyof T,
    name: c.title,
    align: c.align ?? "left",
    width: c.width ? `${c.width}px` : undefined,
    className: c.className,
    sortable: Boolean(c.sortable && onSortChange),
    truncateText: false,
    render: (_value: unknown, row: T) =>
      c.render ? c.render(row) : ((row as Record<string, unknown>)[c.key] as ReactNode),
  }));

  const allRowsSelected = rows.length > 0 && rows.every((row) => selectedSet.has(keyForRow(row)));
  const anyRowSelected = rows.some((row) => selectedSet.has(keyForRow(row)));

  const euiColumns: Array<EuiBasicTableColumn<T>> = selectableRows
    ? [
        {
          name: (
            <EuiCheckbox
              id="seagull-table-select-all"
              checked={allRowsSelected}
              indeterminate={!allRowsSelected && anyRowSelected}
              onChange={(e) => onToggleAllRows?.(e.target.checked)}
              aria-label="Select all rows"
            />
          ),
          width: "40px",
          render: (row: T) => (
            <span onClick={(e) => e.stopPropagation()}>
              <EuiCheckbox
                id={`seagull-table-select-${keyForRow(row)}`}
                checked={selectedSet.has(keyForRow(row))}
                onChange={(e) => onToggleRow?.(row, e.target.checked)}
                aria-label="Select row"
              />
            </span>
          ),
        },
        ...dataColumns,
      ]
    : dataColumns;

  const sorting: EuiTableSortingType<T> | undefined = onSortChange
    ? { sort: sort ? { field: sort.key as keyof T, direction: sort.direction } : undefined }
    : undefined;

  const handleChange = (criteria: Criteria<T>) => {
    if (criteria.sort && onSortChange) {
      onSortChange({ key: String(criteria.sort.field), direction: criteria.sort.direction });
    }
  };

  const getRowProps = (row: T) => {
    const idx = idxOf(row);
    const key = keyForRow(row);
    const isSelected = (selectedRowKey != null && key === selectedRowKey) || selectedSet.has(key);
    return {
      className: cx("ui-row", isSelected && "ui-row-selected", rowClassName?.(row, idx)),
      onClick: onRowClick ? () => onRowClick(row, idx) : undefined,
    };
  };

  return (
    <div
      className={cx(
        "ui-card-shell min-w-0 overflow-hidden",
        stickyHeader && "seagullTable-stickyHeader",
        scrollX && "seagullTable-scrollX",
        className
      )}
    >
      <div className={cx("min-w-0", scrollX ? "overflow-x-auto" : "overflow-x-hidden")}>
        <EuiBasicTable
          tableCaption="Data table"
          items={rows}
          columns={euiColumns}
          rowProps={getRowProps}
          sorting={sorting}
          onChange={handleChange}
          compressed={compact}
          tableLayout="auto"
          responsiveBreakpoint={false}
          noItemsMessage=""
        />
      </div>
      {footer ? <div className="border-t border-border bg-surface-2/60 px-3 py-2">{footer}</div> : null}
    </div>
  );
}
