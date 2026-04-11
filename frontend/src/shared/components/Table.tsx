import type { ReactNode } from "react";

export type Column<T> = {
  key: string;
  title: string;
  render?: (row: T) => ReactNode;
  className?: string;
  width?: number;
};

export function Table<T>({
  columns,
  rows,
  rowKey,
  className,
  scrollX = true
}: {
  columns: Array<Column<T>>;
  rows: T[];
  rowKey: (row: T, idx: number) => string;
  className?: string;
  /** Enable horizontal scrolling when the table content is wider than its container. */
  scrollX?: boolean;
}) {
  return (
    <div
      className={`ui-card-shell overflow-y-auto ${scrollX ? "overflow-x-auto" : "overflow-x-hidden"}`}
      role="region"
      aria-label="Data table"
    >
      <table className={`w-full ${className || "text-sm"}`}>
        <thead className="sticky top-0 z-[1] bg-muted/60 text-left text-[11px] text-muted-foreground uppercase tracking-[0.08em]">
          <tr>
            {columns.map((c) => (
              <th
                key={c.key}
                style={c.width ? { width: c.width } : undefined}
                className={`px-3 py-2.5 font-semibold ${c.className || ""}`}
              >
                {c.title}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={rowKey(r, i)} className="border-t border-border/50 hover:bg-muted/45">
              {columns.map((c) => (
                <td key={c.key} className={`px-3 py-2.5 ${c.className || ""}`}>
                  {c.render ? c.render(r) : (r as any)[c.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
