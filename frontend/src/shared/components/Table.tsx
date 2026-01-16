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
  className
}: {
  columns: Array<Column<T>>;
  rows: T[];
  rowKey: (row: T, idx: number) => string;
  className?: string;
}) {
  return (
    <div className="overflow-auto border border-border/60 bg-background/30">
      <table className={`w-full ${className || "text-sm"}`}>
        <thead className="bg-muted/10 text-left text-[10px] text-muted-foreground font-mono uppercase tracking-widest">
          <tr>
            {columns.map((c) => (
              <th
                key={c.key}
                style={c.width ? { width: c.width } : undefined}
                className={`px-3 py-2 font-bold ${c.className || ""}`}
              >
                {c.title}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={rowKey(r, i)} className="border-t border-border/40 hover:bg-primary/5">
              {columns.map((c) => (
                <td key={c.key} className={`px-3 py-2 ${c.className || ""}`}>
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
