import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { cx } from "@/shared/lib/cx";

import type { Density } from "../constants";
import { fmtTs } from "../lib/alertFormatters";
import { alertIpContext } from "../lib/alertPresenters";
import { sevVariant } from "../lib/alertSeverity";
import type { Alert } from "../types";

interface AlertsTableProps {
  rows: Alert[];
  selectedId: number | null;
  onEdit: (a: Alert) => void;
  selectedRowIds: Set<number>;
  onToggleRow: (alertId: number, nextChecked: boolean) => void;
  onToggleAllRows: (nextChecked: boolean) => void;
  density?: Density;
}

export function AlertsTable({
  rows,
  selectedId,
  onEdit,
  selectedRowIds,
  onToggleRow,
  onToggleAllRows,
  density,
}: AlertsTableProps) {
  const dense = density === "compact";
  const allVisibleSelected = rows.length > 0 && rows.every((row) => selectedRowIds.has(row.id));

  return (
    <div className="w-full">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-background/60 backdrop-blur z-10">
          <tr className="border-b border-border/60 text-muted-foreground">
            <th className="px-3 py-2 w-10">
              <input
                type="checkbox"
                checked={allVisibleSelected}
                onChange={(e) => onToggleAllRows(e.target.checked)}
                aria-label="Select visible alerts"
                className="h-4 w-4"
              />
            </th>
            <th className="text-left font-medium px-3 py-2">Alert</th>
            <th className="text-left font-medium px-3 py-2">Network</th>
            <th className="text-left font-medium px-3 py-2">Description</th>
            <th className="text-right font-medium px-3 py-2">Actions</th>
          </tr>
        </thead>

        <tbody>
          {rows.map((a) => {
            const selected = selectedId !== null && a.id === selectedId;
            return (
              <tr
                key={a.id}
                className={cx("border-b border-border/40 hover:bg-muted/30", selected && "bg-muted/40")}
                role="button"
                tabIndex={0}
                onClick={() => onEdit(a)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onEdit(a);
                  }
                }}
              >
                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <input
                    type="checkbox"
                    checked={selectedRowIds.has(a.id)}
                    onClick={(e) => e.stopPropagation()}
                    onChange={(e) => onToggleRow(a.id, e.target.checked)}
                    aria-label={`Select alert ${a.id}`}
                    className="h-4 w-4"
                  />
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge variant={sevVariant(String(a.severity || "unknown"))}>{String(a.severity || "unknown")}</Badge>
                    <span className="font-mono text-[12px] break-all">{a.rule_id}</span>
                  </div>
                  <div className="font-mono text-[11px] text-muted-foreground">{fmtTs(a.created_at)}</div>
                </td>

                <td className={cx("px-3 text-[12px]", dense ? "py-1.5" : "py-2")}>
                  <div>
                    <IpAddressPill ip={a.src_ip} ipContext={alertIpContext(a, "src")} compact />
                  </div>
                  <div className="mt-1 text-muted-foreground">
                    <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
                      <IpAddressPill ip={a.dst_ip} ipContext={alertIpContext(a, "dst")} compact />
                      {typeof a.dst_port === "number" ? <span>:{a.dst_port}</span> : null}
                    </span>
                  </div>
                </td>

                <td className={cx("px-3", dense ? "py-1.5" : "py-2")}>
                  <div className="text-[12px] text-muted-foreground line-clamp-2">{a.description || ""}</div>
                </td>

                <td className={cx("px-3 text-right", dense ? "py-1.5" : "py-2")}>
                  <Button
                    variant="subtle"
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      onEdit(a);
                    }}
                    title="Open drawer"
                  >
                    View
                  </Button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
