import { useMemo, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";

import AuditEventDrawer from "../components/AuditEventDrawer";
import AuditFiltersBar from "../components/AuditFiltersBar";
import { eventSeverity, fmtDateTime, summarizeEvent } from "../lib";
import { useAuditQuery } from "../useAuditQuery";
import type { AuditEvent } from "../types";

function groupByDay(rows: AuditEvent[]): Array<{ day: string; items: AuditEvent[] }> {
  const buckets = new Map<string, AuditEvent[]>();
  for (const r of rows) {
    const d = new Date(r.created_at);
    const key = Number.isNaN(d.getTime())
      ? "Unknown date"
      : `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
    const arr = buckets.get(key) || [];
    arr.push(r);
    buckets.set(key, arr);
  }

  return Array.from(buckets.entries())
    .map(([day, items]) => ({ day, items }))
    .sort((a, b) => (a.day < b.day ? 1 : -1));
}

export default function AuditTimelineView() {
  const q = useAuditQuery({ defaultLimit: 140 });
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const groups = useMemo(() => groupByDay(q.visibleRows), [q.visibleRows]);

  return (
    <div className="space-y-4">
      <AuditFiltersBar
        filters={q.filters}
        setFilter={q.setFilter}
        onApply={q.reload}
        onClear={q.resetFilters}
        loading={q.loading}
      />

      <div className="flex items-center justify-between rounded-xl border border-border/60 bg-background/60 px-4 py-3">
        <div className="text-xs text-muted-foreground">Timeline grouped by day · Page {q.page}</div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={q.prevPage}
            disabled={!q.hasPrev || q.loading}
            className="h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs disabled:opacity-50"
          >
            Previous
          </button>
          <button
            type="button"
            onClick={q.nextPage}
            disabled={!q.hasMore || q.loading}
            className="h-8 rounded-md border border-border/60 bg-background/40 px-3 text-xs disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>

      {q.error ? <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">{q.error}</div> : null}

      {q.loading ? (
        <div className="py-8 text-sm text-muted-foreground">Loading timeline...</div>
      ) : groups.length === 0 ? (
        <div className="py-8 text-sm text-muted-foreground rounded-xl border border-border/60 bg-background/60 px-4">
          No timeline events in current query.
        </div>
      ) : (
        <div className="space-y-4">
          {groups.map((g) => (
            <Card key={g.day} title={g.day} right={`${g.items.length} events`}>
              <div className="space-y-3">
                {g.items.map((ev) => {
                  const sev = eventSeverity(ev);
                  return (
                    <button
                      key={ev.id}
                      type="button"
                      onClick={() => setSelected(ev)}
                      className="w-full rounded-lg border border-border/60 bg-background/30 px-3 py-2 text-left hover:bg-muted/20"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-mono text-muted-foreground">{fmtDateTime(ev.created_at)}</span>
                        <Badge variant="neutral">{ev.event_type}</Badge>
                        <Badge variant={sev}>sev:{sev}</Badge>
                        <Badge variant={ev.outcome === "success" ? "low" : "critical"}>{ev.outcome || "unknown"}</Badge>
                        <span className="text-xs text-muted-foreground">{ev.actor_username || "unknown"}</span>
                      </div>
                      <div className="mt-1 text-sm font-mono">{ev.action}</div>
                      <div className="mt-1 text-xs text-muted-foreground truncate">{summarizeEvent(ev)}</div>
                    </button>
                  );
                })}
              </div>
            </Card>
          ))}
        </div>
      )}

      <AuditEventDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
