import EmptyState from "@/shared/components/EmptyState";
import { Panel } from "@/shared/components/Panel";
import { useSeverityChartColors } from "@/shared/components/charts/chartTheme";
import type { SeverityLevel } from "@/shared/lib/severity";

import type { ThreatGeoRecentEvent } from "../types";

function severityLevel(severity: string | null | undefined): SeverityLevel {
  const value = (severity || "").toLowerCase();
  if (value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info") {
    return value;
  }
  return "neutral";
}

function fmtTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function locationLabel(event: ThreatGeoRecentEvent): string {
  if (!event.country) return "—";
  return event.city ? `${event.city} · ${event.country}` : event.country;
}

export function RecentEventsPanel({ events }: { events: ThreatGeoRecentEvent[] }) {
  const severityColors = useSeverityChartColors();

  return (
    <Panel
      title="Latest events"
      subtitle="Most recent raw activity involving a public endpoint, served from the shared snapshot"
    >
      {events.length === 0 ? (
        <EmptyState
          title="No recent events"
          hint="No raw events with a public endpoint were captured in this window."
        />
      ) : (
        <div className="max-h-72 space-y-1 overflow-y-auto pr-1">
          {events.map((event, index) => (
            <div
              key={`${event.timestamp}-${event.src_ip ?? ""}-${event.dst_ip ?? ""}-${index}`}
              className="flex items-center gap-2 rounded px-1.5 py-1 text-xs hover:bg-muted/30"
            >
              <span
                className="inline-block h-2 w-2 shrink-0 rounded-full"
                style={{ backgroundColor: severityColors[severityLevel(event.severity)] }}
              />
              <span className="w-16 shrink-0 font-mono text-muted-foreground">{fmtTime(event.timestamp)}</span>
              <span className="w-32 shrink-0 truncate font-medium text-foreground">{event.event_type}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-muted-foreground">
                {event.src_ip ?? "—"}
                <span className="px-1 text-muted-foreground/60">→</span>
                {event.dst_ip ?? "—"}
                {event.dst_port != null ? `:${event.dst_port}` : ""}
              </span>
              <span className="hidden w-36 shrink-0 truncate text-muted-foreground md:inline">
                {locationLabel(event)}
              </span>
              <span className="w-16 shrink-0 text-right text-[10px] uppercase tracking-wide text-muted-foreground/80">
                {event.direction}
              </span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
