import type { Dispatch, SetStateAction } from "react";
import type { NetEvent } from "@/features/events/types";
import DdosDeepDive from "@/features/events/views/ddos/DdosDeepDive";
import EventDetailsPanel from "@/features/events/components/EventDetailsPanel";
import EventsTable from "@/features/events/components/EventsTable";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";

import { FieldLabel, Panel } from "./AgentsPageShared";
import { inputClassName } from "./AgentFormClassNames";

type EventsCfg = {
  event_type: string;
  search: string;
  window_minutes: number;
  limit: number;
};

export default function AgentEventsWorkbench({
  selectedAgentId,
  eventsCfg,
  setEventsCfg,
  availableTypes,
  topTypes,
  explorerBaseCount,
  filteredEvents,
  selectedEvent,
  onSelectEvent,
  eventsLoading,
  eventsError,
  onReload,
  defaultWindowMinutes,
  defaultEventsLimit,
  ddosMode,
  ddosEvents,
  panelHeight,
  streamHeight,
  compact,
}: {
  selectedAgentId: string;
  eventsCfg: EventsCfg;
  setEventsCfg: Dispatch<SetStateAction<EventsCfg>>;
  availableTypes: string[];
  topTypes: Array<{ key: string; count: number }>;
  explorerBaseCount: number;
  filteredEvents: NetEvent[];
  selectedEvent: NetEvent | null;
  onSelectEvent: (event: NetEvent) => void;
  eventsLoading: boolean;
  eventsError: string | null;
  onReload: () => void;
  defaultWindowMinutes: number;
  defaultEventsLimit: number;
  ddosMode: boolean;
  ddosEvents: NetEvent[];
  panelHeight: number;
  streamHeight: number;
  compact: boolean;
}) {
  return (
    <div className="grid gap-6 xl:grid-cols-12 min-w-0">
      <div className="xl:col-span-4 space-y-6 min-h-0 min-w-0">
        <Panel title="Recent alerts/events filters" scrollY style={{ height: 420 }}>
          <div className="space-y-3">
            <div>
              <FieldLabel>Event type</FieldLabel>
              <select
                className={cx(
                  "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
                  "focus:ring-2 focus:ring-primary/30"
                )}
                value={eventsCfg.event_type}
                onChange={(e) => setEventsCfg((p) => ({ ...p, event_type: e.target.value }))}
              >
                <option value="">All types</option>
                {availableTypes.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <FieldLabel>Search</FieldLabel>
              <input
                className={inputClassName(false)}
                value={eventsCfg.search}
                onChange={(e) => setEventsCfg((p) => ({ ...p, search: e.target.value }))}
                placeholder="ip, user, rule, port, vector..."
              />
              <div className="mt-1 text-[11px] text-muted-foreground">Client-side search over event fields + extra JSON.</div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <FieldLabel>Window (min)</FieldLabel>
                <DraftNumberInput
                  value={eventsCfg.window_minutes}
                  min={1}
                  max={10080}
                  fallback={defaultWindowMinutes}
                  onCommit={(v) => setEventsCfg((p) => ({ ...p, window_minutes: v }))}
                  className={inputClassName(false)}
                  title="Lookback window (minutes)"
                />
              </div>

              <div>
                <FieldLabel>Limit</FieldLabel>
                <DraftNumberInput
                  value={eventsCfg.limit}
                  min={50}
                  max={5000}
                  fallback={defaultEventsLimit}
                  onCommit={(v) => setEventsCfg((p) => ({ ...p, limit: v }))}
                  className={inputClassName(false)}
                  title="Max events to fetch"
                />
              </div>
            </div>

            <div className="flex items-center justify-between gap-3 pt-2">
              <button
                type="button"
                onClick={() => setEventsCfg((p) => ({ ...p, event_type: "", search: "" }))}
                className={cx(
                  "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                  "hover:bg-primary/5"
                )}
              >
                Clear filters
              </button>

              <button
                type="button"
                onClick={onReload}
                className={cx(
                  "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                  "hover:bg-primary/5",
                  eventsLoading && "opacity-60 cursor-not-allowed"
                )}
                disabled={eventsLoading || !selectedAgentId}
              >
                {eventsLoading ? "Loading..." : "Reload events"}
              </button>
            </div>
          </div>
        </Panel>

        <Panel title="Event pivots" scrollY style={{ height: 360 }}>
          <div className="space-y-1">
            <button
              type="button"
              className={cx(
                "w-full text-left px-3 py-2 rounded-md border border-border/60 bg-background/30",
                "hover:bg-muted/10",
                !eventsCfg.event_type && "bg-primary/10"
              )}
              onClick={() => setEventsCfg((p) => ({ ...p, event_type: "" }))}
            >
              <div className="flex items-center justify-between">
                <div className="text-sm font-mono">All types</div>
                <div className="text-[10px] font-mono text-muted-foreground">{explorerBaseCount}</div>
              </div>
            </button>

            {topTypes.map((x) => {
              const active = eventsCfg.event_type === x.key;
              return (
                <button
                  key={x.key}
                  type="button"
                  className={cx(
                    "w-full text-left px-3 py-2 rounded-md border border-border/60 bg-background/20",
                    "hover:bg-muted/10",
                    active && "bg-primary/10"
                  )}
                  onClick={() => setEventsCfg((p) => ({ ...p, event_type: x.key }))}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-sm font-mono truncate">{x.key}</div>
                    <div className="text-[10px] font-mono text-muted-foreground">{x.count}</div>
                  </div>
                </button>
              );
            })}
          </div>
        </Panel>

        <Panel title="Selected event detail" scrollY style={{ height: panelHeight }}>
          <EventDetailsPanel event={selectedEvent} />
        </Panel>
      </div>

      <div className="xl:col-span-8 space-y-6 min-h-0 min-w-0">
        {ddosMode && (
          <Panel title="DDoS deep dive" right={ddosEvents.length ? `${ddosEvents.length} events` : ""} scrollY style={{ height: streamHeight }}>
            {ddosEvents.length === 0 ? (
              <EmptyState title="No DDoS events" hint="No DDoS-classified telemetry matches the current filters/window." />
            ) : (
              <DdosDeepDive events={ddosEvents} selectedId={selectedEvent?.id ?? null} onSelect={(e) => onSelectEvent(e)} />
            )}
          </Panel>
        )}

        <Panel title="Recent alerts/events" right={eventsError ? "Error" : `${filteredEvents.length} events`} scrollY style={{ height: streamHeight }}>
          {eventsError ? (
            <EmptyState title="Events error" hint={eventsError} />
          ) : eventsLoading && filteredEvents.length === 0 ? (
            <Loading label="Loading events..." />
          ) : filteredEvents.length === 0 ? (
            <EmptyState title="No events" hint="No events match the current filters/window." />
          ) : (
            <div className="h-full min-w-0">
              <EventsTable
                rows={filteredEvents}
                selectedId={selectedEvent?.id ?? null}
                compact={compact}
                showExtra
                onSelect={(e) => onSelectEvent(e)}
              />
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
