import { memo, useEffect, useMemo, useState, type Dispatch, type SetStateAction } from "react";
import { EuiFacetButton, EuiFacetGroup } from "@elastic/eui";

import type { NetEvent } from "@/features/events/types";
import DdosDeepDive from "@/features/events/views/ddos/DdosDeepDive";
import EventDetailsPanel from "@/features/events/components/EventDetailsPanel";
import EventsTable from "@/features/events/components/EventsTable";
import { Button } from "@/shared/components/Button";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextInput } from "@/shared/components/TextInput";

import { FieldLabel } from "./AgentsPageShared";

type EventsCfg = {
  event_type: string;
  search: string;
  window_minutes: number;
  limit: number;
};

const EVENT_ROWS_PAGE = 100;

export default memo(function AgentEventsWorkbench({
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
  const [visibleRows, setVisibleRows] = useState(EVENT_ROWS_PAGE);

  useEffect(() => {
    setVisibleRows(EVENT_ROWS_PAGE);
  }, [selectedAgentId, eventsCfg.event_type, eventsCfg.search, eventsCfg.window_minutes]);

  const visibleEvents = useMemo(
    () => (filteredEvents.length <= visibleRows ? filteredEvents : filteredEvents.slice(0, visibleRows)),
    [filteredEvents, visibleRows]
  );

  const hiddenCount = filteredEvents.length - visibleEvents.length;

  return (
    <div className="grid gap-6 xl:grid-cols-12 min-w-0">
      <div className="xl:col-span-4 space-y-6 min-h-0 min-w-0">
        <Panel title="Recent alerts/events filters" scrollY style={{ height: 420 }}>
          <div className="space-y-3">
            <div>
              <FieldLabel>Event type</FieldLabel>
              <SelectInput
                className="mt-1 font-mono text-[11px]"
                value={eventsCfg.event_type}
                onChange={(e) => setEventsCfg((p) => ({ ...p, event_type: e.target.value }))}
              >
                <option value="">All types</option>
                {availableTypes.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </SelectInput>
            </div>

            <div>
              <FieldLabel>Search</FieldLabel>
              <TextInput
                className="mt-1 font-mono text-[11px]"
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
                  className="mt-1 w-full font-mono text-[11px]"
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
                  className="mt-1 w-full font-mono text-[11px]"
                  title="Max events to fetch"
                />
              </div>
            </div>

            <div className="flex items-center justify-between gap-3 pt-2">
              <Button
                variant="subtle"
                size="sm"
                onClick={() => setEventsCfg((p) => ({ ...p, event_type: "", search: "" }))}
                className="font-mono uppercase tracking-widest"
              >
                Clear filters
              </Button>

              <Button
                variant="subtle"
                size="sm"
                onClick={onReload}
                disabled={eventsLoading || !selectedAgentId}
                className="font-mono uppercase tracking-widest"
              >
                {eventsLoading ? "Loading..." : "Reload events"}
              </Button>
            </div>
          </div>
        </Panel>

        <Panel title="Event pivots" scrollY style={{ height: 360 }}>
          <EuiFacetGroup layout="vertical" gutterSize="none">
            <EuiFacetButton
              quantity={explorerBaseCount}
              isSelected={!eventsCfg.event_type}
              onClick={() => setEventsCfg((p) => ({ ...p, event_type: "" }))}
            >
              <span className="font-mono text-[12.5px]">All types</span>
            </EuiFacetButton>

            {topTypes.map((x) => (
              <EuiFacetButton
                key={x.key}
                quantity={x.count}
                isSelected={eventsCfg.event_type === x.key}
                onClick={() => setEventsCfg((p) => ({ ...p, event_type: x.key }))}
              >
                <span className="truncate font-mono text-[12.5px]">{x.key}</span>
              </EuiFacetButton>
            ))}
          </EuiFacetGroup>
        </Panel>

        <Panel title="Selected event detail" scrollY style={{ height: panelHeight }}>
          <EventDetailsPanel event={selectedEvent} />
        </Panel>
      </div>

      <div className="xl:col-span-8 space-y-6 min-h-0 min-w-0">
        {ddosMode && (
          <Panel
            title="DDoS deep dive"
            actions={ddosEvents.length ? <span className="text-[10px] font-mono text-muted-foreground">{ddosEvents.length} events</span> : undefined}
            scrollY
            style={{ height: streamHeight }}
          >
            {ddosEvents.length === 0 ? (
              <EmptyState title="No DDoS events" hint="No DDoS-classified telemetry matches the current filters/window." />
            ) : (
              <DdosDeepDive events={ddosEvents} selectedId={selectedEvent?.id ?? null} onSelect={onSelectEvent} />
            )}
          </Panel>
        )}

        <Panel
          title="Recent alerts/events"
          actions={
            <span className="text-[10px] font-mono text-muted-foreground">
              {eventsError ? "Error" : `${visibleEvents.length}/${filteredEvents.length} events`}
            </span>
          }
          scrollY
          style={{ height: streamHeight }}
        >
          {eventsError ? (
            <EmptyState title="Events error" hint={eventsError} />
          ) : eventsLoading && filteredEvents.length === 0 ? (
            <Loading label="Loading events..." />
          ) : filteredEvents.length === 0 ? (
            <EmptyState title="No events" hint="No events match the current filters/window." />
          ) : (
            <div className="h-full min-w-0 space-y-3">
              <EventsTable
                rows={visibleEvents}
                selectedId={selectedEvent?.id ?? null}
                compact={compact}
                showExtra
                onSelect={onSelectEvent}
              />
              {hiddenCount > 0 ? (
                <div className="flex items-center justify-between gap-3 px-1 pb-1">
                  <span className="text-[11px] text-muted-foreground">
                    {hiddenCount} more in the current window
                  </span>
                  <Button
                    variant="subtle"
                    size="sm"
                    onClick={() => setVisibleRows((prev) => prev + EVENT_ROWS_PAGE)}
                    className="font-mono uppercase tracking-widest"
                  >
                    Show more
                  </Button>
                </div>
              ) : null}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
});
