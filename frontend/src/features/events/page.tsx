import type { CSSProperties, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";

import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";

import { useAgentsCatalog } from "@/app/providers";

import { getRecentEvents } from "./api";
import EventsTable from "./components/EventsTable";
import EventsFilters, { type EventsViewConfig } from "./components/EventsFilters";

import EventDetailsPanel from "./components/EventDetailsPanel";
import EventExplorer from "./components/EventExplorer";

import { buildTopCounts } from "./lib/aggregates";
import { eventMatchesSearch } from "./lib/filter";

import DdosDeepDive from "./views/ddos/DdosDeepDive";

import type { NetEvent } from "./types";

// Panel sizing (Grafana-like fixed heights)
const H_FILTERS = 280; // Increased to avoid clipping
const H_EXPLORER = 340;
const H_TABLE = 560;
const H_DETAILS = 560;

const DEFAULT_CFG: EventsViewConfig = {
  agent_id: null,
  event_type: null,
  search: "",
  window_minutes: 60,
  limit: 500
};

function Panel({
  title,
  right,
  children,
  scrollY = false,
  className = "",
  style
}: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  scrollY?: boolean;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div className={cx("border border-border/60 bg-background/70 backdrop-blur-sm flex flex-col", className)} style={style}>
      <div className="flex items-center justify-between border-b border-border/60 bg-muted/10 px-3 py-2 shrink-0">
        <h3 className="text-xs font-bold uppercase tracking-widest font-mono text-primary/90">{title}</h3>
        {right && <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">{right}</div>}
      </div>

      {/* IMPORTANT: when scrollY=false we keep overflow hidden (Grafana-like).
          For Filters we enable scrollY and/or increase height to avoid clipping. */}
      <div className={cx("p-3 flex-1 min-h-0", scrollY ? "overflow-y-auto" : "overflow-hidden")}>{children}</div>
    </div>
  );
}

export default function EventsPage() {
  const { agents, selectedAgentId } = useAgentsCatalog();

  const [cfg, setCfg] = useState<EventsViewConfig>(() => ({ ...DEFAULT_CFG }));

  const [events, setEvents] = useState<NetEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedEvent, setSelectedEvent] = useState<NetEvent | null>(null);

  const inFlight = useRef(false);

  // Always follow the globally selected agent (sidebar rule)
  useEffect(() => {
    if (!selectedAgentId) {
      // If no agent is selected globally, we keep whatever user picked in filters.
      return;
    }
    setCfg((prev) => {
      if (prev.agent_id === selectedAgentId) return prev;
      return { ...prev, agent_id: selectedAgentId };
    });
  }, [selectedAgentId]);

  // Fetch events using current config
  useEffect(() => {
    let cancelled = false;

    async function run() {
      if (inFlight.current) return;
      inFlight.current = true;

      setLoading(true);
      try {
        const payload = await getRecentEvents({
          agent_id: cfg.agent_id || undefined,
          event_type: cfg.event_type || undefined,
          search: (cfg.search || "").trim() || undefined,
          window_minutes: cfg.window_minutes ?? undefined,
          limit: cfg.limit ?? undefined
        });

        if (cancelled) return;

        setEvents(payload);
        setError(null);

        // Keep selection stable if possible
        if (selectedEvent) {
          const stillThere = payload.find((e) => String(e.id) === String(selectedEvent.id));
          setSelectedEvent(stillThere || null);
        }
      } catch (e: any) {
        if (cancelled) return;
        setError(e?.message || "Failed to load events");
        setEvents([]);
        setSelectedEvent(null);
      } finally {
        if (!cancelled) setLoading(false);
        inFlight.current = false;
      }
    }

    run();
    return () => {
      cancelled = true;
    };
  }, [cfg.agent_id, cfg.event_type, cfg.search, cfg.window_minutes, cfg.limit]);

  // Client-side derived explorer (Top event types)
  const topTypes = useMemo(() => {
    const values = events.map((e) => (e.event_type ? String(e.event_type) : ""));
    return buildTopCounts(values, 12);
  }, [events]);

  // Client-side filtering (helps the explorer feel instant even when API is broad)
  const filteredEvents = useMemo(() => {
    const q = (cfg.search || "").trim();
    if (!q) return events;
    return events.filter((e) => eventMatchesSearch(e as any, q));
  }, [events, cfg.search]);

  const ddosMode = (cfg.event_type || "").toLowerCase() === "dos_attack";

  return (
    <div className="min-h-screen pb-20 font-sans text-sm text-foreground">
      <div className="flex items-center justify-between mb-4">
        <div className="text-xs font-mono uppercase tracking-[0.35em] text-muted-foreground">Events</div>
        <div className="text-[10px] font-mono text-muted-foreground">
          {loading ? "LOADING" : error ? "ERROR" : `${filteredEvents.length} events`}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        {/* LEFT COLUMN */}
        <div className="xl:col-span-4 space-y-4 min-h-0">
          {/* FIX: Increase height + enable internal scroll to avoid clipping */}
          <Panel title="Filters" scrollY style={{ height: H_FILTERS }}>
            <EventsFilters
              config={cfg}
              onChange={setCfg}
              agents={agents as any}
              lockAgentId={selectedAgentId || null}
              busy={loading}
            />
          </Panel>

          <Panel
            title="Event explorer"
            scrollY
            style={{ height: H_EXPLORER }}
            right={topTypes.length ? `${topTypes.length} types` : undefined}
          >
            <EventExplorer
              activeType={cfg.event_type || ""}
              types={topTypes.map((x) => ({ type: x.key, count: x.count }))}
              onSelectType={(t) => setCfg((prev) => ({ ...prev, event_type: t || null }))}
              onClearType={() => setCfg((prev) => ({ ...prev, event_type: null }))}
            />
          </Panel>

          <Panel title="Event details" scrollY style={{ height: H_DETAILS }}>
            <EventDetailsPanel event={selectedEvent as any} />
          </Panel>
        </div>

        {/* RIGHT COLUMN */}
        <div className="xl:col-span-8 space-y-4 min-h-0">
          {error ? (
            <Panel title="Stream" style={{ height: H_TABLE }}>
              <EmptyState title="Telemetry error" hint={error} />
            </Panel>
          ) : loading && filteredEvents.length === 0 ? (
            <Panel title="Stream" style={{ height: H_TABLE }}>
              <Loading label="Loading events..." />
            </Panel>
          ) : filteredEvents.length === 0 ? (
            <Panel title="Stream" style={{ height: H_TABLE }}>
              <EmptyState title="No events" hint="No events match the current filters." />
            </Panel>
          ) : (
            <>
              {/* DDoS Deep Dive appears when event_type = dos_attack */}
              {ddosMode && (
                <Panel title="DDoS deep dive" scrollY style={{ height: 420 }}>
                  <DdosDeepDive events={filteredEvents as any} />
                </Panel>
              )}

              <Panel
                title="Event stream"
                style={{ height: H_TABLE }}
                right={cfg.agent_id ? `agent: ${cfg.agent_id}` : "all agents"}
              >
                <div className="h-full">
                  <EventsTable
                    rows={filteredEvents as any}
                    selectedId={selectedEvent ? String(selectedEvent.id) : null}
                    compact
                    showExtra
                    // IMPORTANT: Selecting an event should not crash if event.id is missing
                    onSelect={(id: any) => {
                      const found = filteredEvents.find((e: any) => String(e.id) === String(id));
                      setSelectedEvent(found || null);
                    }}
                  />
                </div>
              </Panel>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
