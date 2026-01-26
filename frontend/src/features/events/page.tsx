import type { CSSProperties, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";

import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";

import { useAgentsCatalog } from "@/app/providers";

import { getRecentEvents } from "./api";
import EventsTable from "./components/EventsTable";
import type { NetEvent } from "./types";

const H_TABLE = 720;
const DEFAULT_WINDOW_MINUTES = 60;
const DEFAULT_LIMIT = 1000;

function Panel(props: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  style?: CSSProperties;
  scrollY?: boolean;
}) {
  return (
    <div className="rounded-xl border border-border/60 bg-card/10 backdrop-blur-md">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border/60">
        <div className="text-sm font-semibold tracking-tight">{props.title}</div>
        {props.right ? <div className="text-xs text-muted-foreground">{props.right}</div> : null}
      </div>

      <div
        className={cx("p-4", props.scrollY && "overflow-y-auto")}
        style={props.style}
      >
        {props.children}
      </div>
    </div>
  );
}

export default function EventsPage() {
  const { agents } = useAgentsCatalog();

  const agentNameById = useMemo(() => {
    const map: Record<string, string> = {};
    for (const a of agents || []) {
      if (a?.agent_id) map[a.agent_id] = a.display_name || a.agent_id;
    }
    return map;
  }, [agents]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [selected, setSelected] = useState<NetEvent | null>(null);

  const inFlight = useRef(false);

  useEffect(() => {
    if (inFlight.current) return;
    inFlight.current = true;

    setLoading(true);
    setError(null);

    (async () => {
      try {
        const payload = await getRecentEvents({
          limit: DEFAULT_LIMIT,
          window_minutes: DEFAULT_WINDOW_MINUTES
        });

        setEvents(payload);
        setSelected(payload[0] || null);
      } catch (e: any) {
        setError(e?.message || "Failed to load events");
        setEvents([]);
        setSelected(null);
      } finally {
        setLoading(false);
        inFlight.current = false;
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Events</h1>
          <div className="text-xs text-muted-foreground">
            Global event stream (all agents)
          </div>
        </div>
      </div>

      <Panel
        title="Event stream"
        right={loading ? "Loading..." : `${events.length} events`}
        scrollY
        style={{ height: H_TABLE }}
      >
        {loading ? (
          <Loading label="Loading events..." />
        ) : error ? (
          <EmptyState title="Events error" hint={error} />
        ) : events.length === 0 ? (
          <EmptyState title="No events" hint="No telemetry events were returned by the backend." />
        ) : (
          <div className="h-full">
            <EventsTable
              rows={events}
              selectedId={selected?.id ?? null}
              compact={false}
              showExtra
              agentNameById={agentNameById}
              onSelect={(e) => setSelected(e)}
            />
          </div>
        )}
      </Panel>
    </div>
  );
}
