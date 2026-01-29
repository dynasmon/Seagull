import type { CSSProperties, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

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

      <div className={cx("p-4", props.scrollY && "overflow-y-auto")} style={props.style}>
        {props.children}
      </div>
    </div>
  );
}

export default function EventsPage() {
  const { agents } = useAgentsCatalog();
  const [searchParams, setSearchParams] = useSearchParams();

  // IMPORTANT UX: Events must be independent.
  // - Default scope is ALWAYS "All agents" when you open /events.
  // - If the URL includes ?agent_id=..., we honor it.
  // - No fallback to sidebar selection.
  const effectiveAgentId = (searchParams.get("agent_id") ?? "").trim();
  const agentIdForApi = effectiveAgentId ? effectiveAgentId : undefined;

  const agentNameById = useMemo(() => {
    const map: Record<string, string> = {};
    for (const a of agents || []) {
      if (a?.agent_id) map[a.agent_id] = a.display_name || a.agent_id;
    }
    return map;
  }, [agents]);

  const selectedAgentLabel = useMemo(() => {
    if (!effectiveAgentId) return null;
    return agentNameById[effectiveAgentId] || effectiveAgentId;
  }, [agentNameById, effectiveAgentId]);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [selected, setSelected] = useState<NetEvent | null>(null);

  const reqSeq = useRef(0);

  function setAgentScope(nextAgentId: string) {
    const next = (nextAgentId ?? "").trim();
    const sp = new URLSearchParams(searchParams);

    // Keep the URL clean: "All agents" == no agent_id param.
    if (!next) sp.delete("agent_id");
    else sp.set("agent_id", next);
    setSearchParams(sp, { replace: true });
  }

  useEffect(() => {
    const agentId = agentIdForApi;

    const mySeq = ++reqSeq.current;

    setLoading(true);
    setError(null);

    (async () => {
      try {
        const payload = await getRecentEvents({
          limit: DEFAULT_LIMIT,
          window_minutes: DEFAULT_WINDOW_MINUTES,
          agent_id: agentId
        });

        if (reqSeq.current !== mySeq) return;

        setEvents(payload);
        setSelected((prev) => {
          if (!prev) return payload[0] || null;
          const still = payload.find((x) => x.id === prev.id);
          return still || payload[0] || null;
        });
      } catch (e: any) {
        if (reqSeq.current !== mySeq) return;

        setError(e?.message || "Failed to load events");
        setEvents([]);
        setSelected(null);
      } finally {
        if (reqSeq.current !== mySeq) return;
        setLoading(false);
      }
    })();
  }, [agentIdForApi]);

  const headerRight = useMemo(() => {
    if (loading) return "Loading...";
    return `${events.length} events`;
  }, [loading, events.length]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Events</h1>
          <div className="text-xs text-muted-foreground">
            {selectedAgentLabel ? (
              <>
                Scope: <span className="text-foreground">{selectedAgentLabel}</span>
              </>
            ) : (
              "Scope: All agents"
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={effectiveAgentId}
            onChange={(e) => setAgentScope(e.target.value)}
            className={cx(
              "border border-border/60 bg-background/40 px-3 py-2",
              "text-[11px] font-mono text-foreground outline-none",
              "focus:ring-2 focus:ring-primary/30"
            )}
            title="Agent scope"
          >
            <option value="">All agents</option>
            {agents.map((a) => (
              <option key={a.agent_id} value={a.agent_id}>
                {a.display_name?.trim() ? a.display_name : a.agent_id}
              </option>
            ))}
          </select>
        </div>
      </div>

      <Panel title="Event stream" right={headerRight} scrollY style={{ height: H_TABLE }}>
        {loading ? (
          <Loading label="Loading events..." />
        ) : error ? (
          <EmptyState title="Events error" hint={error} />
        ) : events.length === 0 ? (
          <EmptyState
            title="No events"
            hint={
              selectedAgentLabel
                ? "No telemetry events were returned for this agent in the current window."
                : "No telemetry events were returned for any agent in the current window."
            }
          />
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
