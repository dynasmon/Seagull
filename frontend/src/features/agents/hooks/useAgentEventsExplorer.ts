import { useMemo } from "react";

import type { NetEvent } from "@/features/events/types";
import { isDdosEvent, isDdosEventType } from "@/features/events/lib/ddos";

import {
  DEFAULT_WINDOW_MINUTES,
  type EventsCfg,
  safeNumber,
  buildTopCounts,
  eventMatchesSearch,
} from "../lib/agentUtils";

interface UseAgentEventsExplorerProps {
  events: NetEvent[];
  eventsCfg: EventsCfg;
}

export function useAgentEventsExplorer({ events, eventsCfg }: UseAgentEventsExplorerProps) {
  const windowedEvents = useMemo(() => {
    const mins = Math.max(1, safeNumber(eventsCfg.window_minutes, DEFAULT_WINDOW_MINUTES));
    const cutoff = Date.now() - mins * 60_000;

    return (events || []).filter((e) => {
      const t = new Date(e.timestamp).getTime();
      if (!Number.isFinite(t)) return true;
      return t >= cutoff;
    });
  }, [events, eventsCfg.window_minutes]);

  const availableTypes = useMemo(() => {
    const set = new Set<string>();
    for (const e of windowedEvents) set.add(e.event_type);
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [windowedEvents]);

  const explorerBase = useMemo(() => {
    const q = (eventsCfg.search || "").trim();
    if (!q) return windowedEvents;
    return windowedEvents.filter((e) => eventMatchesSearch(e, q));
  }, [windowedEvents, eventsCfg.search]);

  const topTypes = useMemo(() => {
    return buildTopCounts(explorerBase.map((e) => e.event_type), 12);
  }, [explorerBase]);

  const filteredEvents = useMemo(() => {
    const type = (eventsCfg.event_type || "").trim();
    const q = (eventsCfg.search || "").trim();
    return windowedEvents.filter((e) => {
      if (type && e.event_type !== type) return false;
      if (q && !eventMatchesSearch(e, q)) return false;
      return true;
    });
  }, [windowedEvents, eventsCfg.event_type, eventsCfg.search]);

  const ddosEvents = useMemo(() => filteredEvents.filter((e) => isDdosEvent(e)), [filteredEvents]);
  const ddosMode = ddosEvents.length > 0 || isDdosEventType((eventsCfg.event_type || "").trim());

  return { windowedEvents, availableTypes, explorerBase, topTypes, filteredEvents, ddosEvents, ddosMode };
}

export type AgentEventsExplorer = ReturnType<typeof useAgentEventsExplorer>;
