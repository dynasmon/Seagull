import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { useAgentsCatalog } from "@/app/providers";
import { isAbortError } from "@/shared/lib/http";
import { getErrorMessage } from "@/shared/lib/errors";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";

import { getOverview } from "@/features/overview/api";
import type { OverviewSnapshot } from "@/features/overview/types";
import { getRecentEvents } from "@/features/events/api";
import type { NetEvent } from "@/features/events/types";

import { getAgent } from "../api";
import type { AgentDetail, AgentPublic } from "../types";
import {
  DEFAULT_WINDOW_MINUTES,
  DEFAULT_EVENTS_LIMIT,
  type EventsCfg,
  safeNumber,
  parsePositiveInt,
} from "../lib/agentUtils";

export type UrlResponseActionTrigger = {
  agentId: string;
  actionId: number | null;
  tab: "create" | "execution" | "result";
  shouldOpen: boolean;
} | null;

export function useAgents() {
  const { agents, selectedAgentId, setSelectedAgentId, refresh } = useAgentsCatalog();
  const [searchParams, setSearchParams] = useSearchParams();

  const [agentQuery, setAgentQuery] = useState("");

  const agentsSorted = useMemo(() => {
    return [...(agents || [])].sort((a, b) => {
      const ad = a.display_name || a.agent_id;
      const bd = b.display_name || b.agent_id;
      return ad.localeCompare(bd);
    });
  }, [agents]);

  const agentsFiltered = useMemo(() => {
    const q = agentQuery.trim().toLowerCase();
    if (!q) return agentsSorted;
    return agentsSorted.filter((a) => {
      const parts = [a.display_name, a.agent_id, ...(a.tags || [])].filter(Boolean).join(" ").toLowerCase();
      return parts.includes(q);
    });
  }, [agentsSorted, agentQuery]);

  const selectAgent = (agentId: string) => {
    const next = new URLSearchParams(searchParams);
    if (agentId) next.set("agent_id", agentId);
    else next.delete("agent_id");
    setSearchParams(next, { replace: true });
    setSelectedAgentId(agentId);
  };

  const [agent, setAgent] = useState<AgentDetail | null>(null);
  const [agentError, setAgentError] = useState<string | null>(null);

  const [snapshot, setSnapshot] = useState<OverviewSnapshot | null>(null);
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<NetEvent | null>(null);

  const [snapshotError, setSnapshotError] = useState<string | null>(null);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [eventsLoading, setEventsLoading] = useState(false);

  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null);

  const [eventsCfg, setEventsCfg] = useState<EventsCfg>(() => ({
    event_type: "",
    search: "",
    window_minutes: DEFAULT_WINDOW_MINUTES,
    limit: DEFAULT_EVENTS_LIMIT,
  }));

  const eventsCfgRef = useRef<EventsCfg>(eventsCfg);
  useEffect(() => {
    eventsCfgRef.current = eventsCfg;
  }, [eventsCfg]);

  const snapshotSeqRef = useRef(0);
  const eventsSeqRef = useRef(0);
  const snapshotAbortRef = useRef<AbortController | null>(null);
  const eventsAbortRef = useRef<AbortController | null>(null);
  const detailLiveDidBootRef = useRef(false);

  const lastUrlId = useRef<string | null>(null);
  const responseUrlHandledRef = useRef<string | null>(null);

  const [urlResponseActionTrigger, setUrlResponseActionTrigger] = useState<UrlResponseActionTrigger>(null);

  useEffect(() => {
    const q = (searchParams.get("agent_id") || "").trim();

    // Apply only when the URL actually changes.
    if (lastUrlId.current !== q) {
      lastUrlId.current = q;
      setSelectedAgentId(q);
    }

    const responseActionId = parsePositiveInt(searchParams.get("response_action_id"));
    const responseTab = (searchParams.get("response_tab") || "").trim().toLowerCase();
    const shouldOpenResponse = String(searchParams.get("open_response_action") || "").trim() === "1" || !!responseActionId;
    const responseKey = `${q}:${responseActionId || ""}:${responseTab}:${shouldOpenResponse ? "1" : "0"}`;
    if (!shouldOpenResponse) return;
    if (responseUrlHandledRef.current === responseKey) return;
    responseUrlHandledRef.current = responseKey;

    let tab: "create" | "execution" | "result" = "execution";
    if (responseTab === "result" || responseTab === "execution" || responseTab === "create") {
      tab = responseTab as "create" | "execution" | "result";
    } else if (responseActionId) {
      tab = "result";
    }

    setUrlResponseActionTrigger({
      agentId: q || "",
      actionId: responseActionId,
      tab,
      shouldOpen: true,
    });
  }, [searchParams, setSelectedAgentId]);

  const selectedAgentRow = useMemo<AgentPublic | null>(() => {
    if (!selectedAgentId) return null;
    return agents.find((a) => a.agent_id === selectedAgentId) || null;
  }, [agents, selectedAgentId]);

  const loadAgent = useCallback(async (agentId: string) => {
    try {
      const a = await getAgent(agentId);
      setAgent(a);
      setAgentError(null);
      return a;
    } catch (e: any) {
      setAgentError(getErrorMessage(e, "Failed to load agent details"));
      setAgent(null);
      return null;
    }
  }, []);

  const loadSnapshot = useCallback(async (agentId: string, cfg: EventsCfg) => {
    const mySeq = ++snapshotSeqRef.current;
    snapshotAbortRef.current?.abort();
    const controller = new AbortController();
    snapshotAbortRef.current = controller;

    try {
      const win = Math.max(1, safeNumber(cfg.window_minutes, DEFAULT_WINDOW_MINUTES));
      const snap = await getOverview(
        { window_minutes: win, agent_id: agentId },
        { signal: controller.signal, timeoutMs: 12000 }
      );
      if (snapshotSeqRef.current !== mySeq) return;
      setSnapshot(snap);
      setSnapshotError(null);
      setLastUpdatedAt(new Date());
    } catch (e: any) {
      if (isAbortError(e)) return;
      if (snapshotSeqRef.current !== mySeq) return;
      setSnapshotError(getErrorMessage(e, "Failed to load overview"));
    } finally {
      if (snapshotAbortRef.current === controller) {
        snapshotAbortRef.current = null;
      }
    }
  }, []);

  const loadEvents = useCallback(async (agentId: string, cfg: EventsCfg) => {
    const mySeq = ++eventsSeqRef.current;
    eventsAbortRef.current?.abort();
    const controller = new AbortController();
    eventsAbortRef.current = controller;

    setEventsLoading(true);
    try {
      const lim = Math.max(50, Math.min(5000, safeNumber(cfg.limit, DEFAULT_EVENTS_LIMIT)));
      const win = Math.max(1, safeNumber(cfg.window_minutes, DEFAULT_WINDOW_MINUTES));
      const eventType = (cfg.event_type || "").trim() || undefined;
      const ev = await getRecentEvents(
        { limit: lim, agent_id: agentId, event_type: eventType, since_minutes: win },
        { signal: controller.signal, timeoutMs: 12000 }
      );
      if (eventsSeqRef.current !== mySeq) return;

      setEvents(ev);
      setSelectedEvent((prev) => {
        if (!prev) return ev[0] || null;
        const still = ev.find((x) => x.id === prev.id);
        return still || ev[0] || null;
      });

      setEventsError(null);
      setLastUpdatedAt(new Date());
    } catch (e: any) {
      if (isAbortError(e)) return;
      if (eventsSeqRef.current !== mySeq) return;
      setEventsError(getErrorMessage(e, "Failed to load events"));
      setEvents([]);
      setSelectedEvent(null);
    } finally {
      if (eventsSeqRef.current === mySeq) {
        setEventsLoading(false);
      }
      if (eventsAbortRef.current === controller) {
        eventsAbortRef.current = null;
      }
    }
  }, []);

  const refreshSelectedAgent = useCallback(async () => {
    if (!selectedAgentId) return;
    const cfg = eventsCfgRef.current;
    await Promise.all([
      loadAgent(selectedAgentId),
      loadSnapshot(selectedAgentId, cfg),
      loadEvents(selectedAgentId, cfg),
      refresh(),
    ]);
  }, [loadAgent, loadEvents, loadSnapshot, refresh, selectedAgentId]);

  const detailLive = useLiveRefresh({
    enabled: Boolean(selectedAgentId) && autoRefresh,
    profile: "hot-operational",
    refresh: refreshSelectedAgent,
  });

  useEffect(() => {
    if (!selectedAgentId) {
      setAgent(null);
      setSnapshot(null);
      setEvents([]);
      setSelectedEvent(null);
      setSnapshotError(null);
      setEventsError(null);
      return;
    }
    setSelectedEvent(null);
    if (!autoRefresh) {
      void refreshSelectedAgent();
      return;
    }
    detailLive.invalidate("dependency", { immediate: true, supersede: true });
  }, [autoRefresh, detailLive.invalidate, refreshSelectedAgent, selectedAgentId]);

  useEffect(() => {
    return () => {
      snapshotAbortRef.current?.abort();
      eventsAbortRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (!selectedAgentId) return;
    if (!detailLiveDidBootRef.current) {
      detailLiveDidBootRef.current = true;
      if (autoRefresh) return;
    }
    if (!autoRefresh) {
      const cfg = eventsCfgRef.current;
      void Promise.all([loadSnapshot(selectedAgentId, cfg), loadEvents(selectedAgentId, cfg)]);
      return;
    }
    detailLive.invalidate("dependency", { immediate: true, supersede: true });
  }, [autoRefresh, detailLive.invalidate, eventsCfg.limit, eventsCfg.window_minutes, loadEvents, loadSnapshot, selectedAgentId]);

  usePortalRealtimeSubscription("ui.agents.invalidate", () => {
    if (!selectedAgentId) return;
    detailLive.invalidate();
  });

  usePortalRealtimeSubscription("ui.agents.presence.patch", (event) => {
    if (!selectedAgentId) return;
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    if (eventAgentId && eventAgentId !== selectedAgentId) return;
    detailLive.invalidate();
  });

  usePortalRealtimeSubscription("ui.events.invalidate", (event) => {
    if (!selectedAgentId) return;
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    if (eventAgentId && eventAgentId !== selectedAgentId) return;
    detailLive.invalidate();
  });

  return {
    agents,
    agentsSorted,
    agentsFiltered,
    agentQuery,
    setAgentQuery,
    selectedAgentId,
    selectedAgentRow,
    selectAgent,
    refresh,
    agent,
    setAgent,
    agentError,
    loadAgent,
    snapshot,
    snapshotError,
    loadSnapshot,
    events,
    eventsError,
    eventsLoading,
    loadEvents,
    selectedEvent,
    setSelectedEvent,
    eventsCfg,
    setEventsCfg,
    eventsCfgRef,
    autoRefresh,
    setAutoRefresh,
    lastUpdatedAt,
    refreshSelectedAgent,
    detailLive,
    urlResponseActionTrigger,
  };
}
