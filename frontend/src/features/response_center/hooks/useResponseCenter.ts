import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { listAgents } from "@/features/agents/api";
import type { AgentPublic } from "@/features/agents/types";
import { useUrlQueryState } from "@/shared/hooks/useUrlQueryState";
import { getErrorMessage } from "@/shared/lib/errors";
import { isAbortError } from "@/shared/lib/http";
import { useLiveRefresh } from "@/shared/realtime";
import { usePortalRealtimeSubscription } from "@/shared/realtime/context";

import { listActionTypes, listResponseActions } from "../api";
import { sinceTokenToIso } from "../lib";
import type { ActionTypeOut, ExecutionFilters, ResponseActionListParams, ResponseActionOut } from "../types";

function parseFilters(sp: URLSearchParams): ExecutionFilters {
  return {
    statuses: (sp.get("status") || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    category: sp.get("category") || "",
    agentId: sp.get("agent") || "",
    since: sp.get("since") || "",
    batchId: sp.get("batch_id") || "",
  };
}

function serializeFilters(state: ExecutionFilters): URLSearchParams {
  const sp = new URLSearchParams();
  if (state.statuses.length) sp.set("status", state.statuses.join(","));
  if (state.category) sp.set("category", state.category);
  if (state.agentId) sp.set("agent", state.agentId);
  if (state.since) sp.set("since", state.since);
  if (state.batchId) sp.set("batch_id", state.batchId);
  return sp;
}

export function useResponseCenter({ enabled = true }: { enabled?: boolean } = {}) {
  const [searchParams] = useSearchParams();
  const deepLinkRef = useRef({
    agentId: searchParams.get("agent_id") || "",
    mode: searchParams.get("mode") || "",
    actionId: Number(searchParams.get("action_id")) || 0,
  });

  const [catalog, setCatalog] = useState<ActionTypeOut[]>([]);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [catalogLoading, setCatalogLoading] = useState(true);

  const [agents, setAgents] = useState<AgentPublic[]>([]);

  const [allExecutions, setAllExecutions] = useState<ResponseActionOut[]>([]);
  const [executionsError, setExecutionsError] = useState<string | null>(null);

  const [filters, setFilters] = useUrlQueryState<ExecutionFilters>({
    parse: parseFilters,
    serialize: serializeFilters,
  });

  const [selectedActionKey, setSelectedActionKey] = useState<string | null>(null);
  const [prefill, setPrefill] = useState<{ actionKey: string; payload: Record<string, any> } | null>(null);
  const [dispatchAgentId, setDispatchAgentId] = useState<string>(deepLinkRef.current.agentId);
  const [detailId, setDetailId] = useState<number | null>(
    deepLinkRef.current.actionId > 0 ? deepLinkRef.current.actionId : null,
  );
  const [dispatchOpen, setDispatchOpen] = useState(deepLinkRef.current.mode === "dispatch");

  const filtersRef = useRef(filters);
  useEffect(() => {
    filtersRef.current = filters;
  }, [filters]);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    setCatalogLoading(true);
    listActionTypes({ cacheMs: 60_000 })
      .then((rows) => {
        if (cancelled) return;
        setCatalog(rows);
        setCatalogError(null);
      })
      .catch((error) => {
        if (cancelled || isAbortError(error)) return;
        setCatalogError(getErrorMessage(error, "Failed to load action catalog"));
      })
      .finally(() => {
        if (!cancelled) setCatalogLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [enabled]);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    listAgents()
      .then((rows) => {
        if (!cancelled) setAgents(rows);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [enabled]);

  const { state: refreshState, refreshNow, invalidate } = useLiveRefresh({
    enabled,
    refresh: async ({ signal }) => {
      const f = filtersRef.current;
      const params: ResponseActionListParams = {
        category: f.category || undefined,
        agent_id: f.agentId || undefined,
        batch_id: f.batchId || undefined,
        since: sinceTokenToIso(f.since) || undefined,
        limit: 200,
      };
      try {
        const rows = await listResponseActions(params, { signal, force: true });
        setAllExecutions(rows);
        setExecutionsError(null);
      } catch (error) {
        if (isAbortError(error)) return;
        setExecutionsError(getErrorMessage(error, "Failed to load executions"));
      }
    },
  });

  usePortalRealtimeSubscription("ui.response_actions.lifecycle.patch", () => invalidate());

  const didMountRef = useRef(false);
  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      return;
    }
    invalidate("dependency", { immediate: true });
  }, [filters.category, filters.agentId, filters.since, filters.batchId, invalidate]);

  const executions = useMemo(() => {
    if (!filters.statuses.length) return allExecutions;
    const wanted = new Set(filters.statuses);
    return allExecutions.filter((row) => wanted.has(row.status));
  }, [allExecutions, filters.statuses]);

  const stats = useMemo(() => {
    const counts = { total: allExecutions.length, queued: 0, running: 0, succeeded: 0, failed: 0, inactive: 0 };
    for (const row of allExecutions) {
      switch (row.status) {
        case "pending":
        case "delivered":
          counts.queued += 1;
          break;
        case "running":
          counts.running += 1;
          break;
        case "success":
          counts.succeeded += 1;
          break;
        case "failed":
          counts.failed += 1;
          break;
        case "cancelled":
        case "expired":
          counts.inactive += 1;
          break;
        default:
          break;
      }
    }
    return counts;
  }, [allExecutions]);

  const openDetail = useCallback((actionId: number) => setDetailId(actionId), []);
  const closeDetail = useCallback(() => setDetailId(null), []);
  const openDispatch = useCallback(() => {
    setPrefill(null);
    setDispatchOpen(true);
  }, []);
  const closeDispatch = useCallback(() => setDispatchOpen(false), []);
  const openDispatchWith = useCallback(
    (input: { actionKey: string; agentId?: string; payload?: Record<string, any> }) => {
      setSelectedActionKey(input.actionKey);
      if (input.agentId) setDispatchAgentId(input.agentId);
      setPrefill(input.payload ? { actionKey: input.actionKey, payload: input.payload } : null);
      setDispatchOpen(true);
    },
    [],
  );

  const prefillPayload = useMemo(
    () => (prefill && prefill.actionKey === selectedActionKey ? prefill.payload : null),
    [prefill, selectedActionKey],
  );
  const reload = useCallback(() => {
    void refreshNow();
  }, [refreshNow]);

  return {
    catalog,
    catalogError,
    catalogLoading,
    agents,
    executions,
    executionsError,
    refreshState,
    stats,
    filters,
    setFilters,
    selectedActionKey,
    setSelectedActionKey,
    dispatchAgentId,
    setDispatchAgentId,
    detailId,
    openDetail,
    closeDetail,
    dispatchOpen,
    openDispatch,
    openDispatchWith,
    closeDispatch,
    prefillPayload,
    reload,
    deepLinkMode: deepLinkRef.current.mode,
  };
}

export type ResponseCenterModel = ReturnType<typeof useResponseCenter>;
