import { useCallback, useEffect, useRef, useState } from "react";

import { isAbortError } from "@/shared/lib/http";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";

import { getInventoryOverview } from "../api";
import type { InventoryOverviewSnapshot } from "../types";

interface UseInventoryOverviewParams {
  agentScope: string;
  windowMinutes: number;
}

export function useInventoryOverview({ agentScope, windowMinutes }: UseInventoryOverviewParams) {
  const [snapshot, setSnapshot] = useState<InventoryOverviewSnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshSeqRef = useRef(0);
  const refreshAbortRef = useRef<AbortController | null>(null);

  const refresh = useCallback(async () => {
    const mySeq = ++refreshSeqRef.current;
    refreshAbortRef.current?.abort();
    const controller = new AbortController();
    refreshAbortRef.current = controller;
    setBusy(true);

    try {
      const data = await getInventoryOverview(
        { window_minutes: windowMinutes, agent_id: agentScope },
        { signal: controller.signal, timeoutMs: 12000 }
      );
      if (refreshSeqRef.current !== mySeq) return;
      setSnapshot(data);
      setError(null);
    } catch (e: any) {
      if (isAbortError(e)) return;
      if (refreshSeqRef.current !== mySeq) return;
      setError(e?.message || "Failed to load inventory overview");
    } finally {
      if (refreshSeqRef.current === mySeq) setBusy(false);
      if (refreshAbortRef.current === controller) refreshAbortRef.current = null;
    }
  }, [agentScope, windowMinutes]);

  const live = useLiveRefresh({
    profile: windowMinutes > 24 * 60 ? "expensive-operational" : "operational",
    refresh,
  });

  useEffect(() => {
    live.invalidate("dependency", { immediate: true, supersede: true });
  }, [agentScope, live.invalidate, windowMinutes]);

  usePortalRealtimeSubscription("ui.inventory.invalidate", (event) => {
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    if (agentScope !== "__all" && eventAgentId && eventAgentId !== agentScope) return;
    live.invalidate();
  });

  usePortalRealtimeSubscription("ui.agents.invalidate", () => {
    live.invalidate();
  });

  usePortalRealtimeSubscription("ui.agents.presence.patch", (event) => {
    const eventAgentId = String(event.payload?.agent_id || "").trim();
    if (agentScope !== "__all" && eventAgentId && eventAgentId !== agentScope) return;
    live.invalidate();
  });

  useEffect(() => {
    return () => {
      refreshAbortRef.current?.abort();
    };
  }, []);

  return { snapshot, busy, error, live };
}

export type InventoryOverviewController = ReturnType<typeof useInventoryOverview>;
