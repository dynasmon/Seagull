import { useCallback, useEffect, useMemo, useState } from "react";

import { getErrorMessage } from "@/shared/lib/errors";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";
import { copyTextToClipboard } from "@/shared/components/investigation";

import {
  cancelResponseAction,
  createResponseAction,
  getResponseAction,
  getResponseActionResult,
  listResponseActions,
} from "../api";
import type { AgentPublic, ResponseActionOut, ResponseActionResultOut } from "../types";
import {
  RESPONSE_ACTION_TYPES,
  isOnline,
  fmtLastSeen,
  safeJsonParse,
  toIsoOrNullFromLocalInput,
  toLocalDateTimeInput,
  mergeResponseActionPatch,
  upsertResponseAction,
  mergeResponseActionResultSummary,
} from "../lib/agentUtils";
import type { UrlResponseActionTrigger } from "./useAgents";

interface UseAgentActionsProps {
  selectedAgentId: string;
  agents: AgentPublic[];
  agentsSorted: AgentPublic[];
  isAdmin: boolean;
  user: { username?: string } | null;
  onRefreshCatalog: () => void;
  urlResponseActionTrigger: UrlResponseActionTrigger;
}

export function useAgentActions({
  selectedAgentId,
  agents,
  isAdmin,
  onRefreshCatalog,
  urlResponseActionTrigger,
}: UseAgentActionsProps) {
  const [responseActionOpen, setResponseActionOpen] = useState(false);

  const [responseActionAgentId, setResponseActionAgentId] = useState("");
  const [responseActionType, setResponseActionType] = useState<string>(RESPONSE_ACTION_TYPES[0].key);
  const [responseActionPayloadText, setResponseActionPayloadText] = useState("{}");
  const [responseActionAdvancedOpen, setResponseActionAdvancedOpen] = useState(false);
  const [responseActionExpiresAt, setResponseActionExpiresAt] = useState("");
  const [responseActionError, setResponseActionError] = useState<string | null>(null);
  const [responseActionCreated, setResponseActionCreated] = useState<ResponseActionOut | null>(null);
  const [responseActionMode, setResponseActionMode] = useState<"create" | "investigate">("create");
  const [responseActionTab, setResponseActionTab] = useState<"create" | "execution" | "result">("create");
  const [responseActionSelectedId, setResponseActionSelectedId] = useState<number | null>(null);
  const [responseActionHistory, setResponseActionHistory] = useState<ResponseActionOut[]>([]);
  const [responseActionHistoryLoading, setResponseActionHistoryLoading] = useState(false);
  const [responseActionHistoryError, setResponseActionHistoryError] = useState<string | null>(null);
  const [responseActionLive, setResponseActionLive] = useState<ResponseActionOut | null>(null);
  const [responseActionLiveLoading, setResponseActionLiveLoading] = useState(false);
  const [responseActionLiveError, setResponseActionLiveError] = useState<string | null>(null);
  const [responseActionResult, setResponseActionResult] = useState<ResponseActionResultOut | null>(null);
  const [responseActionResultLoading, setResponseActionResultLoading] = useState(false);
  const [responseActionResultError, setResponseActionResultError] = useState<string | null>(null);
  const [responseActionResultRawOpen, setResponseActionResultRawOpen] = useState(false);
  const [pinResponseResultId, setPinResponseResultId] = useState<number | null>(null);
  const [responseActionBusy, setResponseActionBusy] = useState(false);

  const resetResponseActionForm = useCallback((agentId: string) => {
    setResponseActionAgentId(agentId);
    setResponseActionType(RESPONSE_ACTION_TYPES[0].key);
    setResponseActionPayloadText("{}");
    setResponseActionAdvancedOpen(false);
    setResponseActionExpiresAt("");
    setResponseActionError(null);
    setResponseActionCreated(null);
    setResponseActionMode("create");
    setResponseActionTab("create");
    setResponseActionSelectedId(null);
    setResponseActionHistory([]);
    setResponseActionHistoryLoading(false);
    setResponseActionHistoryError(null);
    setResponseActionLive(null);
    setResponseActionLiveLoading(false);
    setResponseActionLiveError(null);
    setResponseActionResult(null);
    setResponseActionResultLoading(false);
    setResponseActionResultError(null);
    setResponseActionResultRawOpen(false);
    setResponseActionBusy(false);
  }, []);

  // URL trigger effect — replaces the part of page.tsx URL effect that opened the drawer
  useEffect(() => {
    if (!urlResponseActionTrigger || !urlResponseActionTrigger.shouldOpen) return;

    resetResponseActionForm(urlResponseActionTrigger.agentId || "");
    setResponseActionOpen(true);
    if (urlResponseActionTrigger.actionId) {
      setResponseActionSelectedId(urlResponseActionTrigger.actionId);
    }
    setResponseActionTab(urlResponseActionTrigger.tab);
    setResponseActionMode(urlResponseActionTrigger.tab === "create" ? "create" : "investigate");
  }, [urlResponseActionTrigger, resetResponseActionForm]);

  useEffect(() => {
    if (!responseActionOpen) return;
    if (responseActionSelectedId) return;
    resetResponseActionForm(selectedAgentId || "");
  }, [responseActionOpen, selectedAgentId, responseActionSelectedId, resetResponseActionForm]);

  const loadResponseActionHistory = useCallback(async (agentId: string) => {
    if (!agentId.trim()) {
      setResponseActionHistory([]);
      setResponseActionHistoryError(null);
      return;
    }
    setResponseActionHistoryLoading(true);
    try {
      const rows = await listResponseActions({ agent_id: agentId.trim(), limit: 25 });
      setResponseActionHistory(rows);
      setResponseActionHistoryError(null);
      setResponseActionSelectedId((prev) => {
        if (prev) return prev;
        return rows[0]?.id ?? null;
      });
    } catch (e: any) {
      setResponseActionHistoryError(getErrorMessage(e, "Failed to load response actions"));
      setResponseActionHistory([]);
    } finally {
      setResponseActionHistoryLoading(false);
    }
  }, []);

  const loadResponseActionLive = useCallback(async (actionId: number) => {
    if (!Number.isFinite(actionId) || actionId <= 0) return;
    setResponseActionLiveLoading(true);
    try {
      const out = await getResponseAction(actionId);
      setResponseActionLive(out);
      setResponseActionLiveError(null);
      setResponseActionHistory((prev) => {
        const next = prev.filter((x) => x.id !== out.id);
        return [out, ...next].slice(0, 25);
      });
    } catch (e: any) {
      setResponseActionLiveError(getErrorMessage(e, "Failed to load response action"));
      setResponseActionLive(null);
    } finally {
      setResponseActionLiveLoading(false);
    }
  }, []);

  const loadResponseActionResult = useCallback(async (actionId: number) => {
    if (!Number.isFinite(actionId) || actionId <= 0) return;
    setResponseActionResultLoading(true);
    try {
      const out = await getResponseActionResult(actionId);
      setResponseActionResult(out);
      setResponseActionResultError(null);
    } catch (e: any) {
      setResponseActionResult(null);
      if (Number((e as any)?.status) === 404) {
        setResponseActionResultError(null);
      } else {
        setResponseActionResultError(getErrorMessage(e, "Response action result is not available"));
      }
    } finally {
      setResponseActionResultLoading(false);
    }
  }, []);

  const openResponseActionDrawer = useCallback(() => {
    resetResponseActionForm(selectedAgentId || "");
    setResponseActionOpen(true);
  }, [selectedAgentId, resetResponseActionForm]);

  const closeResponseActionDrawer = useCallback(() => {
    setResponseActionOpen(false);
    resetResponseActionForm(selectedAgentId || "");
  }, [selectedAgentId, resetResponseActionForm]);

  const setResponseActionExpiryOffset = useCallback((minutes: number) => {
    const dt = new Date(Date.now() + minutes * 60_000);
    setResponseActionExpiresAt(toLocalDateTimeInput(dt));
    setResponseActionError(null);
    setResponseActionCreated(null);
  }, []);

  const onSelectResponseAction = useCallback((actionId: number, nextTab: "execution" | "result" = "execution") => {
    if (!Number.isFinite(actionId) || actionId <= 0) {
      setResponseActionSelectedId(null);
      return;
    }
    setResponseActionSelectedId(actionId);
    setResponseActionError(null);
    setResponseActionResultRawOpen(false);
    setResponseActionMode("investigate");
    setResponseActionTab(nextTab);
  }, []);

  const onCancelSelectedResponseAction = useCallback(async () => {
    if (!responseActionSelectedId) return;
    setResponseActionBusy(true);
    setResponseActionError(null);
    try {
      const out = await cancelResponseAction(responseActionSelectedId);
      setResponseActionLive(out);
      await loadResponseActionHistory(responseActionAgentId);
    } catch (e: any) {
      setResponseActionError(getErrorMessage(e, "Failed to cancel response action"));
    } finally {
      setResponseActionBusy(false);
    }
  }, [responseActionSelectedId, responseActionAgentId, loadResponseActionHistory]);

  const onCopyResponseResultJson = useCallback(async () => {
    const payload = responseActionResult?.result_payload || {};
    const ok = await copyTextToClipboard(JSON.stringify(payload, null, 2));
    if (!ok) {
      setResponseActionError("Failed to copy result JSON");
    }
  }, [responseActionResult]);

  const onDownloadResponseResultJson = useCallback(() => {
    const payload = responseActionResult?.result_payload || {};
    const actionId = responseActionSelectedId || 0;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `response-action-${actionId}-result.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [responseActionResult, responseActionSelectedId]);

  // Derived memos
  const responseActionDefinition = useMemo(() => {
    return RESPONSE_ACTION_TYPES.find((x) => x.key === responseActionType) || RESPONSE_ACTION_TYPES[0];
  }, [responseActionType]);

  const responseActionAgentRow = useMemo(() => {
    return agents.find((a) => a.agent_id === responseActionAgentId) || null;
  }, [agents, responseActionAgentId]);

  const responseActionPayload = useMemo(() => {
    if (!responseActionAdvancedOpen) return { error: null, payload: {} as Record<string, any> };
    const parsed = safeJsonParse(responseActionPayloadText);
    if (!parsed.ok) return { error: parsed.error, payload: null as Record<string, any> | null };
    if (parsed.value === null || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
      return { error: "Payload must be a JSON object", payload: null as Record<string, any> | null };
    }
    return { error: null, payload: parsed.value as Record<string, any> };
  }, [responseActionAdvancedOpen, responseActionPayloadText]);

  const responseActionPayloadError = responseActionPayload.error;

  const responseActionExpiresIso = useMemo(() => {
    return toIsoOrNullFromLocalInput(responseActionExpiresAt);
  }, [responseActionExpiresAt]);

  const responseActionExpirationInvalid = useMemo(() => {
    return Boolean(responseActionExpiresAt.trim()) && !responseActionExpiresIso;
  }, [responseActionExpiresAt, responseActionExpiresIso]);

  const responseActionExpirationInPast = useMemo(() => {
    if (!responseActionExpiresIso) return false;
    return Date.parse(responseActionExpiresIso) <= Date.now();
  }, [responseActionExpiresIso]);

  const responseActionAgentStatus = useMemo(() => {
    if (!responseActionAgentRow) return "Unknown";
    if (responseActionAgentRow.is_revoked) return "Disabled";
    return isOnline(responseActionAgentRow.last_seen_at) ? "Online" : "Offline";
  }, [responseActionAgentRow]);

  const responseActionExpiresLabel = useMemo(() => {
    if (!responseActionExpiresIso) return "Not set";
    const dt = new Date(responseActionExpiresIso);
    if (Number.isNaN(dt.getTime())) return "Invalid";
    return dt.toLocaleString();
  }, [responseActionExpiresIso]);

  const canSubmitResponseAction = useMemo(() => {
    if (!isAdmin) return false;
    if (responseActionBusy) return false;
    if (!responseActionAgentId.trim()) return false;
    if (!responseActionType.trim()) return false;
    if (responseActionPayloadError) return false;
    if (responseActionExpirationInvalid || responseActionExpirationInPast) return false;
    return true;
  }, [
    isAdmin,
    responseActionBusy,
    responseActionAgentId,
    responseActionType,
    responseActionPayloadError,
    responseActionExpirationInvalid,
    responseActionExpirationInPast,
  ]);

  const responseActionSelected = useMemo(() => {
    if (!responseActionSelectedId) return null;
    return responseActionHistory.find((x) => x.id === responseActionSelectedId) || responseActionLive || null;
  }, [responseActionSelectedId, responseActionHistory, responseActionLive]);

  const responseActionLiveView = useMemo(() => {
    return responseActionLive || responseActionSelected;
  }, [responseActionLive, responseActionSelected]);

  const responseActionCanCancel = useMemo(() => {
    const s = (responseActionLiveView?.status || "").trim().toLowerCase();
    return s === "pending" || s === "delivered";
  }, [responseActionLiveView]);

  const responseActionLiveRefresh = useLiveRefresh({
    enabled:
      responseActionOpen &&
      Boolean(responseActionSelectedId) &&
      ["pending", "delivered", "running"].includes((responseActionLiveView?.status || "").trim().toLowerCase()),
    profile: "background-detail",
    refresh: async () => {
      if (!responseActionSelectedId) return;
      await Promise.all([
        loadResponseActionLive(responseActionSelectedId),
        loadResponseActionResult(responseActionSelectedId),
      ]);
    },
  });

  useEffect(() => {
    if (!responseActionOpen || !isAdmin) return;
    loadResponseActionHistory(responseActionAgentId || "");
  }, [responseActionOpen, isAdmin, responseActionAgentId, loadResponseActionHistory]);

  useEffect(() => {
    if (!responseActionOpen || !responseActionSelectedId) return;
    responseActionLiveRefresh.invalidate("dependency", { immediate: true, supersede: true });
  }, [responseActionLiveRefresh.invalidate, responseActionOpen, responseActionSelectedId]);

  const onSubmitResponseAction = useCallback(async () => {
    const agentId = responseActionAgentId.trim();
    if (!agentId) {
      setResponseActionError("Agent is required");
      return;
    }
    if (!responseActionType.trim()) {
      setResponseActionError("Action type is required");
      return;
    }
    if (responseActionPayload.error || !responseActionPayload.payload) {
      setResponseActionError(responseActionPayload.error || "Payload must be a JSON object");
      return;
    }

    if (responseActionExpirationInvalid) {
      setResponseActionError("Expiration must be a valid date and time");
      return;
    }
    if (responseActionExpirationInPast) {
      setResponseActionError("Expiration must be in the future");
      return;
    }

    setResponseActionBusy(true);
    setResponseActionError(null);
    setResponseActionCreated(null);
    try {
      const out = await createResponseAction({
        action_type: responseActionType.trim(),
        agent_id: agentId,
        payload: responseActionPayload.payload,
        expires_at: responseActionExpiresIso || undefined,
      });
      setResponseActionCreated(out);
      setResponseActionSelectedId(out.id);
      setResponseActionMode("investigate");
      setResponseActionTab("execution");
      setResponseActionLive(out);
      await loadResponseActionHistory(agentId);
      await loadResponseActionResult(out.id);
      onRefreshCatalog();
    } catch (e: any) {
      setResponseActionError(getErrorMessage(e, "Failed to create response action"));
    } finally {
      setResponseActionBusy(false);
    }
  }, [
    responseActionAgentId,
    responseActionType,
    responseActionPayload,
    responseActionExpirationInvalid,
    responseActionExpirationInPast,
    responseActionExpiresIso,
    loadResponseActionHistory,
    loadResponseActionResult,
    onRefreshCatalog,
  ]);

  usePortalRealtimeSubscription("ui.response_actions.lifecycle.patch", (event) => {
    if (!responseActionOpen || !isAdmin) return;

    const eventAgentId = String(event.payload?.agent_id ?? event.payload?.workflow?.agent_id ?? "").trim();
    const eventActionId = Number(event.payload?.action_id ?? event.payload?.workflow?.id ?? event.payload?.result?.response_action_id ?? 0);
    const activeAgentId = (responseActionAgentId || selectedAgentId || "").trim();
    const selectedActionId = responseActionSelectedId || responseActionLive?.id || responseActionCreated?.id || 0;
    const matchesAgent = !activeAgentId || !eventAgentId || eventAgentId === activeAgentId;
    const matchesAction = selectedActionId > 0 && eventActionId > 0 && eventActionId === selectedActionId;
    if (!matchesAgent && !matchesAction) return;

    const workflowPatch = (event.payload?.workflow || null) as Record<string, any> | null;
    const resultPatch = (event.payload?.result || null) as Record<string, any> | null;
    if (workflowPatch) {
      setResponseActionHistory((prev) => {
        const existing = prev.find((row) => row.id === eventActionId) || null;
        const merged = mergeResponseActionPatch(existing, workflowPatch, eventActionId);
        if (!merged) return prev;
        return upsertResponseAction(prev, merged);
      });
      setResponseActionLive((prev) => {
        if (prev && prev.id !== eventActionId) return prev;
        if (!prev && !matchesAction) return prev;
        return mergeResponseActionPatch(prev, workflowPatch, eventActionId) ?? prev;
      });
      setResponseActionCreated((prev) => {
        if (!prev || prev.id !== eventActionId) return prev;
        return mergeResponseActionPatch(prev, workflowPatch, eventActionId) ?? prev;
      });
      setResponseActionLiveError(null);
      setResponseActionHistoryError(null);
      setResponseActionLiveLoading(false);
      if (!responseActionSelectedId && eventActionId > 0 && matchesAgent) {
        setResponseActionSelectedId(eventActionId);
      }
    }

    if (resultPatch && matchesAction) {
      setResponseActionResult((prev) => mergeResponseActionResultSummary(prev, resultPatch, eventActionId));
      setResponseActionResultError(null);
      setResponseActionResultLoading(false);
    }

    const lifecycleEvent = String(event.payload?.lifecycle_event || "").trim().toLowerCase();
    const requiresReconcile = Boolean(event.payload?.requires_reconcile);
    const shouldHydrateSelectedResult =
      matchesAction &&
      (lifecycleEvent === "completed" ||
        lifecycleEvent === "failed" ||
        lifecycleEvent === "cancelled" ||
        lifecycleEvent === "expired");

    if (shouldHydrateSelectedResult && eventActionId > 0) {
      void loadResponseActionResult(eventActionId);
    }

    if (requiresReconcile && eventActionId > 0) {
      if (matchesAction) {
        responseActionLiveRefresh.invalidate("invalidate", { immediate: true, supersede: false });
      } else if (matchesAgent && activeAgentId) {
        void loadResponseActionHistory(activeAgentId);
      }
    }
  });

  usePortalRealtimeSubscription("ui.workflows.invalidate", (event) => {
    if (!responseActionOpen || !isAdmin) return;

    const eventAgentId = String(event.payload?.agent_id || "").trim();
    const eventActionId = Number(event.payload?.action_id ?? 0);
    const activeAgentId = (responseActionAgentId || selectedAgentId || "").trim();
    if (eventAgentId && activeAgentId && eventAgentId !== activeAgentId) return;
    if (eventActionId > 0 && responseActionSelectedId && eventActionId !== responseActionSelectedId) return;

    if (activeAgentId) {
      void loadResponseActionHistory(activeAgentId);
    }
    if (responseActionSelectedId) {
      responseActionLiveRefresh.invalidate("invalidate", { immediate: true, supersede: false });
    }
  });

  return {
    responseActionOpen,
    setResponseActionOpen,
    responseActionAgentId,
    setResponseActionAgentId,
    responseActionType,
    setResponseActionType,
    responseActionPayloadText,
    setResponseActionPayloadText,
    responseActionAdvancedOpen,
    setResponseActionAdvancedOpen,
    responseActionExpiresAt,
    setResponseActionExpiresAt,
    responseActionError,
    setResponseActionError,
    responseActionCreated,
    setResponseActionCreated,
    responseActionMode,
    setResponseActionMode,
    responseActionTab,
    setResponseActionTab,
    responseActionSelectedId,
    setResponseActionSelectedId,
    responseActionHistory,
    responseActionHistoryLoading,
    responseActionHistoryError,
    responseActionLive,
    responseActionLiveLoading,
    responseActionLiveError,
    responseActionResult,
    responseActionResultLoading,
    responseActionResultError,
    responseActionResultRawOpen,
    setResponseActionResultRawOpen,
    pinResponseResultId,
    setPinResponseResultId,
    responseActionBusy,
    resetResponseActionForm,
    loadResponseActionHistory,
    loadResponseActionLive,
    loadResponseActionResult,
    openResponseActionDrawer,
    closeResponseActionDrawer,
    setResponseActionExpiryOffset,
    onSelectResponseAction,
    onCancelSelectedResponseAction,
    onCopyResponseResultJson,
    onDownloadResponseResultJson,
    onSubmitResponseAction,
    responseActionDefinition,
    responseActionAgentRow,
    responseActionPayload,
    responseActionPayloadError,
    responseActionExpiresIso,
    responseActionExpirationInvalid,
    responseActionExpirationInPast,
    responseActionAgentStatus,
    responseActionExpiresLabel,
    canSubmitResponseAction,
    responseActionSelected,
    responseActionLiveView,
    responseActionCanCancel,
    responseActionLiveRefresh,
    fmtLastSeen,
  };
}

export type AgentActionsController = ReturnType<typeof useAgentActions>;
