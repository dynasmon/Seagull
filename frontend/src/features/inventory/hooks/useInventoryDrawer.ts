import { useCallback, useEffect, useRef, useState } from "react";

import { disableAgent, enableAgent, getAgent, setAgentConfig, updateAgent } from "@/features/agents/api";
import type { AgentDetail } from "@/features/agents/types";

import { getInventoryLatest, getInventoryHistory } from "../api";
import type { DrawerTab, InventorySnapshotOut } from "../types";
import { normalizeTagsInput, safeJsonParse } from "../lib/inventoryParsers";

interface UseInventoryDrawerParams {
  urlAgentId: string;
  urlSnapshotId: number | null;
  urlOpenDrawer: boolean;
}

export function useInventoryDrawer({ urlAgentId, urlSnapshotId, urlOpenDrawer }: UseInventoryDrawerParams) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerAgentId, setDrawerAgentId] = useState<string | null>(null);
  const [drawerTab, setDrawerTab] = useState<DrawerTab>("overview");
  const [drawerCopied, setDrawerCopied] = useState<null | "ok" | "fail">(null);

  const [drawerAgent, setDrawerAgent] = useState<AgentDetail | null>(null);
  const [drawerLatest, setDrawerLatest] = useState<InventorySnapshotOut | null>(null);
  const [drawerHistory, setDrawerHistory] = useState<InventorySnapshotOut[]>([]);
  const [drawerErr, setDrawerErr] = useState<string | null>(null);
  const [drawerBusy, setDrawerBusy] = useState(false);

  const [focusedSnapshotId, setFocusedSnapshotId] = useState<number | null>(null);
  const [pinSnapshotId, setPinSnapshotId] = useState<number | null>(null);
  const [pkgQuery, setPkgQuery] = useState("");

  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editTags, setEditTags] = useState("");
  const [editConfig, setEditConfig] = useState("{}");
  const [editMsg, setEditMsg] = useState<string | null>(null);

  const deepLinkHandledRef = useRef<string | null>(null);

  const openDrawer = useCallback(async (agentId: string, focusSnapshotId?: number | null) => {
    const id = (agentId || "").trim();
    if (!id) return;

    setDrawerOpen(true);
    setDrawerAgentId(id);
    setDrawerTab("overview");
    setDrawerErr(null);
    setEditMsg(null);
    setDrawerCopied(null);
    setPkgQuery("");

    setDrawerBusy(true);
    try {
      const [a, latest, hist] = await Promise.all([
        getAgent(id),
        getInventoryLatest(id).catch(() => null),
        getInventoryHistory(id, { limit: 20 }).catch(() => []),
      ]);

      setDrawerAgent(a);
      setDrawerLatest(latest);
      setDrawerHistory(hist);
      setFocusedSnapshotId(typeof focusSnapshotId === "number" ? focusSnapshotId : null);

      setEditName(a.display_name || "");
      setEditDesc(a.description || "");
      setEditTags((a.tags || []).join(", "));
      setEditConfig(JSON.stringify(a.config || {}, null, 2));
    } catch (e: any) {
      setDrawerErr(e?.message || "Failed to load agent details");
    } finally {
      setDrawerBusy(false);
    }
  }, []);

  useEffect(() => {
    if (urlAgentId === "__all") return;
    if (!urlSnapshotId && !urlOpenDrawer) return;
    const key = `${urlAgentId}:${urlSnapshotId || ""}:${urlOpenDrawer ? "1" : "0"}`;
    if (deepLinkHandledRef.current === key) return;
    deepLinkHandledRef.current = key;
    openDrawer(urlAgentId, urlSnapshotId);
  }, [urlAgentId, urlSnapshotId, urlOpenDrawer, openDrawer]);

  function closeDrawer() {
    setDrawerOpen(false);
    setDrawerAgentId(null);
    setDrawerAgent(null);
    setDrawerLatest(null);
    setDrawerHistory([]);
    setDrawerErr(null);
    setEditMsg(null);
    setFocusedSnapshotId(null);
    setDrawerCopied(null);
  }

  async function saveMetadata() {
    if (!drawerAgentId) return;
    setEditMsg(null);
    setDrawerBusy(true);
    try {
      const next = await updateAgent(drawerAgentId, {
        display_name: editName.trim() ? editName.trim() : null,
        description: editDesc.trim() ? editDesc.trim() : null,
        tags: normalizeTagsInput(editTags),
      });
      setDrawerAgent(next);
      setEditMsg("Metadata updated.");
    } catch (e: any) {
      setEditMsg(e?.message || "Failed to update metadata");
    } finally {
      setDrawerBusy(false);
    }
  }

  async function toggleAgentState() {
    if (!drawerAgentId || !drawerAgent) return;
    setEditMsg(null);
    setDrawerBusy(true);
    try {
      const next = drawerAgent.is_revoked
        ? await enableAgent(drawerAgentId)
        : await disableAgent(drawerAgentId);
      setDrawerAgent(next);
      setEditMsg("State updated.");
    } catch (e: any) {
      setEditMsg(e?.message || "Failed to update state");
    } finally {
      setDrawerBusy(false);
    }
  }

  async function saveConfig() {
    if (!drawerAgentId) return;
    setEditMsg(null);
    const parsed = safeJsonParse(editConfig);
    if (!parsed.ok) {
      setEditMsg(parsed.error);
      return;
    }
    setDrawerBusy(true);
    try {
      const next = await setAgentConfig(drawerAgentId, parsed.data);
      setDrawerAgent(next);
      setEditMsg("Config updated.");
    } catch (e: any) {
      setEditMsg(e?.message || "Failed to update config");
    } finally {
      setDrawerBusy(false);
    }
  }

  function resetConfig() {
    if (!drawerAgent) return;
    setEditConfig(JSON.stringify(drawerAgent.config || {}, null, 2));
  }

  return {
    drawerOpen,
    drawerAgentId,
    drawerTab,
    setDrawerTab,
    drawerCopied,
    setDrawerCopied,
    drawerAgent,
    drawerLatest,
    drawerHistory,
    drawerErr,
    drawerBusy,
    focusedSnapshotId,
    setFocusedSnapshotId,
    pinSnapshotId,
    setPinSnapshotId,
    pkgQuery,
    setPkgQuery,
    editName,
    setEditName,
    editDesc,
    setEditDesc,
    editTags,
    setEditTags,
    editConfig,
    setEditConfig,
    editMsg,
    openDrawer,
    closeDrawer,
    saveMetadata,
    toggleAgentState,
    saveConfig,
    resetConfig,
  };
}

export type InventoryDrawerController = ReturnType<typeof useInventoryDrawer>;
