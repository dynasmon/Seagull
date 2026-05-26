import { useCallback, useEffect, useMemo, useState } from "react";

import { getErrorMessage } from "@/shared/lib/errors";

import { disableAgent, enableAgent, setAgentConfig, updateAgent } from "../api";
import type { AgentDetail, AgentUpdateIn } from "../types";
import {
  type DdosConfigDraft,
  DEFAULT_DDOS_DRAFT,
  safeJsonParse,
  normalizeTags,
  prettyJson,
  pickTimingKeys,
  getDdosConfig,
  withDdosConfig,
} from "../lib/agentUtils";

interface UseAgentConfigProps {
  agent: AgentDetail | null;
  onAgentUpdate: (a: AgentDetail) => void;
  onRefreshCatalog: () => void;
}

export function useAgentConfig({ agent, onAgentUpdate, onRefreshCatalog }: UseAgentConfigProps) {
  const [draftName, setDraftName] = useState("");
  const [draftDesc, setDraftDesc] = useState("");
  const [draftTags, setDraftTags] = useState("");
  const [draftMetaText, setDraftMetaText] = useState("{}");

  const [configText, setConfigText] = useState("{}");
  const [configObj, setConfigObj] = useState<Record<string, any>>({});
  const [configParseError, setConfigParseError] = useState<string | null>(null);
  const [ddosDraft, setDdosDraft] = useState<DdosConfigDraft>(DEFAULT_DDOS_DRAFT);

  const [saveBusy, setSaveBusy] = useState(false);
  const [configBusy, setConfigBusy] = useState(false);
  const [toggleBusy, setToggleBusy] = useState(false);

  const [agentError, setAgentError] = useState<string | null>(null);

  // Sync state when agent changes
  useEffect(() => {
    if (!agent) {
      setDraftName("");
      setDraftDesc("");
      setDraftTags("");
      setDraftMetaText("{}");
      setConfigObj({});
      setConfigText("{}");
      setDdosDraft(DEFAULT_DDOS_DRAFT);
      setConfigParseError(null);
      setAgentError(null);
      return;
    }

    setDraftName(agent.display_name || "");
    setDraftDesc(agent.description || "");
    setDraftTags((agent.tags || []).join(", "));
    setDraftMetaText(prettyJson(agent.metadata || {}));

    setConfigObj(agent.config || {});
    setConfigText(prettyJson(agent.config || {}));
    setDdosDraft(getDdosConfig(agent.config || {}));
    setConfigParseError(null);
  }, [agent]);

  const timingKeys = useMemo(() => pickTimingKeys(configObj), [configObj]);

  const dirty = useMemo(() => {
    if (!agent) return false;
    const desiredTags = normalizeTags(draftTags);
    const currentTags = (agent.tags || []).slice().sort();
    const desiredSorted = desiredTags.slice().sort();

    const meta = safeJsonParse(draftMetaText);
    const metaObj = meta.ok && typeof meta.value === "object" && meta.value ? meta.value : null;

    const nameChanged = (agent.display_name || "") !== draftName;
    const descChanged = (agent.description || "") !== draftDesc;
    const tagsChanged = JSON.stringify(currentTags) !== JSON.stringify(desiredSorted);
    const metaChanged = metaObj ? JSON.stringify(agent.metadata || {}) !== JSON.stringify(metaObj) : false;

    return nameChanged || descChanged || tagsChanged || metaChanged;
  }, [agent, draftName, draftDesc, draftTags, draftMetaText]);

  const canSaveAgent = useMemo(() => {
    if (!agent) return false;
    const meta = safeJsonParse(draftMetaText);
    if (!meta.ok) return false;
    if (meta.ok && (meta.value === null || typeof meta.value !== "object" || Array.isArray(meta.value))) return false;
    return dirty && !saveBusy;
  }, [agent, draftMetaText, dirty, saveBusy]);

  const onSaveAgent = useCallback(async () => {
    if (!agent) return;

    const meta = safeJsonParse(draftMetaText);
    if (!meta.ok) {
      setAgentError(`Metadata JSON: ${meta.error}`);
      return;
    }
    if (meta.value === null || typeof meta.value !== "object" || Array.isArray(meta.value)) {
      setAgentError("Metadata must be a JSON object");
      return;
    }

    const patch: AgentUpdateIn = {
      display_name: draftName.trim() || null,
      description: draftDesc.trim() || null,
      tags: normalizeTags(draftTags),
      metadata: meta.value,
    };

    setSaveBusy(true);
    try {
      const updated = await updateAgent(agent.agent_id, patch);
      onAgentUpdate(updated);
      setAgentError(null);
      onRefreshCatalog();
    } catch (e: any) {
      setAgentError(getErrorMessage(e, "Failed to update agent"));
    } finally {
      setSaveBusy(false);
    }
  }, [agent, draftName, draftDesc, draftTags, draftMetaText, onAgentUpdate, onRefreshCatalog]);

  const onToggleRevoked = useCallback(async () => {
    if (!agent) return;
    setToggleBusy(true);
    try {
      const updated = agent.is_revoked ? await enableAgent(agent.agent_id) : await disableAgent(agent.agent_id);
      onAgentUpdate(updated);
      setAgentError(null);
      onRefreshCatalog();
    } catch (e: any) {
      setAgentError(getErrorMessage(e, "Failed to update agent state"));
    } finally {
      setToggleBusy(false);
    }
  }, [agent, onAgentUpdate, onRefreshCatalog]);

  const pushAgentConfig = useCallback(async (nextConfig: Record<string, any>) => {
    if (!agent) return;
    setConfigBusy(true);
    try {
      const updated = await setAgentConfig(agent.agent_id, nextConfig);
      onAgentUpdate(updated);
      setConfigObj(updated.config || {});
      setConfigText(prettyJson(updated.config || {}));
      setDdosDraft(getDdosConfig(updated.config || {}));
      setConfigParseError(null);
      setAgentError(null);
    } catch (e: any) {
      setAgentError(getErrorMessage(e, "Failed to push config"));
    } finally {
      setConfigBusy(false);
    }
  }, [agent, onAgentUpdate]);

  const onApplyConfig = useCallback(async () => {
    if (!agent) return;

    const parsed = safeJsonParse(configText);
    if (!parsed.ok) {
      setConfigParseError(parsed.error);
      return;
    }
    if (parsed.value === null || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
      setConfigParseError("Config must be a JSON object");
      return;
    }

    await pushAgentConfig(parsed.value as Record<string, any>);
  }, [agent, configText, pushAgentConfig]);

  const onApplyDdosConfig = useCallback(async () => {
    if (!agent) return;
    const next = withDdosConfig(configObj || {}, ddosDraft);
    setConfigObj(next);
    setConfigText(prettyJson(next));
    setConfigParseError(null);
    await pushAgentConfig(next);
  }, [agent, configObj, ddosDraft, pushAgentConfig]);

  const onConfigTextChange = useCallback((v: string) => {
    setConfigText(v);
    const parsed = safeJsonParse(v);
    if (!parsed.ok) {
      setConfigParseError(parsed.error);
      return;
    }
    if (parsed.value === null || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
      setConfigParseError("Config must be a JSON object");
      return;
    }
    setConfigParseError(null);
    const next = parsed.value as Record<string, any>;
    setConfigObj(next);
    setDdosDraft(getDdosConfig(next));
  }, []);

  const onUpdateTiming = useCallback((key: string, value: number) => {
    const next = { ...(configObj || {}) };
    next[key] = value;
    setConfigObj(next);
    setConfigText(prettyJson(next));
    setDdosDraft(getDdosConfig(next));
    setConfigParseError(null);
  }, [configObj]);

  return {
    draftName,
    setDraftName,
    draftDesc,
    setDraftDesc,
    draftTags,
    setDraftTags,
    draftMetaText,
    setDraftMetaText,
    configText,
    setConfigText,
    configObj,
    configParseError,
    ddosDraft,
    setDdosDraft,
    timingKeys,
    saveBusy,
    configBusy,
    toggleBusy,
    agentError,
    dirty,
    canSaveAgent,
    onSaveAgent,
    onToggleRevoked,
    pushAgentConfig,
    onApplyConfig,
    onApplyDdosConfig,
    onConfigTextChange,
    onUpdateTiming,
  };
}

export type AgentConfigController = ReturnType<typeof useAgentConfig>;
