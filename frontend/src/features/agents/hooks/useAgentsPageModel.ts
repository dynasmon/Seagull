import { useCallback, useState } from "react";

import { useAuth } from "@/features/auth/context";
import { useDataTablePreferences } from "@/shared/hooks/useDataTablePreferences";

import { useAgents } from "./useAgents";
import { useAgentConfig } from "./useAgentConfig";
import { useAgentEnrollment } from "./useAgentEnrollment";
import { useAgentTelemetryViewModel } from "./useAgentTelemetryViewModel";
import { useAgentEventsExplorer } from "./useAgentEventsExplorer";

export function useAgentsPageModel() {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const [configOpen, setConfigOpen] = useState(false);
  const openConfig = useCallback(() => setConfigOpen(true), []);
  const closeConfig = useCallback(() => setConfigOpen(false), []);

  const [enrollOpen, setEnrollOpen] = useState(false);
  const openEnroll = useCallback(() => setEnrollOpen(true), []);
  const closeEnroll = useCallback(() => setEnrollOpen(false), []);

  const tablePrefs = useDataTablePreferences({
    storageKey: "nw_agents_tables_v2",
    defaultPageSize: 100,
    minPageSize: 25,
    maxPageSize: 200,
    defaultCompact: true,
  });

  const agents = useAgents();
  const config = useAgentConfig({
    agent: agents.agent,
    onAgentUpdate: agents.setAgent,
    onRefreshCatalog: agents.refresh,
  });
  const telemetry = useAgentTelemetryViewModel({
    snapshot: agents.snapshot,
    selectedAgentRow: agents.selectedAgentRow,
  });

  const events = useAgentEventsExplorer({
    events: agents.events,
    eventsCfg: agents.eventsCfg,
  });

  const enrollment = useAgentEnrollment({
    open: enrollOpen,
    isAdmin,
    onEnrolled: agents.refresh,
  });

  return {
    user,
    isAdmin,
    selectedAgentId: agents.selectedAgentId,
    compact: tablePrefs.compact,
    setCompact: tablePrefs.setCompact,
    agents,
    config,
    telemetry,
    events,
    configOpen,
    openConfig,
    closeConfig,
    enrollment,
    enrollOpen,
    openEnroll,
    closeEnroll,
  };
}

export type AgentsPageModel = ReturnType<typeof useAgentsPageModel>;
