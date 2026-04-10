import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { applyAgentHeartbeatRealtime } from "@/app/agents_realtime";
import { listAgents } from "@/features/agents/api";
import type { AgentPublic } from "@/features/agents/types";
import { AuthProvider, useAuth } from "@/features/auth/context";
import { PortalRealtimeProvider, usePortalRealtimeSubscription } from "@/shared/realtime";
import { getErrorMessage } from "@/shared/lib/errors";

type Theme = "dark" | "light";

type ThemeCtx = {
  theme: Theme;
  setTheme: (t: Theme) => void;
  toggleTheme: () => void;
};

const ThemeContext = createContext<ThemeCtx | null>(null);

type AgentsCtx = {
  agents: AgentPublic[];
  isLoading: boolean;
  error: string | null;
  selectedAgentId: string;
  setSelectedAgentId: (id: string) => void;
  refresh: () => Promise<void>;
};

const AgentsContext = createContext<AgentsCtx | null>(null);

const SELECTED_AGENT_KEY = "nw_selected_agent_id";

function applyThemeToDom(theme: Theme) {
  const root = document.documentElement;
  if (theme === "dark") root.classList.add("dark");
  else root.classList.remove("dark");
}

export function AppProviders({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => {
    const saved = (localStorage.getItem("netwatch_theme") || "").toLowerCase();
    return saved === "light" ? "light" : "dark";
  });

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    localStorage.setItem("netwatch_theme", t);
    applyThemeToDom(t);
  }, []);

  const toggleTheme = useCallback(() => setTheme(theme === "dark" ? "light" : "dark"), [theme, setTheme]);

  useEffect(() => {
    applyThemeToDom(theme);
  }, [theme]);

  const value = useMemo<ThemeCtx>(() => ({ theme, setTheme, toggleTheme }), [theme, setTheme, toggleTheme]);

  return (
    <ThemeContext.Provider value={value}>
      <AuthProvider>
        <AuthedProviders>{children}</AuthedProviders>
      </AuthProvider>
    </ThemeContext.Provider>
  );
}

function AuthedProviders({ children }: { children: ReactNode }) {
  const { status } = useAuth();

  // The login screen is public; avoid polling protected APIs until authenticated.
  if (status !== "authed") return <>{children}</>;

  return (
    <PortalRealtimeProvider enabled={status === "authed"}>
      <AgentsProvider>{children}</AgentsProvider>
    </PortalRealtimeProvider>
  );
}

function AgentsProvider({ children }: { children: ReactNode }) {
  const [agents, setAgents] = useState<AgentPublic[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [agentsError, setAgentsError] = useState<string | null>(null);
  const [selectedAgentId, setSelectedAgentIdState] = useState<string>(() => {
    try {
      return localStorage.getItem(SELECTED_AGENT_KEY) || "";
    } catch {
      return "";
    }
  });

  const setSelectedAgentId = (id: string) => {
    const safe = (id || "").trim();
    setSelectedAgentIdState(safe);
    try {
      localStorage.setItem(SELECTED_AGENT_KEY, safe);
    } catch {
      // no-op
    }
  };

  const selectedAgentRef = useRef(selectedAgentId);
  const agentsRef = useRef<AgentPublic[]>(agents);
  const unknownHeartbeatRefreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    selectedAgentRef.current = selectedAgentId;
  }, [selectedAgentId]);
  useEffect(() => {
    agentsRef.current = agents;
  }, [agents]);

  const refreshAgents = useCallback(async () => {
    try {
      const rows = await listAgents();
      setAgents(rows);
      setAgentsError(null);

      // If an agent was removed, drop the selection.
      const currentSel = (selectedAgentRef.current || "").trim();
      if (currentSel && !rows.some((a) => a.agent_id === currentSel)) {
        setSelectedAgentId("");
      }
    } catch (e: any) {
      setAgentsError(getErrorMessage(e, "Failed to load agents"));
    } finally {
      setAgentsLoading(false);
    }
  }, []);

  const scheduleRealtimeCatalogRefresh = useCallback(() => {
    if (unknownHeartbeatRefreshTimerRef.current) return;
    unknownHeartbeatRefreshTimerRef.current = window.setTimeout(() => {
      unknownHeartbeatRefreshTimerRef.current = null;
      void refreshAgents();
    }, 400);
  }, [refreshAgents]);

  usePortalRealtimeSubscription("ui.agents.presence.patch", (event) => {
    const result = applyAgentHeartbeatRealtime(agentsRef.current, event.payload || {}, event.timestamp);
    if (!result.agentId) return;
    if (!result.updated) {
      scheduleRealtimeCatalogRefresh();
      return;
    }
    agentsRef.current = result.agents;
    setAgents(result.agents);
  });

  usePortalRealtimeSubscription("ui.agents.invalidate", () => {
    scheduleRealtimeCatalogRefresh();
  });

  useEffect(() => {
    let alive = true;
    refreshAgents();

    // Lightweight refresh to keep the sidebar dropdown up-to-date.
    const t = window.setInterval(() => {
      if (!alive) return;
      refreshAgents();
    }, 15000);

    return () => {
      alive = false;
      if (unknownHeartbeatRefreshTimerRef.current) {
        window.clearTimeout(unknownHeartbeatRefreshTimerRef.current);
        unknownHeartbeatRefreshTimerRef.current = null;
      }
      window.clearInterval(t);
    };
  }, [refreshAgents]);

  const agentsValue = useMemo<AgentsCtx>(
    () => ({
      agents,
      isLoading: agentsLoading,
      error: agentsError,
      selectedAgentId,
      setSelectedAgentId,
      refresh: refreshAgents
    }),
    [agents, agentsLoading, agentsError, selectedAgentId, refreshAgents]
  );

  return (
    <AgentsContext.Provider value={agentsValue}>
      {children}
    </AgentsContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within AppProviders");
  return ctx;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAgentsCatalog() {
  const ctx = useContext(AgentsContext);
  if (!ctx) throw new Error("useAgentsCatalog must be used within AppProviders");
  return ctx;
}
