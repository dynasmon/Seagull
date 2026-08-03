import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import { applyAgentHeartbeatRealtime } from "@/app/agents_realtime";
import { listAgents } from "@/features/agents/api";
import { sameAgentList } from "@/features/agents/lib/agentUtils";
import type { AgentPublic } from "@/features/agents/types";
import { AuthProvider, useAuth } from "@/features/auth/context";
import EuiRoot from "@/app/eui/EuiRoot";
import { PortalRealtimeProvider, useLiveRefresh, usePortalRealtime, usePortalRealtimeSubscription } from "@/shared/realtime";
import StatusBanner from "@/shared/components/StatusBanner";
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
const RECONNECT_NOTICE_DELAY_MS = 900;

function applyThemeToDom(theme: Theme) {
  const root = document.documentElement;
  if (theme === "dark") root.classList.add("dark");
  else root.classList.remove("dark");
}

export function AppProviders({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => {
    const saved = (localStorage.getItem("seagull_theme") || "").toLowerCase();
    return saved === "light" ? "light" : "dark";
  });

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    localStorage.setItem("seagull_theme", t);
    applyThemeToDom(t);
  }, []);

  const toggleTheme = useCallback(() => setTheme(theme === "dark" ? "light" : "dark"), [theme, setTheme]);

  useEffect(() => {
    applyThemeToDom(theme);
  }, [theme]);

  const value = useMemo<ThemeCtx>(() => ({ theme, setTheme, toggleTheme }), [theme, setTheme, toggleTheme]);

  return (
    <ThemeContext.Provider value={value}>
      <EuiRoot colorMode={theme}>
        <AuthProvider>
          <AuthedProviders>{children}</AuthedProviders>
        </AuthProvider>
      </EuiRoot>
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

  const setSelectedAgentId = useCallback((id: string) => {
    const safe = (id || "").trim();
    setSelectedAgentIdState(safe);
    try {
      localStorage.setItem(SELECTED_AGENT_KEY, safe);
    } catch {}
  }, []);

  const selectedAgentRef = useRef(selectedAgentId);
  const agentsRef = useRef<AgentPublic[]>(agents);
  useEffect(() => {
    selectedAgentRef.current = selectedAgentId;
  }, [selectedAgentId]);
  useEffect(() => {
    agentsRef.current = agents;
  }, [agents]);

  const refreshAgents = useCallback(async () => {
    try {
      const rows = await listAgents();
      setAgents((prev) => (sameAgentList(prev, rows) ? prev : rows));
      setAgentsError(null);

      const currentSel = (selectedAgentRef.current || "").trim();
      if (currentSel && !rows.some((a) => a.agent_id === currentSel)) {
        setSelectedAgentId("");
      }
    } catch (e: any) {
      setAgentsError(getErrorMessage(e, "Failed to load agents"));
    } finally {
      setAgentsLoading(false);
    }
  }, [setSelectedAgentId]);

  const live = useLiveRefresh({
    profile: "operational",
    refresh: refreshAgents,
  });

  usePortalRealtimeSubscription("ui.agents.presence.patch", (event) => {
    const result = applyAgentHeartbeatRealtime(agentsRef.current, event.payload || {}, event.timestamp);
    if (!result.agentId) return;
    if (!result.updated) {
      live.invalidate();
      return;
    }
    agentsRef.current = result.agents;
    setAgents(result.agents);
    live.markUpdated();
  });

  usePortalRealtimeSubscription("ui.agents.invalidate", () => {
    live.invalidate();
  });

  const agentsValue = useMemo<AgentsCtx>(
    () => ({
      agents,
      isLoading: agentsLoading,
      error: agentsError,
      selectedAgentId,
      setSelectedAgentId,
      refresh: live.refreshNow
    }),
    [agents, agentsLoading, agentsError, live.refreshNow, selectedAgentId, setSelectedAgentId]
  );

  return (
    <AgentsContext.Provider value={agentsValue}>
      <RealtimeStatusNotice />
      {children}
    </AgentsContext.Provider>
  );
}

function RealtimeStatusNotice() {
  const { connection, diagnostics } = usePortalRealtime();
  const [showReconnectNotice, setShowReconnectNotice] = useState(false);

  useEffect(() => {
    const reconnecting = connection.status === "retrying" || connection.status === "connecting";
    if (!reconnecting || !diagnostics.lastFailureKind) {
      setShowReconnectNotice(false);
      return;
    }

    const timer = window.setTimeout(() => {
      setShowReconnectNotice(true);
    }, RECONNECT_NOTICE_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [connection.status, diagnostics.lastFailureKind]);

  if (connection.status === "open" && !connection.isFallbackTransport) return null;
  if (connection.status === "stopped" || connection.status === "idle") return null;
  if ((connection.status === "retrying" || connection.status === "connecting") && !diagnostics.lastFailureKind) {
    return null;
  }

  const transportLabel = connection.transport ? connection.transport.toUpperCase() : "none";
  const lastFailure = diagnostics.lastFailureKind
    ? `${diagnostics.lastFailureKind}${diagnostics.lastFailureMessage ? `: ${diagnostics.lastFailureMessage}` : ""}`
    : "realtime reconnect in progress";

  if (connection.status === "retrying" || connection.status === "connecting") {
    if (!showReconnectNotice) return null;
    return (
      <StatusBanner tone="warning">
        Realtime is reconnecting. Transport: {transportLabel}. Next retry in about {Math.round(diagnostics.lastReconnectDelayMs)} ms. Last signal: {lastFailure}.
      </StatusBanner>
    );
  }

  return (
    <StatusBanner tone="info">
      Realtime is running in degraded mode over {transportLabel}. Fallback transport or polling is active to keep the UI reconciled. Last signal: {lastFailure}.
    </StatusBanner>
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

const DETACHED_AGENTS_CATALOG: Pick<AgentsCtx, "agents" | "isLoading"> = { agents: [], isLoading: false };

// eslint-disable-next-line react-refresh/only-export-components
export function useAgentsDirectory(): Pick<AgentsCtx, "agents" | "isLoading"> {
  return useContext(AgentsContext) ?? DETACHED_AGENTS_CATALOG;
}
