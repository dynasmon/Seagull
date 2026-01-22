import { useEffect, useMemo, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";

import { useAgentsCatalog } from "@/app/providers";

function cx(...v: Array<string | false | undefined | null>) {
  return v.filter(Boolean).join(" ");
}

function ActiveBar({ active }: { active: boolean }) {
  if (!active) return null;
  return <span className="absolute left-0 top-1 bottom-1 w-[3px] rounded-r bg-primary" />;
}

function ItemIcon({
  name,
}: {
  name: "dashboard" | "events" | "alerts" | "agents" | "inventory" | "settings";
}) {
  const common = "h-4 w-4";
  switch (name) {
    case "dashboard":
      return (
        <svg className={common} viewBox="0 0 24 24" fill="none">
          <path d="M4 13h7V4H4v9Zm9 7h7V11h-7v9ZM4 20h7v-5H4v5Zm9-11h7V4h-7v5Z" fill="currentColor" />
        </svg>
      );
    case "events":
      return (
        <svg className={common} viewBox="0 0 24 24" fill="none">
          <path d="M4 6h16M4 12h10M4 18h16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "alerts":
      return (
        <svg className={common} viewBox="0 0 24 24" fill="none">
          <path
            d="M12 9v4m0 4h.01M10.3 4.3 3 18h18L13.7 4.3a2 2 0 0 0-3.4 0Z"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "agents":
      return (
        <svg className={common} viewBox="0 0 24 24" fill="none">
          <path
            d="M7 7h10v10H7V7Zm-3 5h3m10 0h3M12 4v3m0 10v3"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
      );
    case "inventory":
      return (
        <svg className={common} viewBox="0 0 24 24" fill="none">
          <path
            d="M7 7h14M7 12h14M7 17h14M3 7h.01M3 12h.01M3 17h.01"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
      );
    case "settings":
      return (
        <svg className={common} viewBox="0 0 24 24" fill="none">
          <path
            d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7ZM19.4 15a8 8 0 0 0 .1-6l-2 1.1a6.2 6.2 0 0 0-1.5-1.5L17.1 6a8 8 0 0 0-6-.1L12 8a6.2 6.2 0 0 0-2.1 0L9 5.9a8 8 0 0 0-6 .1l1.1 2a6.2 6.2 0 0 0-1.5 1.5L.6 9a8 8 0 0 0 .1 6l2-1.1a6.2 6.2 0 0 0 1.5 1.5L3.1 18a8 8 0 0 0 6 .1l.9-2.1a6.2 6.2 0 0 0 2.1 0l.9 2.1a8 8 0 0 0 6-.1l-1.1-2a6.2 6.2 0 0 0 1.5-1.5l2 1.1Z"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinejoin="round"
          />
        </svg>
      );
    default:
      return null;
  }
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      className={cx("h-4 w-4 transition-transform", open ? "rotate-90" : "rotate-0")}
      viewBox="0 0 24 24"
      fill="none"
    >
      <path d="M9 18l6-6-6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Dot({ state }: { state: "online" | "offline" | "disabled" }) {
  const klass =
    state === "disabled" ? "bg-muted-foreground/70" : state === "online" ? "bg-emerald-400/90" : "bg-amber-400/90";
  return <span className={cx("h-2 w-2 rounded-full", klass)} />;
}

function NavItem({
  collapsed,
  to,
  label,
  icon,
}: {
  collapsed: boolean;
  to: string;
  label: string;
  icon: Parameters<typeof ItemIcon>[0]["name"];
}) {
  return (
    <NavLink
      to={to}
      title={collapsed ? label : undefined}
      className={({ isActive }) =>
        cx(
          "relative flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
          collapsed && "justify-center px-2",
          isActive ? "bg-primary/10 text-foreground" : "text-muted-foreground hover:bg-muted/10 hover:text-foreground"
        )
      }
    >
      {({ isActive }) => (
        <>
          <ActiveBar active={isActive} />
          <span className="text-primary">
            <ItemIcon name={icon} />
          </span>
          {!collapsed && <span className="truncate">{label}</span>}
        </>
      )}
    </NavLink>
  );
}

const AGENTS_OPEN_KEY = "nw_sidebar_agents_open";

function parseIso(iso?: string | null) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return t;
}

export default function Sidebar({ collapsed }: { collapsed: boolean }) {
  const nav = useNavigate();
  const location = useLocation();
  const { agents, isLoading, error, selectedAgentId, setSelectedAgentId } = useAgentsCatalog();

  const agentsSorted = useMemo(() => {
    const copy = [...agents];
    copy.sort((a, b) => {
      const an = (a.display_name || "").trim().toLowerCase();
      const bn = (b.display_name || "").trim().toLowerCase();
      if (an && bn && an !== bn) return an.localeCompare(bn);
      if (an && !bn) return -1;
      if (!an && bn) return 1;
      return a.agent_id.localeCompare(b.agent_id);
    });
    return copy;
  }, [agents]);

  const isAgentsRoute = location.pathname.startsWith("/agents");

  const [agentsOpen, setAgentsOpen] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem(AGENTS_OPEN_KEY);
      if (saved === "1") return true;
      if (saved === "0") return false;
    } catch {
      // no-op
    }
    return isAgentsRoute || !!selectedAgentId;
  });

  useEffect(() => {
    if (isAgentsRoute) setAgentsOpen(true);
  }, [isAgentsRoute]);

  function toggleAgentsOpen() {
    const next = !agentsOpen;
    setAgentsOpen(next);
    try {
      localStorage.setItem(AGENTS_OPEN_KEY, next ? "1" : "0");
    } catch {
      // no-op
    }

    // Se o usuário abriu a árvore de Agents fora da rota /agents,
    // navegue para /agents para fazer sentido visual/funcional.
    if (next && !isAgentsRoute) {
      nav("/agents");
    }
  }

  // CORREÇÃO: selecionar agente deve levar para /agents (não apenas mudar query na rota atual)
  function selectAgent(agentId: string) {
    const safe = (agentId || "").trim();
    setSelectedAgentId(safe);
    nav(safe ? `/agents?agent_id=${encodeURIComponent(safe)}` : "/agents");
  }

  const now = Date.now();
  const onlineWindowMs = 90_000;

  return (
    <aside
      className={cx(
        "h-screen shrink-0 overflow-y-auto border-r border-border/60 bg-card/10 backdrop-blur-md",
        collapsed ? "w-16" : "w-72"
      )}
    >
      <div className="px-3 py-3">
        <div className={cx("rounded-lg border border-border/60 bg-background/40 px-3 py-2", collapsed && "px-2")}>
          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
            {collapsed ? "NW" : "NetWatch"}
          </div>
        </div>
      </div>

      <nav className="px-2 pb-4 space-y-4">
        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
              Telemetry
            </div>
          )}
          <div className="space-y-1">
            <NavItem collapsed={collapsed} to="/overview" label="Overview" icon="dashboard" />
            <NavItem collapsed={collapsed} to="/events" label="Events" icon="events" />
            <NavItem collapsed={collapsed} to="/alerts" label="Alerts" icon="alerts" />
          </div>
        </div>

        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
              Assets
            </div>
          )}

          <div className="space-y-1">
            <div className="space-y-1">
              <button
                type="button"
                onClick={toggleAgentsOpen}
                title={collapsed ? "Agents" : undefined}
                className={cx(
                  "relative flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                  collapsed && "justify-center px-2",
                  isAgentsRoute
                    ? "bg-primary/10 text-foreground"
                    : "text-muted-foreground hover:bg-muted/10 hover:text-foreground"
                )}
                aria-expanded={agentsOpen}
              >
                <ActiveBar active={isAgentsRoute} />
                <Chevron open={agentsOpen} />
                <span className="text-primary">
                  <ItemIcon name="agents" />
                </span>
                {!collapsed && <span className="truncate">Agents</span>}
              </button>

              {!collapsed && agentsOpen && (
                <div className="ml-4 border-l border-border/50 pl-2 space-y-1">
                  {isLoading ? (
                    <div className="px-3 py-2 space-y-2">
                      <div className="h-3 w-2/3 rounded bg-muted/20" />
                      <div className="h-3 w-1/2 rounded bg-muted/20" />
                      <div className="h-3 w-3/4 rounded bg-muted/20" />
                    </div>
                  ) : (
                    <div className="max-h-[260px] overflow-y-auto py-1">
                      {agentsSorted.length === 0 && (
                        <div className="px-2 py-1 text-[11px] text-muted-foreground italic">
                          No agents found
                        </div>
                      )}

                      {agentsSorted.map((a) => {
                        const last = parseIso(a.last_seen_at);
                        const state: "online" | "offline" | "disabled" = a.is_revoked
                          ? "disabled"
                          : last && now - last <= onlineWindowMs
                            ? "online"
                            : "offline";

                        const title = a.display_name ? `${a.display_name} (${a.agent_id})` : a.agent_id;
                        const active = selectedAgentId === a.agent_id;

                        return (
                          <button
                            key={a.agent_id}
                            type="button"
                            onClick={() => selectAgent(a.agent_id)}
                            className={cx(
                              "relative group flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm transition-colors",
                              active
                                ? "bg-primary/10 text-foreground"
                                : "text-muted-foreground hover:bg-muted/10 hover:text-foreground"
                            )}
                            title={title}
                          >
                            <ActiveBar active={active} />
                            <Dot state={state} />
                            <span className="min-w-0 flex-1 truncate">{a.display_name ? a.display_name : a.agent_id}</span>
                          </button>
                        );
                      })}
                    </div>
                  )}

                  {error && (
                    <div className="mt-1 rounded-md border border-border/60 bg-background/20 px-3 py-2 text-[11px] text-muted-foreground">
                      {error}
                    </div>
                  )}
                </div>
              )}
            </div>

            <NavItem collapsed={collapsed} to="/inventory" label="Inventory" icon="inventory" />
          </div>
        </div>

        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
              Admin
            </div>
          )}
          <div className="space-y-1">
            <NavItem collapsed={collapsed} to="/settings" label="Settings" icon="settings" />
          </div>
        </div>
      </nav>
    </aside>
  );
}
