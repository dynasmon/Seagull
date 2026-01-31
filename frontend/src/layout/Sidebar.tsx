// src/layout/Sidebar.tsx
import { useMemo, useState } from "react";
import type { To } from "react-router-dom";
import { NavLink, useLocation, useNavigate } from "react-router-dom";

import { cx } from "@/shared/lib/cx";
import { useAgentsCatalog } from "@/app/providers";

function ActiveBar({ active }: { active: boolean }) {
  if (!active) return null;
  return <span className="absolute left-0 top-1 bottom-1 w-[3px] rounded-r bg-primary" />;
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      className={cx("h-4 w-4 text-muted-foreground transition-transform", open ? "rotate-90" : "rotate-0")}
      viewBox="0 0 24 24"
      fill="none"
    >
      <path d="M9 18l6-6-6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ItemIcon({
  name
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

function Dot({ state }: { state: "online" | "offline" | "disabled" }) {
  const klass =
    state === "disabled"
      ? "bg-muted-foreground/60"
      : state === "online"
        ? "bg-emerald-400/90"
        : "bg-amber-400/90";
  return <span className={cx("h-2 w-2 rounded-full", klass)} />;
}

function parseIso(iso?: string | null) {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return t;
}

function fmtLastSeen(lastSeenAt?: string | null) {
  const t = parseIso(lastSeenAt);
  if (!t) return "never";
  const delta = Date.now() - t;
  if (delta < 15_000) return "just now";
  const sec = Math.floor(delta / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function NavItem({
  collapsed,
  to,
  label,
  icon
}: {
  collapsed: boolean;
  to: To;
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

export default function Sidebar({ collapsed }: { collapsed: boolean }) {
  const nav = useNavigate();
  const location = useLocation();
  const { agents, isLoading, error, selectedAgentId, setSelectedAgentId } = useAgentsCatalog();

  const [agentsOpen, setAgentsOpen] = useState(true);

  // Prefer URL agent_id, fallback to selectedAgentId from catalog
  const urlAgentId = useMemo(() => {
    const sp = new URLSearchParams(location.search);
    return (sp.get("agent_id") || "").trim();
  }, [location.search]);

  const effectiveAgentId = (urlAgentId || selectedAgentId || "").trim();

  function toWithAgentId(pathname: string): To {
    if (!effectiveAgentId) return { pathname, search: "" };
    return { pathname, search: `?agent_id=${encodeURIComponent(effectiveAgentId)}` };
  }

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

  const now = Date.now();
  const onlineWindowMs = 90_000;

  function selectAgent(agentId: string) {
    const safe = (agentId || "").trim();
    setSelectedAgentId(safe);

    // Redirect to Agents page immediately (your requested flow)
    nav(
      safe
        ? { pathname: "/agents", search: `?agent_id=${encodeURIComponent(safe)}` }
        : { pathname: "/agents", search: "" },
      { replace: true }
    );
  }

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
        {/* TELEMETRY */}
        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
              Telemetry
            </div>
          )}
          <div className="space-y-1">
            <NavItem collapsed={collapsed} to={toWithAgentId("/overview")} label="Overview" icon="dashboard" />
            {/* Events is ALWAYS independent: default scope is "All agents" */}
            <NavItem collapsed={collapsed} to="/events" label="Events" icon="events" />
            <NavItem collapsed={collapsed} to="/alerts/queue" label="Alerts" icon="alerts" />
          </div>
        </div>

        {/* ASSETS */}
        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
              Assets
            </div>
          )}

          <div className="space-y-2">
            {/* VSCode-like: click "Agents" to expand */}
            <button
              type="button"
              title={collapsed ? "Agents" : undefined}
              onClick={() => setAgentsOpen((v) => !v)}
              className={cx(
                "w-full relative flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                collapsed ? "justify-center px-2" : "justify-between",
                "text-muted-foreground hover:bg-muted/10 hover:text-foreground"
              )}
            >
              <div className={cx("flex items-center gap-3 min-w-0", collapsed && "justify-center")}>
                <span className="text-primary">
                  <ItemIcon name="agents" />
                </span>

                {!collapsed && (
                  <div className="min-w-0 flex items-center gap-2">
                    <span className="truncate">Agents</span>
                  </div>
                )}
              </div>

              {!collapsed && <Chevron open={agentsOpen} />}
            </button>

            {!collapsed && agentsOpen && (
              <div className="rounded-md border border-border/60 bg-background/20">
                <div className="max-h-[340px] overflow-y-auto py-1">
                  {isLoading ? (
                    <div className="px-3 py-2 space-y-2">
                      <div className="h-3 w-2/3 rounded bg-muted/20" />
                      <div className="h-3 w-1/2 rounded bg-muted/20" />
                      <div className="h-3 w-3/4 rounded bg-muted/20" />
                    </div>
                  ) : agentsSorted.length === 0 ? (
                    <div className="px-3 py-2 text-[11px] text-muted-foreground italic">No agents found</div>
                  ) : (
                    agentsSorted.map((a) => {
                      const last = parseIso(a.last_seen_at);
                      const state: "online" | "offline" | "disabled" = a.is_revoked
                        ? "disabled"
                        : last && now - last <= onlineWindowMs
                          ? "online"
                          : "offline";

                      const active = effectiveAgentId === a.agent_id;

                      return (
                        <button
                          key={a.agent_id}
                          type="button"
                          onClick={() => selectAgent(a.agent_id)}
                          className={cx(
                            "relative group flex w-full items-start gap-2 rounded-md px-3 py-2 text-left transition-colors",
                            active
                              ? "bg-primary/10 text-foreground"
                              : "text-muted-foreground hover:bg-muted/10 hover:text-foreground"
                          )}
                          title={a.display_name ? `${a.display_name} (${a.agent_id})` : a.agent_id}
                        >
                          <ActiveBar active={active} />
                          <div className="mt-[6px]">
                            <Dot state={state} />
                          </div>

                          <div className="min-w-0 flex-1">
                            <div className="flex items-center justify-between gap-2">
                              <div className="truncate text-sm font-medium">
                                {a.display_name?.trim() ? a.display_name : a.agent_id}
                              </div>
                              <div className="shrink-0 text-[10px] font-mono text-muted-foreground/80">
                                {fmtLastSeen(a.last_seen_at)}
                              </div>
                            </div>
                            <div className="truncate text-[10px] font-mono text-muted-foreground/80">{a.agent_id}</div>
                          </div>
                        </button>
                      );
                    })
                  )}

                  {error && (
                    <div className="m-2 rounded-md border border-border/60 bg-background/20 px-3 py-2 text-[11px] text-muted-foreground">
                      {error}
                    </div>
                  )}
                </div>
              </div>
            )}

            <NavItem collapsed={collapsed} to={toWithAgentId("/inventory")} label="Inventory" icon="inventory" />
          </div>
        </div>

        {/* ADMIN */}
        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
              Admin
            </div>
          )}
          <div className="space-y-1">
            <NavItem collapsed={collapsed} to={toWithAgentId("/settings")} label="Settings" icon="settings" />
          </div>
        </div>
      </nav>
    </aside>
  );
}
