import { NavLink } from "react-router-dom";

function cx(...v: Array<string | false | undefined>) {
  return v.filter(Boolean).join(" ");
}

function ItemIcon({ name }: { name: "dashboard" | "events" | "alerts" | "agents" | "inventory" | "settings" }) {
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
          <path d="M7 7h14M7 12h14M7 17h14M3 7h.01M3 12h.01M3 17h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
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

function NavItem({
  collapsed,
  to,
  label,
  icon
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
          "flex items-center gap-3 rounded-md px-3 py-2 text-sm",
          isActive
            ? "bg-primary/10 text-fg"
            : "text-muted hover:bg-panel2 hover:text-fg"
        )
      }
    >
      <span className="text-primary">
        <ItemIcon name={icon} />
      </span>
      {!collapsed && <span className="truncate">{label}</span>}
    </NavLink>
  );
}

export default function Sidebar({ collapsed }: { collapsed: boolean }) {
  return (
    <aside
      className={cx(
        "border-r border-border bg-panel",
        collapsed ? "w-16" : "w-72"
      )}
    >
      <div className="px-3 py-3">
        <div className={cx("rounded-md bg-panel2 px-3 py-2", collapsed && "px-2")}>
          <div className="text-xs font-semibold uppercase tracking-wide text-muted">
            {collapsed ? "NW" : "NetWatch"}
          </div>
        </div>
      </div>

      <nav className="px-2 pb-4 space-y-4">
        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
              Security events
            </div>
          )}
          <div className="space-y-1">
            <NavItem collapsed={collapsed} to="/overview" label="Dashboard" icon="dashboard" />
            <NavItem collapsed={collapsed} to="/events" label="Events" icon="events" />
            <NavItem collapsed={collapsed} to="/alerts" label="Alerts" icon="alerts" />
          </div>
        </div>

        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
              Modules
            </div>
          )}
          <div className="space-y-1">
            <NavItem collapsed={collapsed} to="/agents" label="Agents" icon="agents" />
            <NavItem collapsed={collapsed} to="/inventory" label="Inventory" icon="inventory" />
          </div>
        </div>

        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
              Administration
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
