import { NavLink } from "react-router-dom";

import { SOC_NAV_GROUPS, type AppNavIcon } from "@/layout/navigation";
import { cx } from "@/shared/lib/cx";

function NavIcon({ icon }: { icon: AppNavIcon }) {
  const base = "h-4 w-4";
  switch (icon) {
    case "overview":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M4 13h7V4H4v9Zm9 7h7V11h-7v9ZM4 20h7v-5H4v5Zm9-11h7V4h-7v5Z" fill="currentColor" />
        </svg>
      );
    case "events":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M4 6h16M4 12h16M4 18h10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "protocol":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 3v18M4 8h16M4 16h16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "ssh":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M7.5 11.5 11 8l-3.5-3.5M11 16h5.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          <rect x="3" y="4" width="18" height="16" rx="2" stroke="currentColor" strokeWidth="2" />
        </svg>
      );
    case "ddos":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M3 12h6l2-4 3 8 2-4h5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "alerts":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 9v4m0 4h.01M10.3 4.3 3 18h18L13.7 4.3a2 2 0 0 0-3.4 0Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "attack_chain":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M10.5 13.5 9 15a4 4 0 0 1-5.7 0 4 4 0 0 1 0-5.7l1.5-1.5M13.5 10.5 15 9a4 4 0 0 1 5.7 0 4 4 0 0 1 0 5.7l-1.5 1.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          <path d="M8.5 15.5 15.5 8.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "correlations":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M7 7a3 3 0 1 0 0 .01V7Zm10 10a3 3 0 1 0 0 .01V17ZM9.1 8.9l5.8 5.8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "investigations":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M4 5h16v10H4z" stroke="currentColor" strokeWidth="2" />
          <path d="M8 19h8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "agents":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M7 7h10v10H7V7Zm-3 5h3m10 0h3M12 4v3m0 10v3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "inventory":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M7 7h14M7 12h14M7 17h14M3 7h.01M3 12h.01M3 17h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "vulnerabilities":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 2 20 6v6c0 5-3.3 9.6-8 10-4.7-.4-8-5-8-10V6l8-4Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
          <path d="M9.5 12.5 11 14l3.5-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "audit":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 3 19 7v5c0 4.6-2.9 8.7-7 9.8C7.9 20.7 5 16.6 5 12V7l7-4Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
          <path d="M9.5 12.5 11 14l3.5-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "settings":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7ZM19.4 15a8 8 0 0 0 .1-6l-2 1.1a6.2 6.2 0 0 0-1.5-1.5L17.1 6a8 8 0 0 0-6-.1L12 8a6.2 6.2 0 0 0-2.1 0L9 5.9a8 8 0 0 0-6 .1l1.1 2a6.2 6.2 0 0 0-1.5 1.5L.6 9a8 8 0 0 0 .1 6l2-1.1a6.2 6.2 0 0 0 1.5 1.5L3.1 18a8 8 0 0 0 6 .1l.9-2.1a6.2 6.2 0 0 0 2.1 0l.9 2.1a8 8 0 0 0 6-.1l-1.1-2a6.2 6.2 0 0 0 1.5-1.5l2 1.1Z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
        </svg>
      );
    case "internal":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M6 6h12v12H6V6Zm-2 6h2m12 0h2M12 4v2m0 12v2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          <path d="M9 9h6v6H9V9Z" fill="currentColor" fillOpacity="0.25" />
        </svg>
      );
    default:
      return null;
  }
}

function NavGroupHeading({ compact, label }: { compact: boolean; label: string }) {
  return (
    <h2
      className={cx(
        "px-3 pb-1 text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground",
        compact && "sr-only"
      )}
    >
      {label}
    </h2>
  );
}

function NavItem({
  compact,
  label,
  to,
  icon,
  exact,
  onNavigate,
}: {
  compact: boolean;
  label: string;
  to: string;
  icon: AppNavIcon;
  exact?: boolean;
  onNavigate?: () => void;
}) {
  return (
    <NavLink
      to={to}
      end={exact}
      title={compact ? label : undefined}
      onClick={onNavigate}
      className={({ isActive }) =>
        cx(
          "group relative flex items-center gap-3 rounded-lg px-3 py-2 text-[13px] transition-colors",
          compact && "justify-center px-2",
          isActive
            ? "bg-primary/10 text-foreground shadow-[inset_0_0_0_1px_rgb(var(--primary)/0.28)]"
            : "text-muted-foreground hover:bg-muted/65 hover:text-foreground"
        )
      }
    >
      {({ isActive }) => (
        <>
          <span
            className={cx(
              "absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-r-sm transition-opacity",
              isActive ? "bg-primary opacity-100" : "bg-primary opacity-0"
            )}
          />
          <span className={cx("shrink-0", isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground")}>
            <NavIcon icon={icon} />
          </span>
          {!compact ? <span className="truncate">{label}</span> : <span className="sr-only">{label}</span>}
        </>
      )}
    </NavLink>
  );
}

export default function Sidebar({
  compact,
  mobileOpen,
  onCloseMobile,
}: {
  compact: boolean;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}) {
  const condensed = compact && !mobileOpen;

  return (
    <>
      <div
        className={cx(
          "fixed inset-0 z-30 bg-slate-950/45 backdrop-blur-[1px] transition-opacity lg:hidden",
          mobileOpen ? "opacity-100" : "pointer-events-none opacity-0"
        )}
        aria-hidden="true"
        onClick={onCloseMobile}
      />

      <aside
        className={cx(
          "fixed inset-y-0 left-0 z-40 flex h-screen flex-col border-r border-border/70 bg-card/95 shadow-xl backdrop-blur-sm transition-transform lg:static lg:z-auto lg:translate-x-0 lg:shadow-none",
          compact ? "w-[16.5rem] lg:w-[4.75rem]" : "w-[16.5rem] lg:w-[16.5rem]",
          mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        )}
        aria-label="Primary navigation"
      >
        <div className={cx("border-b border-border/60 px-3 py-3", condensed && "px-2 py-2")}>
          <div className="flex items-center gap-2">
            <div className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M4 13h7V4H4v9Zm9 7h7V11h-7v9ZM4 20h7v-5H4v5Zm9-11h7V4h-7v5Z" fill="currentColor" />
              </svg>
            </div>
            {!condensed ? (
              <div className="min-w-0">
                <div className="truncate text-sm font-semibold text-foreground">NetWatch</div>
                <div className="truncate text-[11px] text-muted-foreground">Security Operations</div>
              </div>
            ) : null}
          </div>
        </div>

        <nav className="flex-1 space-y-5 overflow-y-auto px-2 py-3" aria-label="Portal sections">
          {SOC_NAV_GROUPS.map((group) => (
            <section key={group.id}>
              <NavGroupHeading compact={condensed} label={group.label} />
              <div className="space-y-1">
                {group.items.map((item) => (
                  <NavItem
                    key={item.id}
                    compact={condensed}
                    label={item.label}
                    to={item.to}
                    icon={item.icon}
                    exact={item.exact}
                    onNavigate={onCloseMobile}
                  />
                ))}
              </div>
            </section>
          ))}
        </nav>
      </aside>
    </>
  );
}
