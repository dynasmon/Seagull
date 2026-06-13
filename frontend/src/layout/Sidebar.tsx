import { useMemo, type MouseEvent } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { EuiIcon, EuiSideNav, EuiThemeProvider } from "@elastic/eui";
import type { EuiSideNavItemType, IconType } from "@elastic/eui";

import { SOC_NAV_GROUPS, type AppNavIcon } from "@/layout/navigation";
import { cx } from "@/shared/lib/cx";

const ICON_BY_NAV: Record<AppNavIcon, IconType> = {
  overview: "dashboardApp",
  events: "discoverApp",
  protocol: "inputOutput",
  ssh: "console",
  ddos: "significantEvents",
  alerts: "securitySignalDetected",
  attack_chain: "timelineWithArrow",
  correlations: "graphApp",
  ueba: "anomalyChart",
  investigations: "casesApp",
  agents: "agentApp",
  inventory: "storage",
  vulnerabilities: "vulnerabilityManagementApp",
  exposure: "graphApp",
  network_topology: "cluster",
  audit: "auditbeatApp",
  settings: "gear",
  internal: "processor",
  response_center: "securitySignal",
};

function NavIcon({ icon }: { icon: AppNavIcon }) {
  return <EuiIcon type={ICON_BY_NAV[icon]} color="inherit" size="m" />;
}

function isRouteActive(pathname: string, to: string, exact?: boolean): boolean {
  if (exact) return pathname === to;
  return pathname === to || pathname.startsWith(`${to}/`);
}

function shouldNavigateClientSide(event: MouseEvent<HTMLElement>): boolean {
  return !event.defaultPrevented && event.button === 0 && !event.metaKey && !event.altKey && !event.ctrlKey && !event.shiftKey;
}

function CompactNavItem({
  label,
  to,
  icon,
  exact,
  onNavigate,
}: {
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
      title={label}
      onClick={onNavigate}
      className={({ isActive }) =>
        cx(
          "group relative mx-2 flex items-center justify-center rounded-md px-0 py-2 text-[12.5px] font-medium transition-colors",
          isActive
            ? "bg-primary/15 text-white ring-1 ring-inset ring-primary/20"
            : "text-sidebar-muted hover:bg-white/[0.06] hover:text-sidebar-foreground"
        )
      }
    >
      {({ isActive }) => (
        <>
          <span className={cx("shrink-0", isActive ? "text-primary" : "text-sidebar-muted group-hover:text-sidebar-foreground")}>
            <NavIcon icon={icon} />
          </span>
          <span className="sr-only">{label}</span>
        </>
      )}
    </NavLink>
  );
}

function CompactNav({ onNavigate }: { onNavigate: () => void }) {
  return (
    <nav className="flex-1 space-y-5 overflow-y-auto py-4" aria-label="Portal sections">
      {SOC_NAV_GROUPS.map((group) => (
        <section key={group.id}>
          <h2 className="sr-only">{group.label}</h2>
          <div className="space-y-1">
            {group.items.map((item) => (
              <CompactNavItem
                key={item.id}
                label={item.label}
                to={item.to}
                icon={item.icon}
                exact={item.exact}
                onNavigate={onNavigate}
              />
            ))}
          </div>
        </section>
      ))}
    </nav>
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
  const location = useLocation();
  const navigate = useNavigate();
  const condensed = compact && !mobileOpen;

  const sideNavItems: Array<EuiSideNavItemType<{}>> = useMemo(
    () =>
      SOC_NAV_GROUPS.map((group) => ({
        id: group.id,
        name: group.label,
        forceOpen: true,
        items: group.items.map((item) => ({
          id: item.id,
          name: item.label,
          href: item.to,
          icon: <NavIcon icon={item.icon} />,
          isSelected: isRouteActive(location.pathname, item.to, item.exact),
          onClick: (event: MouseEvent<HTMLElement>) => {
            if (shouldNavigateClientSide(event)) {
              event.preventDefault();
              navigate(item.to);
            }
            onCloseMobile();
          },
        })),
      })),
    [location.pathname, navigate, onCloseMobile]
  );

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

      <EuiThemeProvider colorMode="dark" wrapperProps={{ cloneElement: true }}>
        <aside
          id="primary-navigation"
          className={cx(
            "fixed inset-y-0 left-0 z-40 flex h-screen flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground shadow-pop transition-transform lg:sticky lg:top-0 lg:z-auto lg:translate-x-0 lg:shadow-none",
            compact ? "w-[13rem] lg:w-[4.5rem]" : "w-[13rem] lg:w-[13.5rem]",
            mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
          )}
          aria-label="Primary navigation"
        >
          <div className={cx("flex h-14 shrink-0 items-center border-b border-sidebar-border px-4", condensed && "justify-center px-2")}>
            <div className="flex items-center gap-2.5">
              <img
                src="/icon/seagull-icon.png"
                alt="Seagull"
                className="h-8 w-8 shrink-0 rounded-lg object-cover shadow-[0_6px_18px_rgb(14_165_233/0.30)] ring-1 ring-white/10"
              />
              {!condensed ? (
                <div className="min-w-0">
                  <div className="truncate text-[13px] font-semibold text-sidebar-foreground">Seagull</div>
                  <div className="truncate text-[9px] uppercase tracking-[0.12em] text-sidebar-muted">Security Operations</div>
                </div>
              ) : null}
            </div>
          </div>

          {condensed ? (
            <CompactNav onNavigate={onCloseMobile} />
          ) : (
            <div className="min-h-0 flex-1 overflow-y-auto px-2 py-4">
              <EuiSideNav
                className="seagullSideNav"
                items={sideNavItems}
                heading="Portal sections"
                headingProps={{ screenReaderOnly: true }}
                mobileBreakpoints={undefined}
                truncate
                aria-label="Portal sections"
              />
            </div>
          )}
        </aside>
      </EuiThemeProvider>
    </>
  );
}
