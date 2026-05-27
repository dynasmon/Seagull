import { Link, useLocation } from "react-router-dom";

import { resolveRouteMeta } from "@/layout/navigation";
import { useTheme } from "@/app/providers";
import { useAuth } from "@/features/auth/context";
import { cx } from "@/shared/lib/cx";

function IconMenu() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M4 6h16M4 12h16M4 18h16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

function IconPanelLeft() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="3" y="4" width="18" height="16" rx="2" stroke="currentColor" strokeWidth="2" />
      <path d="M9 4v16" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}

function IconTile() {
  return (
    <div className="hidden h-8 w-8 items-center justify-center rounded-md bg-primary/10 text-primary ring-1 ring-primary/15 sm:flex">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M4 13h7V4H4v9Zm9 7h7V11h-7v9ZM4 20h7v-5H4v5Zm9-11h7V4h-7v5Z" fill="currentColor" />
      </svg>
    </div>
  );
}

function IconSearch() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="2" />
      <path d="m20 20-3.2-3.2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

function IconSun() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="4" stroke="currentColor" strokeWidth="2" />
      <path d="M12 2v2m0 16v2M2 12h2m16 0h2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

function IconMoon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
    </svg>
  );
}

function IconLogout() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path d="M10 8 6 12l4 4M6 12h11" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function BreadcrumbTrail() {
  const location = useLocation();
  const meta = resolveRouteMeta(location.pathname);
  const crumbs = meta.breadcrumbs;

  return (
    <nav aria-label="Breadcrumb" className="min-w-0">
      <ol className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
        {crumbs.map((crumb, idx) => {
          const isLast = idx === (crumbs.length - 1);
          return (
            <li key={`${crumb.label}:${idx}`} className="flex min-w-0 items-center gap-1.5">
              {idx > 0 ? <span className="text-muted-foreground/70">/</span> : null}
              {crumb.to && !isLast ? (
                <Link
                  to={crumb.to}
                  className="truncate rounded-sm px-1 py-0.5 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/45"
                >
                  {crumb.label}
                </Link>
              ) : (
                <span className={cx("truncate px-1 py-0.5", isLast ? "text-foreground" : "")}>{crumb.label}</span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

export default function TopBar({
  onToggleNavigation,
  onToggleCompact,
  compact,
  navigationOpen,
}: {
  onToggleNavigation: () => void;
  onToggleCompact: () => void;
  compact: boolean;
  navigationOpen?: boolean;
}) {
  const { theme, toggleTheme } = useTheme();
  const { user, logout } = useAuth();
  const location = useLocation();
  const meta = resolveRouteMeta(location.pathname);

  return (
    <header className="sticky top-0 z-20 border-b border-border bg-surface-1/85 backdrop-blur-md" role="banner">
      <div className="mx-auto flex h-14 w-full max-w-[1800px] items-center gap-3 px-4 sm:px-5 lg:px-6">
        <button
          type="button"
          onClick={onToggleNavigation}
          className="ui-btn-secondary inline-flex h-9 w-9 items-center justify-center px-0 lg:hidden"
          aria-label={navigationOpen ? "Close navigation" : "Open navigation"}
          aria-controls="primary-navigation"
          aria-expanded={navigationOpen}
          title={navigationOpen ? "Close navigation" : "Open navigation"}
        >
          <IconMenu />
        </button>

        <button
          type="button"
          onClick={onToggleCompact}
          className="ui-btn-secondary hidden h-9 w-9 items-center justify-center px-0 lg:inline-flex"
          aria-label={compact ? "Expand sidebar" : "Collapse sidebar"}
          title={compact ? "Expand sidebar" : "Collapse sidebar"}
        >
          <IconPanelLeft />
        </button>

        <IconTile />

        <div className="min-w-0 flex-1">
          <BreadcrumbTrail />
          <div className="mt-0.5 flex min-w-0 items-baseline gap-2">
            <h1 className="truncate text-[13px] font-semibold tracking-tight text-foreground">{meta.title}</h1>
            <p className="hidden truncate text-[11px] text-muted-foreground 2xl:block">{meta.subtitle}</p>
          </div>
        </div>

        <div className="relative hidden xl:block">
          <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
            <IconSearch />
          </span>
          <input
            type="search"
            aria-label="Search"
            placeholder="Search agents, alerts, hosts…"
            className="h-9 w-60 rounded-md border border-border bg-surface-2 pl-9 pr-3 text-[12px] text-foreground placeholder:text-muted-foreground/70 transition-colors focus:border-primary focus:bg-card focus:outline-none focus:ring-2 focus:ring-primary/20"
          />
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {user ? (
            <div className="hidden items-center gap-2 rounded-md border border-border bg-surface-2 py-1 pl-1 pr-2.5 md:flex">
              <span className="flex h-7 w-7 items-center justify-center rounded bg-primary/10 text-[11px] font-semibold uppercase text-primary">
                {(user.username || "?").slice(0, 1)}
              </span>
              <span className="flex min-w-0 flex-col leading-tight">
                <span className="max-w-[140px] truncate text-[11px] font-semibold text-foreground">{user.username}</span>
                <span className="text-[9px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">{user.role || "user"}</span>
              </span>
            </div>
          ) : null}

          <button
            type="button"
            onClick={toggleTheme}
            className="ui-btn-secondary inline-flex h-9 w-9 items-center justify-center px-0"
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            {theme === "dark" ? <IconSun /> : <IconMoon />}
          </button>

          <button
            type="button"
            onClick={logout}
            className="ui-btn-secondary inline-flex h-9 items-center gap-1.5 px-2.5"
            aria-label="Sign out"
            title="Sign out"
          >
            <IconLogout />
            <span className="hidden sm:inline">Sign out</span>
          </button>
        </div>
      </div>
    </header>
  );
}
