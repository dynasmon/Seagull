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
    <header className="sticky top-0 z-20 border-b border-border/70 bg-background/96 backdrop-blur-sm" role="banner">
      <div className="mx-auto flex h-[4.25rem] w-full max-w-[1800px] items-center gap-3 px-4 sm:px-6 lg:px-8">
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

        <div className="min-w-0 flex-1">
          <BreadcrumbTrail />
          <div className="mt-0.5 flex min-w-0 items-baseline gap-2">
            <h1 className="truncate text-base font-semibold tracking-tight text-foreground">{meta.title}</h1>
            <p className="hidden truncate text-xs text-muted-foreground xl:block">{meta.subtitle}</p>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {user ? (
            <div className="hidden items-center gap-2 rounded-md border border-border/70 bg-card/70 px-2.5 py-1.5 md:flex">
              <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">{user.role || "user"}</span>
              <span className="max-w-[150px] truncate text-sm text-foreground">{user.username}</span>
            </div>
          ) : null}

          <button
            type="button"
            onClick={toggleTheme}
            className="ui-btn-secondary h-9 px-3"
            aria-label="Toggle theme"
          >
            {theme === "dark" ? "Light" : "Dark"}
          </button>

          <button
            type="button"
            onClick={logout}
            className="ui-btn-secondary h-9 px-3"
            aria-label="Sign out"
          >
            Sign out
          </button>
        </div>
      </div>
    </header>
  );
}
