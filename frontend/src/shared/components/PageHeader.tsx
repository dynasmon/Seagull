import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

export type PageHeaderTab = { label: string; to: string; end?: boolean };

function cx(...v: Array<string | false | undefined>) {
  return v.filter(Boolean).join(" ");
}

export function PageHeader({
  title,
  breadcrumb,
  description,
  tabs,
  toolbarRight
}: {
  title: string;
  breadcrumb?: string[];
  description?: string | ReactNode;
  tabs?: PageHeaderTab[];
  toolbarRight?: ReactNode;
}) {
  const computedTabs = tabs ?? [];

  function computeEnd(t: PageHeaderTab): boolean {
    if (typeof t.end === "boolean") return t.end;

    // If another tab is nested under this route (prefix match), treat this tab as "exact"
    // so it does not stay active when you navigate to a child tab.
    const base = (t.to || "/").replace(/\/+$/g, "") || "/";
    const prefix = base === "/" ? "/" : `${base}/`;
    const hasChild = computedTabs.some((o) => o.to !== t.to && (o.to || "").startsWith(prefix));
    return hasChild;
  }

  return (
    <div className="mb-6">
      {breadcrumb && breadcrumb.length > 0 ? (
        <div className="text-xs text-muted-foreground">{breadcrumb.join(" / ")}</div>
      ) : null}

      <div className="mt-1 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold">{title}</h1>
          {description ? (
            <div className="mt-1 text-sm text-muted">{description}</div>
          ) : null}
        </div>

        {toolbarRight}
      </div>

      {tabs && tabs.length > 0 && (
        <div className="mt-4 border-b border-border/60">
          <div className="flex gap-6">
            {tabs.map((t) => (
              <NavLink
                key={t.to}
                to={t.to}
                end={computeEnd(t)}
                className={({ isActive }) =>
                  cx(
                    "pb-3 text-sm transition-colors",
                    isActive
                      ? "border-b-2 border-primary text-foreground"
                      : "text-muted-foreground hover:text-foreground"
                  )
                }
              >
                {t.label}
              </NavLink>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default PageHeader;
