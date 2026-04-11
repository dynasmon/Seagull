import type { ReactNode } from "react";
import { Link, NavLink } from "react-router-dom";

import { cx } from "@/shared/lib/cx";

export type PageHeaderTab = { label: string; to: string; end?: boolean };
export type PageHeaderBreadcrumb = string | { label: string; to?: string };

function asBreadcrumbItem(item: PageHeaderBreadcrumb): { label: string; to?: string } {
  if (typeof item === "string") return { label: item };
  return item;
}

export function PageHeader({
  title,
  breadcrumb,
  description,
  tabs,
  toolbarRight
}: {
  title: string;
  breadcrumb?: PageHeaderBreadcrumb[];
  description?: string | ReactNode;
  tabs?: PageHeaderTab[];
  toolbarRight?: ReactNode;
}) {
  const computedTabs = tabs ?? [];

  function computeEnd(t: PageHeaderTab): boolean {
    if (typeof t.end === "boolean") return t.end;

    const base = (t.to || "/").replace(/\/+$/g, "") || "/";
    const prefix = base === "/" ? "/" : `${base}/`;
    const hasChild = computedTabs.some((o) => o.to !== t.to && (o.to || "").startsWith(prefix));
    return hasChild;
  }

  return (
    <section className="ui-section-shell mb-6 overflow-hidden" aria-label={`${title} section`}>
      <div className="border-b border-border/60 bg-muted/35 px-4 py-3 sm:px-5">
        {breadcrumb && breadcrumb.length > 0 ? (
          <nav aria-label="Section breadcrumb" className="mb-1.5">
            <ol className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
              {breadcrumb.map((entry, idx) => {
                const item = asBreadcrumbItem(entry);
                const isLast = idx === (breadcrumb.length - 1);
                return (
                  <li key={`${item.label}:${idx}`} className="flex items-center gap-1.5">
                    {idx > 0 ? <span className="text-muted-foreground/70">/</span> : null}
                    {item.to && !isLast ? (
                      <Link
                        to={item.to}
                        className="rounded-sm px-1 py-0.5 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/45"
                      >
                        {item.label}
                      </Link>
                    ) : (
                      <span className={cx("px-1 py-0.5", isLast ? "text-foreground" : "")}>{item.label}</span>
                    )}
                  </li>
                );
              })}
            </ol>
          </nav>
        ) : null}

        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold tracking-tight text-foreground">{title}</h1>
            {description ? (
              <div className="mt-1 text-sm text-muted-foreground">{description}</div>
            ) : null}
          </div>

          {toolbarRight ? <div className="shrink-0">{toolbarRight}</div> : null}
        </div>
      </div>

      {tabs && tabs.length > 0 ? (
        <div className="px-3 py-2 sm:px-4">
          <div className="ui-tab-shell gap-1.5 border-b-0">
            {tabs.map((t) => (
              <NavLink
                key={t.to}
                to={t.to}
                end={computeEnd(t)}
                className={({ isActive }) =>
                  cx(
                    "ui-tab-item",
                    isActive && "ui-tab-item-active"
                  )
                }
              >
                {t.label}
              </NavLink>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}

export default PageHeader;
