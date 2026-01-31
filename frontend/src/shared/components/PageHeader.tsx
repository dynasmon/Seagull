import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

export type PageHeaderTab = { label: string; to: string };

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
  return (
    <div className="mb-6">
      {breadcrumb && breadcrumb.length > 0 && (
        <div className="text-xs text-muted">{breadcrumb.join(" / ")}</div>
      )}

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
        <div className="mt-3 border-b border-border">
          <div className="flex gap-6">
            {tabs.map((t) => (
              <NavLink
                key={t.to}
                to={t.to}
                className={({ isActive }) =>
                  cx(
                    "pb-3 text-sm",
                    isActive
                      ? "border-b-2 border-primary text-fg"
                      : "text-muted hover:text-fg"
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
