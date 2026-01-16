import { NavLink } from "react-router-dom";

type Tab = { label: string; to: string };

function cx(...v: Array<string | false | undefined>) {
  return v.filter(Boolean).join(" ");
}

export default function PageHeader({
  title,
  breadcrumb,
  tabs,
  toolbarRight
}: {
  title: string;
  breadcrumb?: string[];
  tabs?: Tab[];
  toolbarRight?: React.ReactNode;
}) {
  return (
    <div className="mb-6">
      {breadcrumb && breadcrumb.length > 0 && (
        <div className="text-xs text-muted">{breadcrumb.join(" / ")}</div>
      )}

      <div className="mt-1 flex items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">{title}</h1>
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
