import { NavLink } from "react-router-dom";
import { useMemo, useState } from "react";

type NavItem = { label: string; to: string };
type NavGroup = { label: string; items: NavItem[] };

function cx(...v: Array<string | false | undefined>) {
  return v.filter(Boolean).join(" ");
}

export default function Sidebar() {
  const groups = useMemo<NavGroup[]>(
    () => [
      {
        label: "Home",
        items: [{ label: "Overview", to: "/overview" }]
      },
      {
        label: "Hunting",
        items: [
          { label: "Agents", to: "/agents" },
          { label: "Events", to: "/events" },
          { label: "Alerts", to: "/alerts" }
        ]
      },
      {
        label: "Endpoint",
        items: [{ label: "Inventory", to: "/inventory" }]
      },
      {
        label: "Admin",
        items: [{ label: "Settings", to: "/settings" }]
      }
    ],
    []
  );

  const [open, setOpen] = useState<Record<string, boolean>>({
    Home: true,
    Hunting: true,
    Endpoint: true,
    Admin: false
  });

  return (
    <aside className="w-72 border-r border-white/10 bg-black/20">
      <div className="px-4 py-4">
        <div className="text-sm font-semibold">Dynasmon NetWatch</div>
        <div className="text-xs text-white/60">Portal</div>
      </div>

      <nav className="px-2 pb-4">
        {groups.map((g) => {
          const isOpen = !!open[g.label];
          return (
            <div key={g.label} className="mb-2">
              <button
                type="button"
                onClick={() => setOpen((p) => ({ ...p, [g.label]: !p[g.label] }))}
                className="flex w-full items-center justify-between rounded-md px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-white/60 hover:bg-white/5"
              >
                <span>{g.label}</span>
                <span className="text-white/40">{isOpen ? "—" : "+"}</span>
              </button>

              {isOpen && (
                <div className="mt-1 space-y-1">
                  {g.items.map((it) => (
                    <NavLink
                      key={it.to}
                      to={it.to}
                      className={({ isActive }) =>
                        cx(
                          "block rounded-md px-3 py-2 text-sm",
                          isActive
                            ? "bg-white/10 text-white"
                            : "text-white/70 hover:bg-white/5 hover:text-white"
                        )
                      }
                    >
                      {it.label}
                    </NavLink>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </nav>
    </aside>
  );
}
