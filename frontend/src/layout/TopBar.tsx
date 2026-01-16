import { useLocation } from "react-router-dom";
import { useTheme } from "@/app/providers";

function titleFromPath(pathname: string) {
  if (pathname.startsWith("/overview")) return "Security events";
  if (pathname.startsWith("/agents")) return "Agents";
  if (pathname.startsWith("/events")) return "Events";
  if (pathname.startsWith("/alerts")) return "Alerts";
  if (pathname.startsWith("/inventory")) return "Inventory";
  if (pathname.startsWith("/settings")) return "Settings";
  return "NetWatch";
}

function IconMenu() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path
        d="M4 6h16M4 12h16M4 18h16"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  );
}

export default function TopBar({ onToggleNav }: { onToggleNav?: () => void }) {
  const { pathname } = useLocation();
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="border-b border-[var(--border)] bg-[var(--panel)] px-6 py-3">
      <div className="flex items-center gap-4">
        <button
          type="button"
          onClick={onToggleNav}
          disabled={!onToggleNav}
          className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-[var(--border)] bg-[var(--panel2)] text-sm disabled:opacity-50"
          aria-label="Toggle navigation"
          title="Toggle navigation"
        >
          <IconMenu />
        </button>

        <div className="min-w-[220px]">
          <div className="text-xs text-[var(--muted)]">Modules</div>
          <div className="text-sm font-semibold">{titleFromPath(pathname)}</div>
        </div>

        <div className="flex-1">
          <input
            placeholder="Search (KQL-like) - next step"
            className="w-full rounded-md border border-[var(--border)] bg-[var(--panel2)] px-3 py-2 text-sm outline-none"
          />
        </div>

        <button
          type="button"
          onClick={toggleTheme}
          className="rounded-md border border-[var(--border)] bg-[var(--panel2)] px-3 py-2 text-sm"
        >
          {theme === "dark" ? "Dark" : "Light"}
        </button>
      </div>
    </header>
  );
}
