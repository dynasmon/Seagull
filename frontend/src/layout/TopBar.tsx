import { useTheme } from "@/app/providers";
import { useAuth } from "@/features/auth/context";

export default function TopBar({ onToggleNav }: { onToggleNav?: () => void }) {
  const { theme, toggleTheme } = useTheme();
  const { user, logout } = useAuth();

  return (
    <header className="border-b border-border/60 bg-card/10 backdrop-blur-md px-6 py-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onToggleNav}
            className="inline-flex h-9 items-center justify-center border border-border/60 bg-background/40 px-3 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60"
            aria-label="Toggle navigation"
          >
            Menu
          </button>

          <div className="leading-tight">
            <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">
              NetWatch
            </div>
            <div className="text-sm font-semibold">Security Operations</div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {user && (
            <div className="hidden md:flex items-center gap-2 border border-border/60 bg-background/40 px-3 h-9">
              <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{user.role || "user"}</span>
              <span className="text-xs font-mono text-foreground/90">{user.username}</span>
            </div>
          )}

          <button
            type="button"
            onClick={logout}
            className="inline-flex h-9 items-center justify-center border border-border/60 bg-background/40 px-3 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60"
            aria-label="Logout"
          >
            Logout
          </button>

          <button
            type="button"
            onClick={toggleTheme}
            className="inline-flex h-9 items-center justify-center border border-border/60 bg-background/40 px-3 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60"
            aria-label="Toggle theme"
          >
            {theme === "dark" ? "Light" : "Dark"}
          </button>
        </div>
      </div>
    </header>
  );
}
