import type { CSSProperties, ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export function Dot({ state }: { state: "online" | "offline" | "disabled" }) {
  const cls =
    state === "online"
      ? "bg-emerald-400 shadow-[0_0_10px_rgba(74,222,128,0.6)]"
      : state === "offline"
        ? "bg-amber-400"
        : "bg-slate-400";

  return <span className={cx("inline-block h-2.5 w-2.5 rounded-full", cls)} />;
}

export function Switch({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => {
        if (disabled) return;
        onChange(!checked);
      }}
      className={cx(
        "inline-flex items-center gap-2 rounded-md border border-border/60 bg-background/40 px-3 py-2",
        "text-[10px] font-mono font-bold uppercase tracking-widest",
        checked ? "text-foreground" : "text-muted-foreground",
        "hover:bg-primary/5",
        disabled && "opacity-50 cursor-not-allowed"
      )}
    >
      <span
        className={cx(
          "h-2.5 w-2.5 rounded-full",
          checked ? "bg-emerald-400" : "bg-muted-foreground/50"
        )}
      />
      <span>{label}</span>
    </button>
  );
}

export function Panel({
  title,
  right,
  children,
  scrollY,
  className,
  style,
}: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  scrollY?: boolean;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div
      className={cx(
        "border border-border/60 bg-background/70 backdrop-blur-sm flex flex-col",
        className || ""
      )}
      style={style}
    >
      <div className="flex items-center justify-between border-b border-border/60 bg-muted/10 px-4 py-3">
        <h3 className="text-[11px] font-mono font-bold uppercase tracking-[0.35em] text-primary/90">{title}</h3>
        {right ? <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">{right}</div> : null}
      </div>
      <div className={cx("p-4 flex-1 min-h-0", scrollY ? "overflow-y-auto" : "overflow-hidden")}>{children}</div>
    </div>
  );
}

export function StatTile({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "good" | "warn";
}) {
  const valueColor = tone === "good" ? "text-emerald-300" : tone === "warn" ? "text-amber-300" : "text-foreground";

  return (
    <div className="rounded-lg border border-border/60 bg-background/80 backdrop-blur-md px-4 py-3 min-w-0">
      <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{label}</div>
      <div className={cx("mt-2 text-xl font-bold font-mono tracking-tight leading-none truncate", valueColor)}>{value}</div>
      {hint ? <div className="mt-2 text-[11px] text-muted-foreground font-mono opacity-80 truncate">{hint}</div> : null}
    </div>
  );
}

export function FieldLabel({ children }: { children: ReactNode }) {
  return <div className="text-[10px] font-mono font-bold uppercase tracking-[0.32em] text-muted-foreground">{children}</div>;
}
