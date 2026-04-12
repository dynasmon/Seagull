import { cx } from "@/shared/lib/cx";

export type InternalStatTone = "default" | "good" | "warn";

export default function InternalStatTile({
  label,
  value,
  tone = "default",
  className,
}: {
  label: string;
  value: string | number;
  tone?: InternalStatTone;
  className?: string;
}) {
  return (
    <div className={cx("rounded-md border border-border/60 bg-background/60 px-4 py-3", className)}>
      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
      <div
        className={cx(
          "mt-2 text-2xl font-bold font-mono",
          tone === "good" && "text-emerald-400",
          tone === "warn" && "text-amber-400"
        )}
      >
        {value}
      </div>
    </div>
  );
}

