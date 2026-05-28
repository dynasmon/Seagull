import { cx } from "@/shared/lib/cx";

type HeaderBadgeTone = "neutral" | "warning" | "danger" | "success";

const toneClass: Record<HeaderBadgeTone, string> = {
  neutral: "border-border bg-surface-2 text-muted-foreground",
  warning: "border-warning/40 bg-warning/10 text-warning",
  danger: "border-danger/40 bg-danger/10 text-danger",
  success: "border-success/40 bg-success/10 text-success",
};

export function HeaderBadge({ text, tone = "neutral" }: { text: string; tone?: HeaderBadgeTone }) {
  return (
    <span
      className={cx(
        "inline-flex h-6 items-center rounded-md border px-2 text-[10.5px] font-semibold uppercase tracking-[0.08em]",
        toneClass[tone],
      )}
    >
      {text}
    </span>
  );
}
