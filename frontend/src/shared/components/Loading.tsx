import { cx } from "@/shared/lib/cx";

export default function Loading({
  label = "Loading...",
  className,
}: {
  label?: string;
  className?: string;
}) {
  return (
    <div className={cx("ui-loading-state", className)} role="status" aria-live="polite">
      <span
        className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-border/70 border-t-primary"
        aria-hidden="true"
      />
      <span className="text-[12px]">{label}</span>
    </div>
  );
}
