import { EuiLoadingSpinner } from "@elastic/eui";

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
      <EuiLoadingSpinner size="m" />
      <span className="text-[12px]">{label}</span>
    </div>
  );
}
