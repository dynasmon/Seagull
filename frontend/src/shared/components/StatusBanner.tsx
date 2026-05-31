import type { ReactNode } from "react";
import { EuiCallOut } from "@elastic/eui";

type StatusTone = "error" | "warning" | "info" | "success";

const colorByTone: Record<StatusTone, "primary" | "success" | "warning" | "danger"> = {
  error: "danger",
  warning: "warning",
  info: "primary",
  success: "success",
};

export default function StatusBanner({
  tone = "info",
  children,
  action,
  className,
}: {
  tone?: StatusTone;
  children: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <EuiCallOut className={className} color={colorByTone[tone]} size="s">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 leading-relaxed">{children}</div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
    </EuiCallOut>
  );
}
