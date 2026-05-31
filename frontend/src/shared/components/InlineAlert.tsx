import type { ReactNode } from "react";
import { EuiCallOut } from "@elastic/eui";

export type AlertTone = "info" | "success" | "warning" | "danger";

const colorByTone: Record<AlertTone, "primary" | "success" | "warning" | "danger"> = {
  info: "primary",
  success: "success",
  warning: "warning",
  danger: "danger",
};

const iconByTone: Record<AlertTone, string> = {
  info: "iInCircle",
  success: "check",
  warning: "warning",
  danger: "error",
};

export function InlineAlert({
  tone = "info",
  children,
  className,
  showIcon = true,
}: {
  tone?: AlertTone;
  children: ReactNode;
  className?: string;
  showIcon?: boolean;
}) {
  return (
    <EuiCallOut
      className={className}
      color={colorByTone[tone]}
      size="s"
      iconType={showIcon ? iconByTone[tone] : undefined}
    >
      {children}
    </EuiCallOut>
  );
}
