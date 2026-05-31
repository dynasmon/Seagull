import type { ReactNode } from "react";
import { EuiHealth } from "@elastic/eui";

import { cx } from "@/shared/lib/cx";

export type StatusVariant =
  | "active"
  | "inactive"
  | "pending"
  | "success"
  | "warning"
  | "danger"
  | "info"
  | "neutral";

const statusEuiColor: Record<StatusVariant, string> = {
  active: "success",
  inactive: "subdued",
  pending: "warning",
  success: "success",
  warning: "warning",
  danger: "danger",
  info: "primary",
  neutral: "subdued",
};

export function StatusPill({
  variant = "neutral",
  children,
  className,
}: {
  variant?: StatusVariant;
  children: ReactNode;
  className?: string;
  withDot?: boolean;
  size?: "default" | "sm";
}) {
  return (
    <EuiHealth color={statusEuiColor[variant]} className={cx("shrink-0 whitespace-nowrap", className)}>
      {children}
    </EuiHealth>
  );
}
