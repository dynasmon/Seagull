import type { ReactNode } from "react";
import { EuiBadge } from "@elastic/eui";

import { severityEuiColor, type SeverityLevel } from "@/shared/lib/severity";

export type SeverityVariant = SeverityLevel;

export function SeverityPill({
  variant = "neutral",
  children,
  className,
  withDot = false,
}: {
  variant?: SeverityVariant;
  children: ReactNode;
  className?: string;
  withDot?: boolean;
  size?: "default" | "sm";
}) {
  return (
    <EuiBadge color={severityEuiColor[variant]} iconType={withDot ? "dot" : undefined} className={className}>
      {children}
    </EuiBadge>
  );
}
