import type { ReactNode } from "react";
import { EuiBadge } from "@elastic/eui";

import { severityEuiColor, type SeverityLevel } from "@/shared/lib/severity";

export type BadgeVariant = SeverityLevel;

export function Badge({
  children,
  variant = "neutral",
  className,
}: {
  children: ReactNode;
  variant?: BadgeVariant;
  className?: string;
}) {
  return (
    <EuiBadge color={severityEuiColor[variant]} className={className}>
      {children}
    </EuiBadge>
  );
}
