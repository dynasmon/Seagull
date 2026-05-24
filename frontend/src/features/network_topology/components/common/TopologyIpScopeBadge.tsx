import { Badge } from "@/shared/components/Badge";

import { ipScopeLabel, ipScopeVariant } from "../../lib/presentation/labels";

export function TopologyIpScopeBadge({ scope, compact = false }: { scope?: string | null; compact?: boolean }) {
  const label = ipScopeLabel(scope);
  return (
    <Badge
      variant={ipScopeVariant(scope)}
      className={compact ? "px-1.5 py-0 text-[9px] tracking-[0.05em]" : undefined}
    >
      <span data-ip-scope={scope || "unknown"} data-ip-scope-label={label}>
        {label}
      </span>
    </Badge>
  );
}
