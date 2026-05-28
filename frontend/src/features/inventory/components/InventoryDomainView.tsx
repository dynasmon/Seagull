import { Panel } from "@/shared/components/Panel";

import { HYGIENE_TABS, DOMAIN_HINT } from "../constants";
import type { HygieneDomain } from "../types";

interface InventoryDomainViewProps {
  domain: HygieneDomain;
  scopeLabel: string;
  windowMinutes: number;
}

export function InventoryDomainView({ domain, scopeLabel, windowMinutes }: InventoryDomainViewProps) {
  const label = HYGIENE_TABS.find((x) => x.key === domain)?.label || "Dashboard";
  return (
    <Panel
      title={`${label} view`}
      actions={
        <span className="font-mono text-[10.5px] text-muted-foreground">
          {windowMinutes}m window
        </span>
      }
    >
      <div className="grid gap-3 md:grid-cols-2">
        <div className="text-[12px] leading-relaxed text-muted-foreground">{DOMAIN_HINT[domain]}</div>
        <div className="text-[12px] text-muted-foreground">
          Scope <span className="font-mono text-foreground">{scopeLabel}</span> · window{" "}
          <span className="font-mono text-foreground">{windowMinutes}m</span>
        </div>
      </div>
    </Panel>
  );
}
