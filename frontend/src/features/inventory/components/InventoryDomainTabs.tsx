import { Tabs } from "@/shared/components/Tabs";

import { HYGIENE_TABS } from "../constants";
import type { HygieneDomain } from "../types";

interface InventoryDomainTabsProps {
  domain: HygieneDomain;
  onChange: (domain: HygieneDomain) => void;
}

export function InventoryDomainTabs({ domain, onChange }: InventoryDomainTabsProps) {
  return (
    <Tabs
      value={domain}
      onChange={(next) => onChange(next as HygieneDomain)}
      tabs={HYGIENE_TABS.map((tab) => ({ key: tab.key, label: tab.label }))}
    />
  );
}
