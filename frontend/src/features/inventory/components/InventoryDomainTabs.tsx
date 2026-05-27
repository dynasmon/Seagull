import { cx } from "@/shared/lib/cx";

import { HYGIENE_TABS } from "../constants";
import type { HygieneDomain } from "../types";

interface InventoryDomainTabsProps {
  domain: HygieneDomain;
  onChange: (domain: HygieneDomain) => void;
}

export function InventoryDomainTabs({ domain, onChange }: InventoryDomainTabsProps) {
  return (
    <div className="ui-tab-shell px-1 pb-2">
      {HYGIENE_TABS.map((tab) => {
        const active = domain === tab.key;
        return (
          <button
            key={tab.key}
            type="button"
            onClick={() => onChange(tab.key)}
            className={cx("ui-tab-item", active && "ui-tab-item-active")}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}
