import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export interface TabItem<T extends string = string> {
  key: T;
  label: ReactNode;
  badge?: ReactNode;
}

export function Tabs<T extends string>({
  value,
  onChange,
  tabs,
  className,
}: {
  value: T;
  onChange: (key: T) => void;
  tabs: Array<TabItem<T>>;
  className?: string;
}) {
  return (
    <div className={cx("ui-tab-shell", className)} role="tablist">
      {tabs.map((t) => {
        const active = t.key === value;
        return (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(t.key)}
            className={cx("ui-tab-item", active && "ui-tab-item-active")}
          >
            {t.label}
            {t.badge != null ? (
              <span
                className={cx(
                  "ml-1.5 rounded-full border px-1.5 py-0.5 text-[10px] font-mono leading-none",
                  active
                    ? "border-primary/35 bg-primary/10 text-primary"
                    : "border-border/60 bg-muted/40 text-muted-foreground",
                )}
              >
                {t.badge}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
