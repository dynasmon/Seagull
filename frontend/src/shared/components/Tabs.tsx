import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export interface TabItem<T extends string = string> {
  key: T;
  label: ReactNode;
  badge?: ReactNode;
  icon?: ReactNode;
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
            {t.icon ? <span className="-ml-0.5 shrink-0">{t.icon}</span> : null}
            {t.label}
            {t.badge != null ? (
              <span
                className={cx(
                  "ml-1 inline-flex h-4 min-w-[1rem] items-center justify-center rounded-full px-1.5 text-[10px] font-semibold leading-none",
                  active
                    ? "bg-primary/12 text-primary"
                    : "bg-muted/60 text-muted-foreground",
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
