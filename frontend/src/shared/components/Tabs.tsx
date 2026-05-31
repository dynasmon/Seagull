import type { ReactNode } from "react";
import { EuiNotificationBadge, EuiTab, EuiTabs } from "@elastic/eui";

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
    <EuiTabs className={className}>
      {tabs.map((t) => (
        <EuiTab
          key={t.key}
          isSelected={t.key === value}
          onClick={() => onChange(t.key)}
          prepend={t.icon ?? undefined}
          append={t.badge != null ? <EuiNotificationBadge size="s">{t.badge}</EuiNotificationBadge> : undefined}
        >
          {t.label}
        </EuiTab>
      ))}
    </EuiTabs>
  );
}
