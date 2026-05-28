import type { ReactNode } from "react";
import { useState } from "react";

import { Badge } from "@/shared/components/Badge";
import type { BadgeVariant } from "@/shared/components/Badge";
import EmptyState from "@/shared/components/EmptyState";
import { JsonBlock } from "@/shared/components/JsonBlock";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";
import { copyTextToClipboard } from "./utils";

export function InvestigationShell({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={cx("space-y-5", className)}>{children}</div>;
}

export function InvestigationMetaStrip({
  items,
}: {
  items: Array<{ label: string; value: ReactNode; variant?: BadgeVariant }>;
}) {
  const rows = items.filter(
    (x) => x && x.value !== undefined && x.value !== null && String(x.value).trim() !== "",
  );
  if (rows.length === 0) return null;

  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
      {rows.map((item) => (
        <div
          key={`${item.label}-${String(item.value)}`}
          className="ui-card-shell px-3 py-2"
        >
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            {item.label}
          </div>
          {item.variant ? (
            <div className="mt-1.5">
              <Badge variant={item.variant}>{item.value}</Badge>
            </div>
          ) : (
            <div className="mt-1 break-words font-mono text-[12px] text-foreground">{item.value}</div>
          )}
        </div>
      ))}
    </div>
  );
}

export function InvestigationActionBar({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-surface-2/60 p-2">
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  );
}

export function InvestigationActionButton({
  children,
  onClick,
  title,
  disabled,
  tone = "default",
}: {
  children: ReactNode;
  onClick?: () => void;
  title?: string;
  disabled?: boolean;
  tone?: "default" | "primary";
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      disabled={disabled}
      className={cx(
        "inline-flex h-8 items-center gap-2 rounded-md border px-3 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/35",
        tone === "primary"
          ? "border-primary/50 bg-primary/15 text-primary hover:bg-primary/20"
          : "border-border bg-card text-foreground hover:border-primary/35 hover:bg-muted",
        disabled && "opacity-60 cursor-not-allowed",
      )}
    >
      {children}
    </button>
  );
}

export function InvestigationTabs<T extends string>({
  value,
  onChange,
  tabs,
}: {
  value: T;
  onChange: (next: T) => void;
  tabs: Array<{ key: T; label: string }>;
}) {
  return (
    <div className="ui-tab-shell">
      {tabs.map((t) => {
        const active = t.key === value;
        return (
          <button
            key={t.key}
            type="button"
            onClick={() => onChange(t.key)}
            className={cx("ui-tab-item", active && "ui-tab-item-active")}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

export function InvestigationSection({
  title,
  subtitle,
  right,
  children,
  className,
  bodyClassName,
}: {
  title: string;
  subtitle?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cx("ui-card-shell", className)}>
      <header className="ui-panel-header">
        <div className="min-w-0">
          <div className="ui-panel-eyebrow truncate">{title}</div>
          {subtitle ? <div className="ui-panel-subtitle">{subtitle}</div> : null}
        </div>
        {right ? <div className="shrink-0">{right}</div> : null}
      </header>
      <div className={cx("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

export function InvestigationSummaryGrid({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={cx("grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3", className)}>{children}</div>;
}

export function InvestigationFactCard({
  label,
  value,
  hint,
  mono = false,
  copyValue,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  mono?: boolean;
  copyValue?: string | null;
}) {
  const [copied, setCopied] = useState<null | "ok" | "fail">(null);

  return (
    <div className="rounded-md border border-border bg-surface-2/50 px-3 py-2">
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</div>
      <div className="mt-1 flex items-start justify-between gap-3">
        <div className={cx("min-w-0 flex-1 break-words text-sm text-foreground", mono && "font-mono text-[12px]")}>
          {value}
        </div>
        {copyValue ? (
          <button
            type="button"
            onClick={async () => {
              const ok = await copyTextToClipboard(copyValue);
              setCopied(ok ? "ok" : "fail");
              window.setTimeout(() => setCopied(null), 1200);
            }}
            className="shrink-0 rounded px-1 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            {copied === "ok" ? "Copied" : copied === "fail" ? "Failed" : "Copy"}
          </button>
        ) : null}
      </div>
      {hint ? <div className="mt-1 text-[11px] text-muted-foreground">{hint}</div> : null}
    </div>
  );
}

export function InvestigationChipList({
  title,
  chips,
}: {
  title: string;
  chips: Array<{ label: ReactNode; variant?: BadgeVariant }>;
}) {
  const items = chips.filter(
    (c) => c && c.label !== null && c.label !== undefined && String(c.label).trim() !== "",
  );
  if (items.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{title}</div>
      <div className="flex flex-wrap items-center gap-2">
        {items.map((item, i) => (
          <Badge key={`${title}-${i}-${String(item.label)}`} variant={item.variant || "neutral"}>
            {item.label}
          </Badge>
        ))}
      </div>
    </div>
  );
}

export function InvestigationKeyValueGrid({
  entries,
}: {
  entries: Array<{ key: string; value: ReactNode }>;
}) {
  const rows = entries.filter(
    (x) => x && x.key && x.value !== undefined && x.value !== null && String(x.value).trim() !== "",
  );
  if (rows.length === 0) {
    return (
      <div className="rounded-md border border-border bg-surface-2/40 px-3 py-2 text-sm text-muted-foreground">
        No evidence fields.
      </div>
    );
  }
  return (
    <div className="overflow-hidden rounded-md border border-border bg-surface-2/40">
      {rows.map((item, idx) => (
        <div
          key={`${item.key}-${String(item.value)}`}
          className={cx(
            "flex items-start justify-between gap-3 px-3 py-2",
            idx > 0 ? "border-t border-border/55" : "",
          )}
        >
          <div className="min-w-0 text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
            {item.key}
          </div>
          <div className="max-w-[72%] break-words text-right font-mono text-[12px] text-foreground">
            {item.value}
          </div>
        </div>
      ))}
    </div>
  );
}

export function InvestigationFieldGroup({
  title,
  subtitle,
  entries,
  emptyHint = "No evidence fields.",
  className,
}: {
  title: string;
  subtitle?: ReactNode;
  entries: Array<{ key: string; value: ReactNode }>;
  emptyHint?: string;
  className?: string;
}) {
  const rows = entries.filter((item) => {
    if (!item || !item.key) return false;
    if (item.value === undefined || item.value === null) return false;
    return String(item.value).trim() !== "";
  });

  return (
    <div className={cx("ui-card-shell p-3", className)}>
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{title}</div>
      {subtitle ? <div className="mt-1 text-[12px] text-muted-foreground">{subtitle}</div> : null}
      <div className="mt-3">
        {rows.length > 0 ? (
          <InvestigationKeyValueGrid entries={rows} />
        ) : (
          <div className="rounded-md border border-border bg-surface-2/30 px-3 py-2 text-sm text-muted-foreground">
            {emptyHint}
          </div>
        )}
      </div>
    </div>
  );
}

export function InvestigationListItem({
  title,
  description,
  badges,
  meta,
  actions,
  children,
  active = false,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  badges?: Array<{ label: ReactNode; variant?: BadgeVariant }>;
  meta?: Array<{ label?: ReactNode; value: ReactNode }>;
  actions?: ReactNode;
  children?: ReactNode;
  active?: boolean;
  className?: string;
}) {
  const badgeItems = (badges || []).filter(
    (item) => item && item.label !== undefined && item.label !== null && String(item.label).trim() !== "",
  );
  const metaItems = (meta || []).filter(
    (item) => item && item.value !== undefined && item.value !== null && String(item.value).trim() !== "",
  );

  return (
    <div
      className={cx(
        "ui-card-shell p-4",
        active && "border-primary/55 bg-primary/[0.08]",
        className,
      )}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold text-foreground">{title}</div>
          {description ? <div className="mt-1 break-words text-sm text-muted-foreground">{description}</div> : null}
          {badgeItems.length > 0 ? (
            <div className="mt-3 flex flex-wrap items-center gap-2">
              {badgeItems.map((item, index) => (
                <Badge key={`${index}-${String(item.label)}`} variant={item.variant || "neutral"}>
                  {item.label}
                </Badge>
              ))}
            </div>
          ) : null}
        </div>
        {actions ? <div className="shrink-0">{actions}</div> : null}
      </div>

      {metaItems.length > 0 ? (
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-[11px] font-mono text-muted-foreground">
          {metaItems.map((item, index) => (
            <span key={`${index}-${String(item.value)}`} className="inline-flex items-center gap-2">
              {item.label ? (
                <span className="uppercase tracking-[0.1em] text-muted-foreground/80">{item.label}</span>
              ) : null}
              <span className="text-foreground/90">{item.value}</span>
            </span>
          ))}
        </div>
      ) : null}

      {children ? <div className="mt-3">{children}</div> : null}
    </div>
  );
}

export function InvestigationRawJsonPanel({
  value,
  title = "Raw JSON",
  initialWrap = true,
}: {
  value: unknown;
  title?: string;
  initialWrap?: boolean;
}) {
  return (
    <InvestigationSection title={title}>
      <JsonBlock value={value} initialWrap={initialWrap} />
    </InvestigationSection>
  );
}

export function InvestigationStateBlock({
  loading,
  loadingLabel,
  error,
  empty,
  emptyTitle,
  emptyHint,
}: {
  loading?: boolean;
  loadingLabel?: string;
  error?: string | null;
  empty?: boolean;
  emptyTitle?: string;
  emptyHint?: string;
}) {
  if (loading) return <Loading label={loadingLabel || "Loading..."} />;
  if (error) {
    return (
      <div className="rounded-md border border-danger/50 bg-danger/10 px-3 py-2.5 text-sm text-danger">
        {error}
      </div>
    );
  }
  if (empty) return <EmptyState title={emptyTitle || "No data"} hint={emptyHint} />;
  return null;
}
