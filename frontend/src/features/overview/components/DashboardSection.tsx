import { useCallback, useMemo } from "react";
import type { ReactNode } from "react";
import { EuiAccordion } from "@elastic/eui";

function storageKey(id: string): string {
  return `nw_overview_section_${id}`;
}

function readInitialOpen(id: string, defaultOpen: boolean): boolean {
  try {
    const v = localStorage.getItem(storageKey(id));
    if (v === null) return defaultOpen;
    return v === "1";
  } catch {
    return defaultOpen;
  }
}

export function DashboardSection({
  id,
  title,
  children,
  defaultOpen = true,
  right,
}: {
  id: string;
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
  right?: ReactNode;
}) {
  // EuiAccordion owns the open/closed state once mounted; we seed it from
  // localStorage and persist every toggle so a section's collapse state
  // survives reloads (matching the previous hand-rolled behavior).
  const initialIsOpen = useMemo(() => readInitialOpen(id, defaultOpen), [id, defaultOpen]);

  const handleToggle = useCallback(
    (isOpen: boolean) => {
      try {
        localStorage.setItem(storageKey(id), isOpen ? "1" : "0");
      } catch {
        /* persistence is best-effort */
      }
    },
    [id],
  );

  return (
    <EuiAccordion
      id={`overview-section-${id}`}
      className="nw-overview-section"
      initialIsOpen={initialIsOpen}
      onToggle={handleToggle}
      paddingSize="none"
      buttonProps={{ className: "nw-overview-section__trigger py-1.5" }}
      buttonContent={
        <span className="text-[11px] font-semibold uppercase tracking-[0.16em] text-foreground/85">{title}</span>
      }
      extraAction={right ? <div className="text-[11px] text-muted-foreground">{right}</div> : undefined}
    >
      <div className="space-y-4 pt-3">{children}</div>
    </EuiAccordion>
  );
}
