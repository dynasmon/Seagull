import { useState } from "react";
import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

interface InventorySectionProps {
  id: string;
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
  right?: ReactNode;
}

export function InventorySection({ id, title, children, defaultOpen = true, right }: InventorySectionProps) {
  const key = `nw_inventory_section_${id}`;
  const [open, setOpen] = useState(() => {
    try {
      const v = localStorage.getItem(key);
      if (v === null) return defaultOpen;
      return v === "1";
    } catch {
      return defaultOpen;
    }
  });

  function toggle() {
    setOpen((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(key, next ? "1" : "0");
      } catch {
      }
      return next;
    });
  }

  return (
    <section className="space-y-3">
      <header className="flex items-center gap-3">
        <button
          type="button"
          onClick={toggle}
          aria-expanded={open}
          className="inline-flex items-center gap-2 rounded-md px-2 py-1 text-left text-[11px] font-semibold uppercase tracking-[0.16em] text-foreground/85 transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/35"
        >
          <svg
            viewBox="0 0 12 12"
            className={cx("h-2.5 w-2.5 shrink-0 transition-transform", open ? "rotate-90" : "rotate-0")}
            aria-hidden="true"
          >
            <path d="M4 2.5 8 6l-4 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" fill="none" />
          </svg>
          {title}
        </button>
        <div className="h-px flex-1 bg-border" />
        {right ? <div className="shrink-0 text-[11px] text-muted-foreground">{right}</div> : null}
      </header>
      {open ? <div className="space-y-4">{children}</div> : null}
    </section>
  );
}
