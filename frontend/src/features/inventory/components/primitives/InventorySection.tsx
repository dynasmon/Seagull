import { useState } from "react";
import type { ReactNode } from "react";

interface InventorySectionProps {
  id: string;
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
}

export function InventorySection({ id, title, children, defaultOpen = true }: InventorySectionProps) {
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
        // no-op
      }
      return next;
    });
  }

  return (
    <div className="space-y-4">
      <button type="button" onClick={toggle} className="w-full flex items-center gap-3 text-left select-none">
        <span className="text-muted-foreground font-mono text-xs">{open ? "▾" : "▸"}</span>
        <span className="text-[11px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{title}</span>
        <div className="h-px bg-border/60 flex-1" />
      </button>
      {open ? <div className="space-y-4">{children}</div> : null}
    </div>
  );
}
