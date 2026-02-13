import type { ReactNode } from "react";
import { useEffect } from "react";
import { createPortal } from "react-dom";

import { cx } from "@/shared/lib/cx";

export default function Drawer({
  open,
  title,
  description,
  onClose,
  children,
  widthClassName = "w-[720px]"
}: {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  widthClassName?: string;
}) {
  useEffect(() => {
    if (!open) return;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };

    window.addEventListener("keydown", onKeyDown);

    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      window.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  // IMPORTANT: render into document.body so we are not affected by any parent
  // stacking contexts (e.g., transform/backdrop/filters) that break `position: fixed`.
  if (typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999]">
      <div
        className="absolute inset-0 bg-black/55 backdrop-blur-[2px]"
        onMouseDown={onClose}
        aria-hidden="true"
      />

      <section
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cx(
          "absolute right-0 top-0 h-full max-w-[92vw]",
          widthClassName,
          "border-l border-border/60 bg-background/92 backdrop-blur-md shadow-2xl",
          "flex flex-col overflow-hidden"
        )}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <header className="shrink-0 border-b border-border/60 bg-muted/10 px-5 py-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
                Drawer
              </div>
              <h2 className="mt-1 text-lg font-semibold truncate">{title}</h2>
              {description ? <div className="mt-1 text-sm text-muted-foreground">{description}</div> : null}
            </div>

            <button
              type="button"
              onClick={onClose}
              className={cx(
                "shrink-0 rounded-md border border-border/60 bg-background/40",
                "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground",
                "focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              Close
            </button>
          </div>
        </header>

        <div className="flex-1 min-h-0 overflow-y-auto p-5">{children}</div>
      </section>
    </div>,
    document.body
  );
}
