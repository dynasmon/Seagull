import type { ReactNode } from "react";
import { useEffect, useId, useRef } from "react";
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
  const titleId = useId();
  const descriptionId = useId();
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);

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

  useEffect(() => {
    if (!open) return;
    closeButtonRef.current?.focus();
  }, [open]);

  if (!open) return null;

  // IMPORTANT: render into document.body so we are not affected by any parent
  // stacking contexts (e.g., transform/backdrop/filters) that break `position: fixed`.
  if (typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999]">
      <div
        className="absolute inset-0 bg-slate-950/55 backdrop-blur-[1px]"
        onMouseDown={onClose}
        aria-hidden="true"
      />

      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        className={cx(
          "absolute right-0 top-0 h-full max-w-[92vw]",
          widthClassName,
          "border-l border-border/70 bg-background/96 backdrop-blur-sm shadow-2xl",
          "flex flex-col overflow-hidden"
        )}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <header className="ui-drawer-header shrink-0 px-5 py-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                Drawer
              </div>
              <h2 id={titleId} className="mt-1 truncate text-lg font-semibold">{title}</h2>
              {description ? <div id={descriptionId} className="mt-1 text-sm text-muted-foreground">{description}</div> : null}
            </div>

            <button
              ref={closeButtonRef}
              type="button"
              onClick={onClose}
              className={cx(
                "ui-btn shrink-0"
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
