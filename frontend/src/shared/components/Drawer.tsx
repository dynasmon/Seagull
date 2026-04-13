import type { ReactNode, RefObject } from "react";
import { useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";

import { cx } from "@/shared/lib/cx";

const drawerStack: string[] = [];
let bodyScrollLockDepth = 0;
let bodyScrollLockSnapshot: { overflow: string; paddingRight: string } | null = null;

function pushDrawer(id: string) {
  drawerStack.push(id);
}

function popDrawer(id: string) {
  const idx = drawerStack.lastIndexOf(id);
  if (idx >= 0) drawerStack.splice(idx, 1);
}

function isTopMostDrawer(id: string): boolean {
  if (drawerStack.length === 0) return false;
  return drawerStack[drawerStack.length - 1] === id;
}

function lockBodyScroll() {
  if (typeof document === "undefined") return;
  bodyScrollLockDepth += 1;
  if (bodyScrollLockDepth > 1) return;

  const { body, documentElement } = document;
  bodyScrollLockSnapshot = {
    overflow: body.style.overflow,
    paddingRight: body.style.paddingRight,
  };

  const scrollbarWidth = Math.max(0, window.innerWidth - documentElement.clientWidth);
  body.style.overflow = "hidden";
  if (scrollbarWidth > 0) {
    body.style.paddingRight = `${scrollbarWidth}px`;
  }
}

function unlockBodyScroll() {
  if (typeof document === "undefined" || bodyScrollLockDepth === 0) return;
  bodyScrollLockDepth -= 1;
  if (bodyScrollLockDepth > 0) return;

  const snapshot = bodyScrollLockSnapshot;
  bodyScrollLockSnapshot = null;
  if (!snapshot) return;

  document.body.style.overflow = snapshot.overflow;
  document.body.style.paddingRight = snapshot.paddingRight;
}

function getFocusable(container: HTMLElement): HTMLElement[] {
  const nodes = container.querySelectorAll<HTMLElement>(
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
  );
  return Array.from(nodes).filter((n) => !n.hasAttribute("hidden") && n.getAttribute("aria-hidden") !== "true");
}

export default function Drawer({
  open,
  title,
  description,
  onClose,
  children,
  widthClassName = "w-[720px]",
  headerLabel = "Drawer",
  headerActions,
  footer,
  bodyClassName,
  closeOnOverlayClick = true,
  initialFocusRef,
}: {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  widthClassName?: string;
  headerLabel?: string;
  headerActions?: ReactNode;
  footer?: ReactNode;
  bodyClassName?: string;
  closeOnOverlayClick?: boolean;
  initialFocusRef?: RefObject<HTMLElement | null>;
}) {
  const titleId = useId();
  const descriptionId = useId();
  const drawerId = useId();
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const panelRef = useRef<HTMLElement | null>(null);
  const lastFocusedRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;

    pushDrawer(drawerId);
    lockBodyScroll();
    lastFocusedRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;

    const onKeyDown = (e: KeyboardEvent) => {
      if (!isTopMostDrawer(drawerId)) return;

      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }

      if (e.key !== "Tab") return;
      const panel = panelRef.current;
      if (!panel) return;

      const focusable = getFocusable(panel);
      if (focusable.length === 0) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;

      if (e.shiftKey) {
        if (active === first || !panel.contains(active)) {
          e.preventDefault();
          last.focus();
        }
        return;
      }

      if (active === last) {
        e.preventDefault();
        first.focus();
      }
    };

    window.addEventListener("keydown", onKeyDown);

    return () => {
      window.removeEventListener("keydown", onKeyDown);
      popDrawer(drawerId);
      unlockBodyScroll();
      const shouldRestoreFocus = drawerStack.length === 0;
      if (
        shouldRestoreFocus &&
        lastFocusedRef.current &&
        document.contains(lastFocusedRef.current)
      ) {
        lastFocusedRef.current.focus();
      }
    };
  }, [drawerId, onClose, open]);

  useEffect(() => {
    if (!open) return;
    let frame = 0;
    const focusTarget = () => {
      const target = initialFocusRef?.current;
      if (target && document.contains(target)) {
        target.focus();
        return;
      }
      closeButtonRef.current?.focus();
    };
    frame = window.requestAnimationFrame(focusTarget);
    return () => {
      window.cancelAnimationFrame(frame);
    };
  }, [initialFocusRef, open]);

  if (!open) return null;

  if (typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999]" data-drawer-id={drawerId}>
      <div
        className="absolute inset-0 bg-slate-950/55 backdrop-blur-[1px]"
        onClick={(event) => {
          if (event.target !== event.currentTarget) return;
          if (!closeOnOverlayClick) return;
          if (!isTopMostDrawer(drawerId)) return;
          onClose();
        }}
        aria-hidden="true"
      />

      <section
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        tabIndex={-1}
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
                {headerLabel}
              </div>
              <h2 id={titleId} className="mt-1 truncate text-lg font-semibold">{title}</h2>
              {description ? <div id={descriptionId} className="mt-1 text-sm text-muted-foreground">{description}</div> : null}
            </div>

            <div className="flex shrink-0 items-center gap-2">
              {headerActions}
              <button
                ref={closeButtonRef}
                type="button"
                onClick={onClose}
                className={cx("ui-btn shrink-0")}
              >
                Close
              </button>
            </div>
          </div>
        </header>

        <div className={cx("flex-1 min-h-0 overflow-y-auto overscroll-contain p-5", bodyClassName)}>{children}</div>

        {footer ? <footer className="shrink-0 border-t border-border/60 bg-muted/20 px-5 py-3">{footer}</footer> : null}
      </section>
    </div>,
    document.body
  );
}
