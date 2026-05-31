import type { ReactNode, RefObject } from "react";
import { useId } from "react";
import { EuiFlyout, EuiFlyoutBody, EuiFlyoutFooter, EuiFlyoutHeader } from "@elastic/eui";

import { cx } from "@/shared/lib/cx";

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

  if (!open) return null;

  return (
    <EuiFlyout
      type="overlay"
      ownFocus
      onClose={onClose}
      outsideClickCloses={closeOnOverlayClick}
      hideCloseButton
      maxWidth={false}
      paddingSize="none"
      className={cx("max-w-[92vw]", widthClassName)}
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
    >
      <EuiFlyoutHeader className="ui-drawer-header">
        <div className="px-5 py-3.5">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-primary/90">{headerLabel}</div>
              <h2 id={titleId} className="mt-1 truncate text-[15px] font-semibold tracking-tight">{title}</h2>
              {description ? (
                <div id={descriptionId} className="mt-1 text-[12px] leading-relaxed text-muted-foreground">{description}</div>
              ) : null}
            </div>

            <div className="flex shrink-0 items-center gap-2">
              {headerActions}
              <button
                type="button"
                onClick={onClose}
                aria-label="Close drawer"
                className={cx(
                  "inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-card text-muted-foreground transition-colors",
                  "hover:border-primary/40 hover:bg-muted hover:text-foreground",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/35"
                )}
              >
                <svg viewBox="0 0 24 24" aria-hidden="true" className="h-4 w-4">
                  <path d="M6 6l12 12M18 6 6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </EuiFlyoutHeader>

      <EuiFlyoutBody>
        <div className={cx("p-5", bodyClassName)}>{children}</div>
      </EuiFlyoutBody>

      {footer ? (
        <EuiFlyoutFooter>
          <div className="px-5 py-3">{footer}</div>
        </EuiFlyoutFooter>
      ) : null}
    </EuiFlyout>
  );
}
