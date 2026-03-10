import type { ReactNode } from "react";

import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { cx } from "@/shared/lib/cx";

type Props = {
  loading: boolean;
  error?: string | null;
  empty: boolean;
  loadingLabel?: string;
  errorTitle?: string;
  emptyTitle: string;
  emptyDescription?: string | ReactNode;
  className?: string;
  onRetry?: () => void;
};

export default function AsyncState({
  loading,
  error,
  empty,
  loadingLabel = "Loading...",
  errorTitle = "Failed to load",
  emptyTitle,
  emptyDescription,
  className,
  onRetry
}: Props) {
  if (loading) {
    return (
      <div className={cx("p-4", className)}>
        <Loading label={loadingLabel} />
      </div>
    );
  }

  if (error) {
    return (
      <div className={cx("space-y-3 p-4", className)}>
        <EmptyState title={errorTitle} description={error} />
        {onRetry ? (
          <div className="flex justify-end">
            <button
              type="button"
              onClick={onRetry}
              className={cx(
                "rounded-md border border-border/60 bg-background/40",
                "px-3 py-2 text-xs font-mono uppercase tracking-widest text-muted-foreground",
                "hover:bg-muted/15 hover:text-foreground",
                "focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              Retry
            </button>
          </div>
        ) : null}
      </div>
    );
  }

  if (empty) {
    return (
      <div className={cx("p-4", className)}>
        <EmptyState title={emptyTitle} description={emptyDescription} />
      </div>
    );
  }

  return null;
}

