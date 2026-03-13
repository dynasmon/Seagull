import type { ReactNode } from "react";

import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";

export default function QueryState({
  loading,
  error,
  isEmpty,
  loadingLabel = "Loading...",
  emptyTitle,
  emptyDescription,
  errorTitle = "Unable to load data",
  onRetry,
  children
}: {
  loading: boolean;
  error?: string | null;
  isEmpty: boolean;
  loadingLabel?: string;
  emptyTitle: string;
  emptyDescription?: ReactNode;
  errorTitle?: string;
  onRetry?: (() => void) | null;
  children: ReactNode;
}) {
  if (loading) {
    return <Loading label={loadingLabel} />;
  }

  if (error) {
    return (
      <EmptyState
        title={errorTitle}
        description={
          <div className="space-y-3">
            <div>{error}</div>
            {onRetry ? (
              <div>
                <button
                  type="button"
                  onClick={onRetry}
                  className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs font-mono uppercase tracking-widest text-foreground hover:bg-muted/15"
                >
                  Retry
                </button>
              </div>
            ) : null}
          </div>
        }
      />
    );
  }

  if (isEmpty) {
    return <EmptyState title={emptyTitle} description={emptyDescription} />;
  }

  return <>{children}</>;
}
