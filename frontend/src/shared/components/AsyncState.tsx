import type { ReactNode } from "react";

import { Button } from "@/shared/components/Button";
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
      <div className={cx("space-y-3 p-4", className)} role="alert">
        <EmptyState title={errorTitle} description={error} />
        {onRetry ? (
          <div className="flex justify-end">
            <Button variant="secondary" size="sm" onClick={onRetry}>
              Retry
            </Button>
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
