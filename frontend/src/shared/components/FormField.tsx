import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export function FormField({
  label,
  htmlFor,
  required,
  error,
  helper,
  children,
  className,
}: {
  label?: ReactNode;
  htmlFor?: string;
  required?: boolean;
  error?: string | null;
  helper?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx("space-y-1", className)}>
      {label ? (
        <label
          htmlFor={htmlFor}
          className="block text-[11px] font-mono font-semibold uppercase tracking-[0.1em] text-muted-foreground"
        >
          {label}
          {required ? (
            <span className="ml-1 text-danger" aria-hidden="true">
              *
            </span>
          ) : null}
        </label>
      ) : null}
      {children}
      {error ? (
        <p className="text-[11px] text-danger" role="alert">
          {error}
        </p>
      ) : helper ? (
        <p className="text-[11px] text-muted-foreground">{helper}</p>
      ) : null}
    </div>
  );
}
