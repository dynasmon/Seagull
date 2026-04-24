import type { ReactNode, SelectHTMLAttributes } from "react";

import { cx } from "@/shared/lib/cx";

interface SelectInputProps extends SelectHTMLAttributes<HTMLSelectElement> {
  error?: boolean;
  children: ReactNode;
}

export function SelectInput({ error, disabled, className, children, ...rest }: SelectInputProps) {
  return (
    <select
      disabled={disabled}
      className={cx(
        "ui-select transition-colors",
        error && "border-danger/60 bg-danger/5",
        disabled && "cursor-not-allowed opacity-60",
        className,
      )}
      {...rest}
    >
      {children}
    </select>
  );
}
