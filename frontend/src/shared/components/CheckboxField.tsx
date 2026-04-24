import type { InputHTMLAttributes, ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

interface CheckboxFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  label: ReactNode;
  helper?: ReactNode;
  error?: string | null;
}

export function CheckboxField({
  label,
  helper,
  error,
  disabled,
  className,
  ...rest
}: CheckboxFieldProps) {
  return (
    <label
      className={cx(
        "flex cursor-pointer items-start gap-2.5",
        disabled && "cursor-not-allowed opacity-60",
        className,
      )}
    >
      <input
        type="checkbox"
        disabled={disabled}
        className="mt-0.5 h-4 w-4 shrink-0 accent-primary"
        {...rest}
      />
      <div className="min-w-0">
        <span className="text-sm text-foreground">{label}</span>
        {error ? (
          <p className="text-[11px] text-danger" role="alert">
            {error}
          </p>
        ) : helper ? (
          <p className="text-[11px] text-muted-foreground">{helper}</p>
        ) : null}
      </div>
    </label>
  );
}
