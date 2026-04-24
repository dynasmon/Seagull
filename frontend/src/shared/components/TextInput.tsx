import type { InputHTMLAttributes } from "react";

import { cx } from "@/shared/lib/cx";

interface TextInputProps extends InputHTMLAttributes<HTMLInputElement> {
  error?: boolean;
}

export function TextInput({ error, disabled, className, ...rest }: TextInputProps) {
  return (
    <input
      disabled={disabled}
      className={cx(
        "ui-input transition-colors",
        error && "border-danger/60 bg-danger/5",
        disabled && "cursor-not-allowed opacity-60",
        className,
      )}
      {...rest}
    />
  );
}
