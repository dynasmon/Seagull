import type { InputHTMLAttributes } from "react";

import { cx } from "@/shared/lib/cx";

interface ToggleSwitchProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: string;
}

export function ToggleSwitch({ label, className, ...inputProps }: ToggleSwitchProps) {
  const { disabled } = inputProps;

  return (
    <label
      className={cx(
        "inline-flex cursor-pointer items-center gap-2.5",
        disabled && "cursor-not-allowed opacity-60",
        className,
      )}
    >
      <span className="relative inline-block h-5 w-9 shrink-0">
        <input type="checkbox" role="switch" className="peer sr-only" {...inputProps} />
        <span className="absolute inset-0 rounded-full border border-border bg-muted transition-colors peer-checked:border-primary/60 peer-checked:bg-primary peer-focus-visible:ring-2 peer-focus-visible:ring-primary/40 peer-focus-visible:ring-offset-1 peer-focus-visible:ring-offset-card" />
        <span className="absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white shadow-sm transition-transform peer-checked:translate-x-4" />
      </span>
      {label ? <span className="text-sm text-foreground">{label}</span> : null}
    </label>
  );
}
