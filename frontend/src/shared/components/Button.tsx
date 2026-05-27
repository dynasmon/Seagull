import type { ButtonHTMLAttributes, ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "success" | "subtle";
export type ButtonSize = "sm" | "md" | "lg" | "icon";

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    "border-primary bg-primary text-primary-foreground shadow-sm hover:bg-primary/90 hover:border-primary/90 focus-visible:ring-primary/40",
  secondary:
    "border-border bg-surface-2 text-foreground hover:border-primary/40 hover:bg-muted focus-visible:ring-primary/35",
  ghost:
    "border-transparent bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-primary/35",
  danger:
    "border-danger/50 bg-danger/10 text-danger hover:bg-danger/20 focus-visible:ring-danger/40",
  success:
    "border-success/50 bg-success/10 text-success hover:bg-success/20 focus-visible:ring-success/40",
  subtle:
    "border-border/60 bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-primary/30",
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: "h-7 px-2.5 text-[11px] gap-1.5",
  md: "h-8 px-3 text-[11px] gap-2",
  lg: "h-9 px-4 text-[12px] gap-2",
  icon: "h-8 w-8 px-0",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  children?: ReactNode;
}

export function Button({
  variant = "secondary",
  size = "md",
  disabled,
  className,
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      type="button"
      disabled={disabled}
      className={cx(
        "inline-flex items-center justify-center rounded-md border font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-0",
        variantClasses[variant],
        sizeClasses[size],
        disabled && "cursor-not-allowed opacity-50",
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  );
}
