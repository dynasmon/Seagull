import type { ButtonHTMLAttributes, ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "success" | "subtle";
export type ButtonSize = "sm" | "md" | "lg" | "icon";

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    "border-primary/70 bg-primary text-primary-foreground hover:bg-primary/90 hover:border-primary/80",
  secondary:
    "border-border/80 bg-muted/35 text-foreground hover:border-primary/30 hover:bg-muted/55",
  ghost:
    "border-transparent bg-transparent text-muted-foreground hover:bg-muted/40 hover:text-foreground",
  danger:
    "border-danger/50 bg-danger/10 text-danger hover:bg-danger/20",
  success:
    "border-success/50 bg-success/10 text-success hover:bg-success/20",
  subtle:
    "border-border/50 bg-muted/20 text-muted-foreground hover:bg-muted/45 hover:text-foreground",
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
        "inline-flex items-center justify-center rounded-md border font-semibold transition-colors",
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
