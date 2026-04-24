import type { ButtonHTMLAttributes, ReactNode } from "react";

import { cx } from "@/shared/lib/cx";
import { Button } from "./Button";
import type { ButtonVariant } from "./Button";

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  "aria-label": string;
  variant?: ButtonVariant;
  children: ReactNode;
}

export function IconButton({
  variant = "ghost",
  className,
  children,
  ...rest
}: IconButtonProps) {
  return (
    <Button variant={variant} size="icon" className={cx("shrink-0", className)} {...rest}>
      {children}
    </Button>
  );
}
