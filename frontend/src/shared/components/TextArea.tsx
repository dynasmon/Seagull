import type { TextareaHTMLAttributes } from "react";

import { cx } from "@/shared/lib/cx";

interface TextAreaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  error?: boolean;
}

export function TextArea({ error, disabled, className, ...rest }: TextAreaProps) {
  return (
    <textarea
      disabled={disabled}
      className={cx(
        "w-full resize-y rounded-md border border-border/70 bg-card/85 px-3 py-2",
        "min-h-[80px] text-sm text-foreground placeholder:text-muted-foreground/80 transition-colors",
        error && "border-danger/60 bg-danger/5",
        disabled && "cursor-not-allowed opacity-60",
        className,
      )}
      {...rest}
    />
  );
}
