import { cx } from "@/shared/lib/cx";

export function inputClassName(disabled?: boolean) {
  return cx(
    "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
    "placeholder:text-muted-foreground/70 focus:ring-2 focus:ring-primary/30",
    disabled && "opacity-60 cursor-not-allowed"
  );
}

export function textAreaClassName(disabled?: boolean) {
  return cx(
    "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
    "placeholder:text-muted-foreground/70 focus:ring-2 focus:ring-primary/30",
    disabled && "opacity-60 cursor-not-allowed"
  );
}

