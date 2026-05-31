import { cx } from "@/shared/lib/cx";

type Props = {
  codes: string[];
  className?: string;
  nowrap?: boolean;
};

export function ExposureReasonCodes({ codes, className, nowrap = false }: Props) {
  if (!codes.length) return null;
  return (
    <div className={cx("flex gap-1", nowrap ? "min-w-0 flex-nowrap overflow-hidden" : "flex-wrap", className)}>
      {codes.map((code) => (
        <span
          key={code}
          className="inline-flex shrink-0 items-center rounded border border-border/60 bg-muted/40 px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground"
        >
          {code}
        </span>
      ))}
    </div>
  );
}
