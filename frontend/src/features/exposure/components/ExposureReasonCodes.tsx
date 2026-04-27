import { cx } from "@/shared/lib/cx";

type Props = {
  codes: string[];
  className?: string;
};

export function ExposureReasonCodes({ codes, className }: Props) {
  if (!codes.length) return null;
  return (
    <div className={cx("flex flex-wrap gap-1", className)}>
      {codes.map((code) => (
        <span
          key={code}
          className="inline-flex items-center rounded border border-border/60 bg-muted/40 px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground"
        >
          {code}
        </span>
      ))}
    </div>
  );
}
