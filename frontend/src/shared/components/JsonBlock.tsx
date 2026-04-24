import { useMemo, useState } from "react";

import { cx } from "@/shared/lib/cx";
import { copyTextToClipboard, safeJson } from "./investigation/utils";

export function JsonBlock({
  value,
  maxHeight = "360px",
  initialWrap = true,
  showControls = true,
  className,
}: {
  value: unknown;
  maxHeight?: string;
  initialWrap?: boolean;
  showControls?: boolean;
  className?: string;
}) {
  const [wrap, setWrap] = useState(initialWrap);
  const [copied, setCopied] = useState<null | "ok" | "fail">(null);
  const text = useMemo(
    () => (typeof value === "string" ? value : safeJson(value)),
    [value],
  );

  return (
    <div className={cx("space-y-2", className)}>
      {showControls ? (
        <div className="flex items-center justify-end gap-3">
          <label className="flex cursor-pointer items-center gap-1.5 text-[11px] text-muted-foreground">
            <input
              type="checkbox"
              checked={wrap}
              onChange={(e) => setWrap(e.target.checked)}
              className="h-3.5 w-3.5"
            />
            Wrap
          </label>
          <button
            type="button"
            onClick={async () => {
              const ok = await copyTextToClipboard(text);
              setCopied(ok ? "ok" : "fail");
              window.setTimeout(() => setCopied(null), 1200);
            }}
            className="text-[11px] text-muted-foreground transition-colors hover:text-foreground"
          >
            {copied === "ok" ? "Copied" : copied === "fail" ? "Failed" : "Copy"}
          </button>
        </div>
      ) : null}
      <pre
        style={{ maxHeight }}
        className={cx(
          "overflow-auto rounded-md border border-border/60 bg-background/30 p-3 text-[11px] leading-relaxed",
          wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre",
        )}
      >
        {text}
      </pre>
    </div>
  );
}
