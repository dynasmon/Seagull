import { useMemo, useState } from "react";
import { EuiCodeBlock } from "@elastic/eui";

import { cx } from "@/shared/lib/cx";
import { safeJson } from "./investigation/utils";

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
  const text = useMemo(() => (typeof value === "string" ? value : safeJson(value)), [value]);

  return (
    <div className={cx("space-y-2", className)}>
      {showControls ? (
        <div className="flex items-center justify-end">
          <label className="flex cursor-pointer items-center gap-1.5 text-[11px] text-muted-foreground">
            <input
              type="checkbox"
              checked={wrap}
              onChange={(e) => setWrap(e.target.checked)}
              className="h-3.5 w-3.5"
            />
            Wrap
          </label>
        </div>
      ) : null}
      <EuiCodeBlock
        language="json"
        fontSize="s"
        paddingSize="m"
        overflowHeight={maxHeight}
        whiteSpace={wrap ? "pre-wrap" : "pre"}
        isCopyable={showControls}
      >
        {text}
      </EuiCodeBlock>
    </div>
  );
}
