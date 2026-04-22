import { useEffect, useState } from "react";

import { fmtSec } from "./scanUtils";

/**
 * Renders a live-updating elapsed/duration string in its own component so the timer
 * does not trigger re-renders in parent components.
 * When endIso is absent, ticks every second. When endIso is set, renders statically.
 */
export function LiveElapsedText({
  startIso,
  endIso,
  className,
}: {
  startIso?: string | null;
  endIso?: string | null;
  className?: string;
}) {
  const active = Boolean(startIso && !endIso);
  const [, setTick] = useState(0);

  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, [active]);

  const start = Date.parse(startIso ?? "");
  if (Number.isNaN(start)) return <span className={className}>-</span>;
  const end = endIso ? Date.parse(endIso) : Date.now();
  return (
    <span className={className}>
      {fmtSec(Math.max(0, Math.floor((end - start) / 1000)))}
    </span>
  );
}
